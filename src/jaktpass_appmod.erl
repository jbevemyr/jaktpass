%%%-------------------------------------------------------------------
%%% jaktpass_appmod.erl - Yaws appmod for jaktpass MVP
%%%
%%% All API routing goes via /api (yaws.conf: appmods = <"/api", jaktpass_appmod>)
%%% Persistence: JSON + image files on disk under JAKTPASS_DATA_DIR (default ./data)
%%% Admin protection: Basic Auth for /api/admin/*
%%%-------------------------------------------------------------------

-module(jaktpass_appmod).
-export([out/1]).

%% Yaws records (#arg, #http_request, #headers, ...)
%% OTP 22: använd lokal header (incheckad i repo) istället för include_lib(...)
-include("yaws_api.hrl").

%%====================================================================
%% Entry
%%====================================================================

out(A) ->
    try
        Method = ((A#arg.req)#http_request.method),
        Path0  = request_path(A),
        Path   = strip_api_prefix(Path0),
        Segs   = split_path(Path),
        dispatch(Method, Segs, A)
    catch
        Class:Reason:Stack ->
            json_error(500, <<"internal_error">>, #{
                <<"class">> => to_bin(Class),
                <<"reason">> => to_bin(io_lib:format("~p", [Reason])),
                <<"stack">> => to_bin(io_lib:format("~p", [Stack]))
            })
    end.

%%====================================================================
%% Routing
%%====================================================================

dispatch('GET', ["sets"], _A) ->
    handle_get_sets();
dispatch('GET', ["sets", SetId], _A) ->
    with_valid_set_id(SetId, fun(SId) -> handle_get_set(SId) end);
dispatch('GET', ["sets", SetId, "quiz"], A) ->
    with_valid_set_id(SetId, fun(SId) -> handle_get_quiz(SId, A) end);
dispatch('GET', ["media", "sets", SetId, "image"], _A) ->
    with_valid_set_id(SetId, fun(SId) -> handle_get_image(SId) end);

%% Admin
dispatch('GET', ["admin", "ping"], A) ->
    with_admin(A, fun() -> json_ok(200, #{<<"authenticated">> => true}) end);
dispatch('POST', ["admin", "sets"], A) ->
    with_admin(A, fun() -> handle_post_admin_sets(A) end);
dispatch('DELETE', ["admin", "sets", SetId], A) ->
    with_admin(A, fun() -> with_valid_set_id(SetId, fun(SId) -> handle_delete_admin_set(SId) end) end);
dispatch('POST', ["admin", "sets", SetId, "image"], A) ->
    with_admin(A, fun() -> with_valid_set_id(SetId, fun(SId) -> handle_post_admin_set_image(SId, A) end) end);
dispatch('POST', ["admin", "sets", SetId, "stands"], A) ->
    with_admin(A, fun() -> with_valid_set_id(SetId, fun(SId) -> handle_post_admin_set_stands(SId, A) end) end);
dispatch('PATCH', ["admin", "stands", StandId], A) ->
    with_admin(A, fun() -> handle_patch_admin_stand(StandId, A) end);
dispatch('DELETE', ["admin", "stands", StandId], A) ->
    with_admin(A, fun() -> handle_delete_admin_stand(StandId) end);

dispatch(_Method, _Segs, _A) ->
    json_error(404, <<"not_found">>, #{<<"path">> => <<"unknown">>}).

%%====================================================================
%% Public handlers
%%====================================================================

handle_get_sets() ->
    case list_sets() of
        {ok, Sets} ->
            json_ok(200, Sets);
        {error, Reason} ->
            json_error(500, <<"failed_to_list_sets">>, #{<<"reason">> => to_bin(Reason)})
    end.

handle_get_set(SetId) ->
    case load_set_meta(SetId) of
        {ok, Meta0} ->
            ImageUrl =
                case get_in(Meta0, [<<"image">>, <<"filename">>]) of
                    undefined -> undefined;
                    null -> undefined;
                    <<>> -> undefined;
                    _ -> <<"/api/media/sets/", (to_bin(SetId))/binary, "/image">>
                end,
            Meta = Meta0#{<<"imageUrl">> => (case ImageUrl of undefined -> null; _ -> ImageUrl end)},
            json_ok(200, Meta);
        {error, enoent} ->
            json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
        {error, Reason} ->
            json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
    end.

handle_get_quiz(SetId, A) ->
    Q = query_map(A),
    Mode0 = maps:get(<<"mode">>, Q, <<"rand10">>),
    case load_set_meta(SetId) of
        {ok, Meta} ->
            Stands0 = maps:get(<<"stands">>, Meta, []),
            seed_rand(),
            N0 = length(Stands0),
            Count =
                case Mode0 of
                    <<"all">> -> N0;
                    <<"randHalf">> -> (N0 + 1) div 2;
                    <<"half">> -> (N0 + 1) div 2;
                    <<"rand10">> -> 10;
                    <<"rand">> -> 10;
                    _ -> 10
                end,
            Sample = take_n(shuffle(Stands0), Count),
            VisibleDots = [#{<<"id">> => maps:get(<<"id">>, S),
                             <<"x">> => maps:get(<<"x">>, S),
                             <<"y">> => maps:get(<<"y">>, S)} || S <- Sample],
            Questions = [#{<<"standId">> => maps:get(<<"id">>, S),
                           <<"name">> => maps:get(<<"name">>, S)} || S <- Sample],
            json_ok(200, #{<<"visibleStands">> => VisibleDots,
                           <<"questions">> => Questions});
        {error, enoent} ->
            json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
        {error, Reason} ->
            json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
    end.

handle_get_image(SetId) ->
    case load_set_meta(SetId) of
        {ok, Meta} ->
            case get_in(Meta, [<<"image">>, <<"filename">>]) of
                undefined -> json_error(404, <<"image_not_found">>, #{<<"setId">> => to_bin(SetId)});
                null -> json_error(404, <<"image_not_found">>, #{<<"setId">> => to_bin(SetId)});
                <<>> -> json_error(404, <<"image_not_found">>, #{<<"setId">> => to_bin(SetId)});
                FilenameBin ->
                    Filename = binary_to_list(FilenameBin),
                    Path = filename:join([set_dir(SetId), Filename]),
                    case file:read_file(Path) of
                        {ok, Bin} ->
                            CT = content_type_from_filename(Filename),
                            [{status, 200},
                             {header, {"Content-Type", CT}},
                             {content, CT, Bin}];
                        {error, enoent} ->
                            json_error(404, <<"image_not_found">>, #{<<"setId">> => to_bin(SetId)});
                        {error, Reason} ->
                            json_error(500, <<"failed_to_read_image">>, #{<<"reason">> => to_bin(Reason)})
                    end
            end;
        {error, enoent} ->
            json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
        {error, Reason} ->
            json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
    end.

%%====================================================================
%% Admin handlers
%%====================================================================

handle_post_admin_sets(A) ->
    case read_json_body(A) of
        {ok, Body} ->
            Name0 = maps:get(<<"name">>, Body, undefined),
            case validate_nonempty_string(Name0) of
                {ok, Name} ->
                    SetId = uuid_v4(),
                    Now = now_rfc3339(),
                    Meta = #{
                        <<"set">> => #{<<"id">> => to_bin(SetId), <<"name">> => Name, <<"createdAt">> => Now},
                        <<"image">> => null,
                        <<"stands">> => []
                    },
                    case save_set_meta(SetId, Meta) of
                        ok -> json_ok(201, #{<<"id">> => to_bin(SetId)});
                        {error, Reason} -> json_error(500, <<"failed_to_create_set">>, #{<<"reason">> => to_bin(Reason)})
                    end;
                {error, Msg} ->
                    json_error(400, <<"invalid_name">>, #{<<"details">> => Msg})
            end;
        {error, Msg} ->
            json_error(400, <<"invalid_json">>, #{<<"details">> => Msg})
    end.

handle_delete_admin_set(SetId) ->
    with_set_lock(SetId, fun() ->
        Dir = set_dir(SetId),
        case filelib:is_dir(Dir) of
            false ->
                json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
            true ->
                case delete_dir_recursive(Dir) of
                    ok ->
                        json_ok(200, #{<<"deleted">> => true, <<"setId">> => to_bin(SetId)});
                    {error, Reason} ->
                        json_error(500, <<"failed_to_delete_set">>, #{<<"reason">> => to_bin(Reason)})
                end
        end
    end).

handle_post_admin_set_image(SetId, A) ->
    with_set_lock(SetId, fun() ->
        case load_set_meta(SetId) of
            {ok, Meta0} ->
                case parse_multipart_file(A, "file") of
                    {ok, #{filename := OrigName, data := Bin}} ->
                        case image_ext(OrigName) of
                            {ok, Ext} ->
                                Filename = "image." ++ Ext,
                                Path = filename:join([set_dir(SetId), Filename]),
                                ok = filelib:ensure_dir(Path),
                                ok = file:write_file(Path, Bin),
                                {W, H} = image_dims(Ext, Bin),
                                Now = now_rfc3339(),
                                ImageMeta = #{
                                    <<"filename">> => to_bin(Filename),
                                    <<"width">> => (case W of undefined -> null; _ -> W end),
                                    <<"height">> => (case H of undefined -> null; _ -> H end),
                                    <<"uploadedAt">> => Now
                                },
                                Meta = Meta0#{<<"image">> => ImageMeta},
                                case save_set_meta(SetId, Meta) of
                                    ok -> json_ok(200, ImageMeta);
                                    {error, Reason} -> json_error(500, <<"failed_to_update_meta">>, #{<<"reason">> => to_bin(Reason)})
                                end;
                            {error, invalid_ext} ->
                                json_error(400, <<"invalid_image_extension">>, #{<<"allowed">> => [<<"png">>,<<"jpg">>,<<"jpeg">>,<<"webp">>]})
                        end;
                    {error, Msg} ->
                        json_error(400, <<"invalid_multipart">>, #{<<"details">> => Msg})
                end;
            {error, enoent} ->
                json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
            {error, Reason} ->
                json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
        end
    end).

handle_post_admin_set_stands(SetId, A) ->
    with_set_lock(SetId, fun() ->
        case {load_set_meta(SetId), read_json_body(A)} of
            {{ok, Meta0}, {ok, Body}} ->
                Name0 = maps:get(<<"name">>, Body, undefined),
                X0 = maps:get(<<"x">>, Body, undefined),
                Y0 = maps:get(<<"y">>, Body, undefined),
                Note0 = maps:get(<<"note">>, Body, undefined),
                case {validate_nonempty_string(Name0),
                      validate_norm_coord(X0),
                      validate_norm_coord(Y0)} of
                    {{ok, Name}, {ok, X}, {ok, Y}} ->
                        Now = now_rfc3339(),
                        Stand = #{
                            <<"id">> => to_bin(uuid_v4()),
                            <<"name">> => Name,
                            <<"x">> => X,
                            <<"y">> => Y,
                            <<"createdAt">> => Now,
                            <<"updatedAt">> => Now
                        },
                        Stand2 =
                            case Note0 of
                                undefined -> Stand;
                                _ -> Stand#{<<"note">> => to_bin(Note0)}
                            end,
                        Stands0 = maps:get(<<"stands">>, Meta0, []),
                        Meta = Meta0#{<<"stands">> => [Stand2 | Stands0]},
                        case save_set_meta(SetId, Meta) of
                            ok -> json_ok(201, Stand2);
                            {error, Reason} -> json_error(500, <<"failed_to_save_meta">>, #{<<"reason">> => to_bin(Reason)})
                        end;
                    _ ->
                        json_error(400, <<"invalid_payload">>, #{<<"expected">> => <<"name + x + y (0..1)">>})
                end;
            {{error, enoent}, _} ->
                json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
            {{error, Reason}, _} ->
                json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)});
            {_, {error, Msg}} ->
                json_error(400, <<"invalid_json">>, #{<<"details">> => Msg})
        end
    end).

handle_patch_admin_stand(StandId, A) ->
    case read_json_body(A) of
        {ok, Body} ->
            patch_entity_by_id(<<"stands">>, StandId, fun(Stand0) ->
                Now = now_rfc3339(),
                case maybe_updates([
                        {<<"name">>, fun validate_nonempty_string/1},
                        {<<"x">>, fun validate_norm_coord/1},
                        {<<"y">>, fun validate_norm_coord/1}
                    ], Body, Stand0) of
                    {error, Msg} ->
                        {error, Msg};
                    {ok, Stand3} ->
                        Stand4 =
                            case maps:is_key(<<"note">>, Body) of
                                true ->
                                    %% tillåt tom sträng; konvertera till binary
                                    Stand3#{<<"note">> => to_bin(maps:get(<<"note">>, Body))};
                                false -> Stand3
                            end,
                        {ok, Stand4#{<<"updatedAt">> => Now}}
                end
            end);
        {error, Msg} ->
            json_error(400, <<"invalid_json">>, #{<<"details">> => Msg})
    end.

handle_delete_admin_stand(StandId) ->
    delete_entity_by_id(<<"stands">>, StandId).

%% NOTE: areas (områden) är borttagna i denna MVP. Ev. äldre meta.json kan fortfarande ha "areas",
%% men de används inte och inga /api/admin/*-endpoints finns för dem.

%%====================================================================
%% Auth
%%====================================================================

with_admin(A, Fun) ->
    case check_admin_auth(A) of
        ok -> Fun();
        {error, Resp} -> Resp
    end.

check_admin_auth(A) ->
    AdminUser = getenv_default("JAKTPASS_ADMIN_USER", "admin"),
    AdminPass = getenv_default("JAKTPASS_ADMIN_PASS", "admin"),
    Auth = find_header_lower("authorization", A#arg.headers),
    case Auth of
        undefined ->
            {error, unauthorized()};
        Val ->
            case parse_basic_auth(Val) of
                {ok, {User, Pass}} when User =:= AdminUser, Pass =:= AdminPass ->
                    ok;
                _ ->
                    {error, unauthorized()}
            end
    end.

unauthorized() ->
    [{status, 401},
     {header, {"WWW-Authenticate", "Basic realm=\"jaktpass-admin\""}},
     {header, {"Content-Type", "application/json"}},
     {content, "application/json", iolist_to_binary(json_encode(#{
         <<"ok">> => false,
         <<"error">> => <<"unauthorized">>,
         <<"details">> => <<"Missing or invalid Basic Auth">>
     }))}].

parse_basic_auth(Val0) ->
    %% Accept both list and binary header values
    Val = case Val0 of
              B when is_binary(B) -> binary_to_list(B);
              L when is_list(L) -> L
          end,
    case lists:prefix("Basic ", Val) of
        true ->
            Enc = lists:nthtail(length("Basic "), Val),
            try
                DecBin = base64:decode(list_to_binary(Enc)),
                case binary:split(DecBin, <<":">>, [global]) of
                    [U, P] -> {ok, {binary_to_list(U), binary_to_list(P)}};
                    _ -> error
                end
            catch _:_ -> error end;
        false ->
            error
    end.

find_header_lower(NameLower, H) ->
    %% Different Yaws versions expose either find_header_value/2 or find_header/2.
    case erlang:function_exported(yaws_api, find_header_value, 2) of
        true ->
            yaws_api:find_header_value(NameLower, H);
        false ->
            case erlang:function_exported(yaws_api, find_header, 2) of
                true ->
                    case yaws_api:find_header(NameLower, H) of
                        undefined -> undefined;
                        {ok, V} -> V;
                        V -> V
                    end;
                false ->
                    undefined
            end
    end.

%%====================================================================
%% Disk / JSON
%%====================================================================

data_dir() ->
    getenv_default("JAKTPASS_DATA_DIR", "./priv/data").

sets_dir() ->
    filename:join([data_dir(), "sets"]).

set_dir(SetId) ->
    filename:join([sets_dir(), SetId]).

meta_path(SetId) ->
    filename:join([set_dir(SetId), "meta.json"]).

list_sets() ->
    Root = sets_dir(),
    ok = filelib:ensure_dir(filename:join([Root, "dummy"])),
    case file:list_dir(Root) of
        {ok, Entries} ->
            Sets =
                lists:foldl(
                  fun(SetId, Acc) ->
                      case load_set_meta(SetId) of
                          {ok, Meta} ->
                              Name = get_in(Meta, [<<"set">>, <<"name">>]),
                              HasImage =
                                  case get_in(Meta, [<<"image">>, <<"filename">>]) of
                                      undefined -> false;
                                      null -> false;
                                      <<>> -> false;
                                      _ -> true
                                  end,
                              [#{<<"id">> => to_bin(SetId), <<"name">> => Name, <<"hasImage">> => HasImage} | Acc];
                          _ ->
                              Acc
                      end
                  end, [], Entries),
            {ok, lists:reverse(Sets)};
        {error, enoent} ->
            {ok, []};
        {error, Reason} ->
            {error, Reason}
    end.

load_set_meta(SetId) ->
    Path = meta_path(SetId),
    case file:read_file(Path) of
        {ok, Bin} ->
            try
                {ok, json_decode(Bin)}
            catch _:_ ->
                {error, invalid_json}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

save_set_meta(SetId, Meta) ->
    Path = meta_path(SetId),
    ok = filelib:ensure_dir(Path),
    write_json_atomic(Path, Meta).

write_json_atomic(Path, Term) ->
    Tmp = Path ++ ".tmp",
    Bin = iolist_to_binary(json_encode(Term)),
    case file:write_file(Tmp, Bin) of
        ok -> file:rename(Tmp, Path);
        {error, Reason} -> {error, Reason}
    end.

%% Per-set lock using global:trans (single-node assumption).
with_set_lock(SetId, Fun) ->
    global:trans({jaktpass_set, SetId}, Fun, [node()], 30000).

delete_dir_recursive(Dir) ->
    case file:list_dir(Dir) of
        {ok, Names} ->
            Res = lists:foldl(
                    fun(Name, Acc) ->
                        case Acc of
                            ok ->
                                Path = filename:join([Dir, Name]),
                                case filelib:is_dir(Path) of
                                    true ->
                                        delete_dir_recursive(Path);
                                    false ->
                                        file:delete(Path)
                                end;
                            Err -> Err
                        end
                    end, ok, Names),
            case Res of
                ok -> file:del_dir(Dir);
                Err -> Err
            end;
        {error, enoent} ->
            ok;
        {error, Reason} ->
            {error, Reason}
    end.

%%====================================================================
%% Entity helpers (stand/area by ID across sets)
%%====================================================================

patch_entity_by_id(ListKey, EntityId, PatchFun) ->
    case find_entity_set(ListKey, EntityId) of
        {ok, SetId} ->
            with_set_lock(SetId, fun() ->
                case load_set_meta(SetId) of
                    {ok, Meta0} ->
                        List0 = maps:get(ListKey, Meta0, []),
                        case split_by_id(List0, EntityId) of
                            {ok, Entity0, Rest} ->
                                case PatchFun(Entity0) of
                                    {ok, Entity1} ->
                                        Meta = Meta0#{ListKey => [Entity1 | Rest]},
                                        case save_set_meta(SetId, Meta) of
                                            ok -> json_ok(200, Entity1);
                                            {error, Reason} -> json_error(500, <<"failed_to_save_meta">>, #{<<"reason">> => to_bin(Reason)})
                                        end;
                                    {error, Msg} ->
                                        json_error(400, <<"invalid_payload">>, #{<<"details">> => Msg})
                                end;
                            not_found ->
                                json_error(404, <<"not_found">>, #{<<"id">> => to_bin(EntityId)})
                        end;
                    {error, enoent} ->
                        json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
                    {error, Reason} ->
                        json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
                end
            end);
        not_found ->
            json_error(404, <<"not_found">>, #{<<"id">> => to_bin(EntityId)});
        {error, Reason} ->
            json_error(500, <<"failed_to_find_entity">>, #{<<"reason">> => to_bin(Reason)})
    end.

delete_entity_by_id(ListKey, EntityId) ->
    case find_entity_set(ListKey, EntityId) of
        {ok, SetId} ->
            with_set_lock(SetId, fun() ->
                case load_set_meta(SetId) of
                    {ok, Meta0} ->
                        List0 = maps:get(ListKey, Meta0, []),
                        case split_by_id(List0, EntityId) of
                            {ok, _Entity, Rest} ->
                                Meta = Meta0#{ListKey => Rest},
                                case save_set_meta(SetId, Meta) of
                                    ok -> json_ok(200, #{<<"deleted">> => true});
                                    {error, Reason} -> json_error(500, <<"failed_to_save_meta">>, #{<<"reason">> => to_bin(Reason)})
                                end;
                            not_found ->
                                json_error(404, <<"not_found">>, #{<<"id">> => to_bin(EntityId)})
                        end;
                    {error, enoent} ->
                        json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
                    {error, Reason} ->
                        json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
                end
            end);
        not_found ->
            json_error(404, <<"not_found">>, #{<<"id">> => to_bin(EntityId)});
        {error, Reason} ->
            json_error(500, <<"failed_to_find_entity">>, #{<<"reason">> => to_bin(Reason)})
    end.

find_entity_set(ListKey, EntityId) ->
    case file:list_dir(sets_dir()) of
        {ok, SetIds} ->
            find_entity_set_loop(SetIds, ListKey, EntityId);
        {error, enoent} ->
            not_found;
        {error, Reason} ->
            {error, Reason}
    end.

find_entity_set_loop([], _ListKey, _EntityId) ->
    not_found;
find_entity_set_loop([SetId | Rest], ListKey, EntityId) ->
    case load_set_meta(SetId) of
        {ok, Meta} ->
            List0 = maps:get(ListKey, Meta, []),
            case has_id(List0, EntityId) of
                true -> {ok, SetId};
                false -> find_entity_set_loop(Rest, ListKey, EntityId)
            end;
        _ ->
            find_entity_set_loop(Rest, ListKey, EntityId)
    end.

has_id(List0, EntityId) ->
    lists:any(fun(E) -> maps:get(<<"id">>, E, undefined) =:= to_bin(EntityId) end, List0).

split_by_id(List0, EntityId0) ->
    EntityId = to_bin(EntityId0),
    split_by_id(List0, EntityId, []).

split_by_id([], _Id, _Acc) ->
    not_found;
split_by_id([E | Rest], Id, Acc) ->
    case maps:get(<<"id">>, E, undefined) of
        Id -> {ok, E, lists:reverse(Acc) ++ Rest};
        _ -> split_by_id(Rest, Id, [E | Acc])
    end.

%% NOTE: områden/polygon-stöd är borttaget i denna MVP, så geometri-hjälpare är rensade.

%%====================================================================
%% Multipart (image upload)
%%====================================================================

parse_multipart_file(A, FieldName) ->
    %% Yaws provides yaws_api:parse_multipart_post/1 in common setups.
    case erlang:function_exported(yaws_api, parse_multipart_post, 1) of
        true ->
            try
                Parts = yaws_api:parse_multipart_post(A),
                pick_file_part(Parts, FieldName)
            catch _:_ ->
                {error, <<"failed_to_parse_multipart">>}
            end;
        false ->
            {error, <<"multipart_not_supported_in_this_yaws">>}
    end.

pick_file_part([], _FieldName) ->
    {error, <<"missing_file_field">>};
pick_file_part([P | Rest], FieldName) ->
    case P of
        {FieldName, {Filename, _CT, Bin}} ->
            {ok, #{filename => Filename, data => Bin}};
        {FieldName, {Filename, _CT, _Charset, Bin}} ->
            {ok, #{filename => Filename, data => Bin}};
        {_Other, _} ->
            pick_file_part(Rest, FieldName)
    end.

image_ext(OrigName0) ->
    OrigName =
        case OrigName0 of
            B when is_binary(B) -> binary_to_list(B);
            L when is_list(L) -> L
        end,
    Ext0 = string:lowercase(filename:extension(OrigName)),
    Ext = case Ext0 of
              ".jpeg" -> "jpeg";
              ".jpg" -> "jpg";
              ".png" -> "png";
              ".webp" -> "webp";
              _ -> invalid
          end,
    case Ext of
        invalid -> {error, invalid_ext};
        _ -> {ok, Ext}
    end.

content_type_from_filename(Filename) ->
    Ext0 = string:lowercase(filename:extension(Filename)),
    case Ext0 of
        ".png" -> "image/png";
        ".jpg" -> "image/jpeg";
        ".jpeg" -> "image/jpeg";
        ".webp" -> "image/webp";
        _ -> "application/octet-stream"
    end.

image_dims("png", Bin) -> png_dims(Bin);
image_dims("jpg", Bin) -> jpeg_dims(Bin);
image_dims("jpeg", Bin) -> jpeg_dims(Bin);
image_dims("webp", Bin) -> webp_dims(Bin);
image_dims(_, _Bin) -> {undefined, undefined}.

png_dims(<<137,80,78,71,13,10,26,10, _Len:32, "IHDR", W:32/big, H:32/big, _/binary>>) ->
    {W, H};
png_dims(_) ->
    {undefined, undefined}.

jpeg_dims(Bin) ->
    %% Parse JPEG markers until SOF0/SOF2
    case Bin of
        <<16#FF,16#D8, Rest/binary>> ->
            jpeg_scan(Rest);
        _ ->
            {undefined, undefined}
    end.

jpeg_scan(<<16#FF, Marker:8, _Len:16/big, Payload/binary>>) when Marker =:= 16#C0; Marker =:= 16#C2 ->
    %% SOF0 / SOF2: [precision][height][width]...
    case Payload of
        <<_Precision:8, H:16/big, W:16/big, _/binary>> ->
            {W, H};
        _ ->
            {undefined, undefined}
    end;
jpeg_scan(<<16#FF, _Marker:8, Len:16/big, Rest/binary>>) ->
    Skip = Len - 2,
    case Rest of
        <<_Skip:Skip/binary, Tail/binary>> ->
            %% Skip other segments
            jpeg_scan(Tail);
        _ ->
            {undefined, undefined}
    end;
jpeg_scan(<<16#FF, 16#D9, _/binary>>) ->
    {undefined, undefined};
jpeg_scan(<<_, Tail/binary>>) ->
    jpeg_scan(Tail);
jpeg_scan(_) ->
    {undefined, undefined}.

webp_dims(<<"RIFF", _Size:32/little, "WEBP", Rest/binary>>) ->
    webp_scan(Rest);
webp_dims(_) ->
    {undefined, undefined}.

webp_scan(<<"VP8X", _ChunkSize:32/little, _Flags:8, Wm1:24/little, Hm1:24/little, _/binary>>) ->
    {Wm1 + 1, Hm1 + 1};
webp_scan(<<_FourCC:4/binary, ChunkSize:32/little, Rest/binary>>) ->
    Pad = ChunkSize rem 2,
    Skip = ChunkSize + Pad,
    case Rest of
        <<_Skip:Skip/binary, Tail/binary>> -> webp_scan(Tail);
        _ -> {undefined, undefined}
    end;
webp_scan(_) ->
    {undefined, undefined}.

%%====================================================================
%% Validation / utils
%%====================================================================

read_json_body(A) ->
    case recv_body_bin(A) of
        {ok, Bin} ->
            try
                {ok, json_decode(Bin)}
            catch _:_ ->
                {error, <<"could_not_decode_json">>}
            end;
        {error, Msg} -> {error, Msg}
    end.

recv_body_bin(A) ->
    %% Prefer yaws_api:recv_body/1 if available.
    case erlang:function_exported(yaws_api, recv_body, 1) of
        true ->
            try
                case yaws_api:recv_body(A) of
                    {ok, B} when is_binary(B) -> {ok, B};
                    B when is_binary(B) -> {ok, B};
                    L when is_list(L) -> {ok, list_to_binary(L)};
                    _ -> {ok, <<>>}
                end
            catch _:_ ->
                {error, <<"failed_to_read_body">>}
            end;
        false ->
            %% Fallback: Arg#arg.clidata sometimes contains body
            case A#arg.clidata of
                undefined -> {ok, <<>>};
                B when is_binary(B) -> {ok, B};
                L when is_list(L) -> {ok, list_to_binary(L)};
                _ -> {ok, <<>>}
            end
    end.

validate_nonempty_string(undefined) -> {error, <<"missing">>};
validate_nonempty_string(null) -> {error, <<"missing">>};
validate_nonempty_string(B) when is_binary(B) ->
    case bin_trim(B) of
        <<>> -> {error, <<"empty">>};
        T -> {ok, T}
    end;
validate_nonempty_string(L) when is_list(L) ->
    validate_nonempty_string(list_to_binary(L));
validate_nonempty_string(_) -> {error, <<"invalid_type">>}.

bin_trim(B) when is_binary(B) ->
    %% OTP 22 saknar binary:trim/1, så vi gör en enkel whitespace-trim själva.
    list_to_binary(string:trim(binary_to_list(B))).

validate_norm_coord(V) when is_integer(V); is_float(V) ->
    if V >= 0.0, V =< 1.0 -> {ok, V + 0.0}; true -> {error, <<"out_of_range">>} end;
validate_norm_coord(B) when is_binary(B) ->
    case catch binary_to_float(B) of
        F when is_float(F) -> validate_norm_coord(F);
        _ ->
            case catch binary_to_integer(B) of
                I when is_integer(I) -> validate_norm_coord(I);
                _ -> {error, <<"invalid_number">>}
            end
    end;
validate_norm_coord(L) when is_list(L) ->
    validate_norm_coord(list_to_binary(L));
validate_norm_coord(_) -> {error, <<"invalid_type">>}.

%% NOTE: validate_polygon/is_valid_point borttaget (områden stöds ej längre).

maybe_updates(Specs, Body, Obj0) ->
    %% If a field is present but invalid => error (strict PATCH)
    lists:foldl(
      fun({Key, ValidateFun}, {ok, Obj}) ->
              case maps:is_key(Key, Body) of
                  false ->
                      {ok, Obj};
                  true ->
                      V0 = maps:get(Key, Body),
                      case ValidateFun(V0) of
                          {ok, V} -> {ok, Obj#{Key => V}};
                          {error, Msg} -> {error, <<Key/binary, ": ", Msg/binary>>}
                      end
              end;
         (_Spec, {error, _}=Err) ->
              Err
      end,
      {ok, Obj0},
      Specs).

query_map(A) ->
    %% Best-effort: use #arg.querydata if available (string without '?')
    Q0 = case A#arg.querydata of
             undefined -> "";
             L when is_list(L) -> L;
             B when is_binary(B) -> binary_to_list(B);
             _ -> ""
         end,
    case Q0 of
        "" -> #{};
        _ ->
            parse_querystring(Q0)
    end.

strip_api_prefix(Path0) ->
    Path = case Path0 of
               B when is_binary(B) -> binary_to_list(B);
               L when is_list(L) -> L
           end,
    case lists:prefix("/api", Path) of
        true ->
            Rest = lists:nthtail(4, Path),
            case Rest of
                [] -> "/";
                _ -> Rest
            end;
        false ->
            Path
    end.

split_path(Path0) ->
    Path = case Path0 of
               B when is_binary(B) -> binary_to_list(B);
               L when is_list(L) -> L
           end,
    Segs0 = string:tokens(Path, "/"),
    [S || S <- Segs0, S =/= ""].

%% NOTE: clamp_int/4 borttaget (används ej längre).

seed_rand() ->
    _ = rand:seed(exsplus, {erlang:monotonic_time(), erlang:unique_integer([positive]), erlang:phash2(self())}),
    ok.

shuffle(List) ->
    lists:foldl(fun(E, Acc) -> insert_random(E, Acc) end, [], List).

insert_random(E, Acc) ->
    case Acc of
        [] -> [E];
        _ ->
            Pos = rand:uniform(length(Acc) + 1),
            {A, B} = lists:split(Pos - 1, Acc),
            A ++ [E] ++ B
    end.

take_n(List, N) ->
    take_n(List, N, []).

take_n(_List, 0, Acc) ->
    lists:reverse(Acc);
take_n([], _N, Acc) ->
    lists:reverse(Acc);
take_n([H | T], N, Acc) ->
    take_n(T, N - 1, [H | Acc]).

now_rfc3339() ->
    %% OTP 22-kompatibel RFC3339 (UTC, Z)
    {{Y,Mo,D},{H,Mi,S}} = calendar:universal_time(),
    iolist_to_binary(io_lib:format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ", [Y,Mo,D,H,Mi,S])).

uuid_v4() ->
    <<A:32, B:16, C0:16, D0:16, E:48>> = crypto:strong_rand_bytes(16),
    C = (C0 band 16#0FFF) bor 16#4000,
    D = (D0 band 16#3FFF) bor 16#8000,
    lists:flatten(io_lib:format("~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b", [A,B,C,D,E])).

getenv_default(Key, Default) ->
    case os:getenv(Key) of
        false -> Default;
        V -> V
    end.

get_in(Map, [K | Rest]) when is_map(Map) ->
    case maps:get(K, Map, undefined) of
        undefined -> undefined;
        V -> get_in(V, Rest)
    end;
get_in(V, []) -> V;
get_in(_, _Ks) -> undefined.

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L) -> iolist_to_binary(L);
to_bin(A) when is_atom(A) -> atom_to_binary(A, utf8);
to_bin(I) when is_integer(I) -> integer_to_binary(I);
to_bin(F) when is_float(F) -> float_to_binary(F, [compact]);
to_bin(T) -> iolist_to_binary(io_lib:format("~p", [T])).

%%====================================================================
%% Security: validate setId to avoid path traversal (OTP22-safe)
%%====================================================================

with_valid_set_id(SetId0, Fun) ->
    SetId = case SetId0 of
                B when is_binary(B) -> binary_to_list(B);
                L when is_list(L) -> L
            end,
    case is_valid_uuid(SetId) of
        true -> Fun(SetId);
        false -> json_error(400, <<"invalid_set_id">>, #{<<"setId">> => to_bin(SetId)})
    end.

is_valid_uuid(S) when is_list(S) ->
    %% Enforce UUID v4-ish shape to prevent ".." and other traversal tokens.
    case re:run(S, "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", [{capture, none}]) of
        match -> true;
        nomatch -> false
    end.

%%====================================================================
%% Response helpers
%%====================================================================

json_ok(Code, Data) ->
    Body = iolist_to_binary(json_encode(#{<<"ok">> => true, <<"data">> => Data})),
    [{status, Code},
     {header, {"Content-Type", "application/json"}},
     {content, "application/json", Body}].

json_error(Code, Err, Details) ->
    Body = iolist_to_binary(json_encode(#{<<"ok">> => false, <<"error">> => Err, <<"details">> => Details})),
    [{status, Code},
     {header, {"Content-Type", "application/json"}},
     {content, "application/json", Body}].

%%====================================================================
%% OTP 22-compatible JSON + query parsing
%%====================================================================

%% Minimal JSON encoder/decoder to avoid OTP 27+ built-in json module dependency.
%% Supports:
%% - maps with binary/list/atom keys (encoded as JSON strings)
%% - lists (JSON arrays)
%% - binaries/lists (JSON strings, UTF-8 bytes kept as-is)
%% - integers/floats
%% - atoms true/false/null

json_encode(Term) ->
    encode_value(Term).

encode_value(null) -> <<"null">>;
encode_value(true) -> <<"true">>;
encode_value(false) -> <<"false">>;
encode_value(I) when is_integer(I) -> integer_to_binary(I);
encode_value(F) when is_float(F) -> float_to_binary(F, [compact]);
encode_value(B) when is_binary(B) -> encode_string(B);
encode_value(L) when is_list(L) ->
    %% Heuristic: treat as string if it's a flat (byte) list, else array
    case is_flat_string_list(L) of
        true -> encode_string(iolist_to_binary(L));
        false -> encode_array(L)
    end;
encode_value(M) when is_map(M) -> encode_object(M);
encode_value(Other) ->
    %% Fallback: represent as string
    encode_string(to_bin(Other)).

is_flat_string_list([]) -> true;
is_flat_string_list(L) ->
    lists:all(fun(C) -> is_integer(C) andalso C >= 0 andalso C =< 255 end, L).

encode_array(List) ->
    Inner = join_iolist([encode_value(V) || V <- List], <<",">>),
    [<<"[">>, Inner, <<"]">>].

encode_object(Map) ->
    Pairs0 = maps:to_list(Map),
    %% Stable-ish ordering for deterministic output (key as binary)
    Pairs = lists:sort(fun({K1,_},{K2,_}) -> to_bin(K1) =< to_bin(K2) end, Pairs0),
    Inner = join_iolist([encode_kv(K,V) || {K,V} <- Pairs], <<",">>),
    [<<"{">>, Inner, <<"}">>].

encode_kv(K, V) ->
    [encode_string(to_bin(K)), <<":">>, encode_value(V)].

encode_string(Bin) ->
    Esc = escape_json_string(binary_to_list(Bin), []),
    [<<"\"">>, lists:reverse(Esc), <<"\"">>].

escape_json_string([], Acc) ->
    Acc;
escape_json_string([$\n | T], Acc) ->
    escape_json_string(T, [$n, $\\ | Acc]);
escape_json_string([$\r | T], Acc) ->
    escape_json_string(T, [$r, $\\ | Acc]);
escape_json_string([$\t | T], Acc) ->
    escape_json_string(T, [$t, $\\ | Acc]);
escape_json_string([$\\ | T], Acc) ->
    escape_json_string(T, [$\\, $\\ | Acc]);
escape_json_string([$\" | T], Acc) ->
    escape_json_string(T, [$\", $\\ | Acc]);
escape_json_string([C | T], Acc) when C < 32 ->
    %% Control char -> \u00XX
    [H1,H2] = lists:flatten(io_lib:format("~2.16.0B", [C])),
    %% Acc byggs baklänges, så vi pushar omvänt: X2 X1 0 0 u \
    escape_json_string(T, [H2, H1, $0, $0, $u, $\\ | Acc]);
escape_json_string([C | T], Acc) ->
    escape_json_string(T, [C | Acc]).

join_iolist([], _Sep) -> <<>>;
join_iolist([One], _Sep) -> One;
join_iolist([H|T], Sep) ->
    [H, [[Sep, X] || X <- T]].

json_decode(Bin) when is_binary(Bin) ->
    {V, Rest} = parse_value(skip_ws(binary_to_list(Bin))),
    case skip_ws(Rest) of
        [] -> V;
        _ -> V
    end.

skip_ws([C|T]) when C =:= $\s; C =:= $\t; C =:= $\n; C =:= $\r -> skip_ws(T);
skip_ws(L) -> L.

parse_value([$\" | T]) ->
    parse_string(T, []);
parse_value([$\{ | T]) ->
    parse_object(skip_ws(T), #{});
parse_value([$[ | T]) ->
    parse_array(skip_ws(T), []);
parse_value([$t,$r,$u,$e | T]) -> {true, T};
parse_value([$f,$a,$l,$s,$e | T]) -> {false, T};
parse_value([$n,$u,$l,$l | T]) -> {null, T};
parse_value([C|_]=L) when (C >= $0 andalso C =< $9) orelse C =:= $- ->
    parse_number(L);
parse_value([]) -> {null, []}.

parse_object([$} | T], Acc) ->
    {Acc, T};
parse_object(L, Acc) ->
    %% key
    {K, Rest1} = case L of
                     [$\" | T] -> parse_string(T, []);
                     _ -> {<<>>, L}
                 end,
    Rest2 = skip_ws(Rest1),
    Rest3 = case Rest2 of [$:|T3] -> skip_ws(T3); _ -> Rest2 end,
    {V, Rest4} = parse_value(Rest3),
    Acc2 = Acc#{K => V},
    Rest5 = skip_ws(Rest4),
    case Rest5 of
        [$,|T5] -> parse_object(skip_ws(T5), Acc2);
        [$}|T5] -> {Acc2, T5};
        _ -> {Acc2, Rest5}
    end.

parse_array([$] | T], AccRev) ->
    {lists:reverse(AccRev), T};
parse_array(L, AccRev) ->
    {V, Rest1} = parse_value(L),
    Rest2 = skip_ws(Rest1),
    case Rest2 of
        [$,|T2] -> parse_array(skip_ws(T2), [V | AccRev]);
        [$]|T2] -> {lists:reverse([V | AccRev]), T2};
        _ -> {lists:reverse([V | AccRev]), Rest2}
    end.

parse_string([$\" | T], AccRev) ->
    {list_to_binary(lists:reverse(AccRev)), T};
parse_string([$\\, Esc | T], AccRev) ->
    case Esc of
        $\" -> parse_string(T, [$\" | AccRev]);
        $\\ -> parse_string(T, [$\\ | AccRev]);
        $/  -> parse_string(T, [$/  | AccRev]);
        $b  -> parse_string(T, [$\b | AccRev]);
        $f  -> parse_string(T, [$\f | AccRev]);
        $n  -> parse_string(T, [$\n | AccRev]);
        $r  -> parse_string(T, [$\r | AccRev]);
        $t  -> parse_string(T, [$\t | AccRev]);
        $u  ->
            case T of
                [H1,H2,H3,H4 | T2] ->
                    Code = hex4_to_int(H1,H2,H3,H4),
                    case unicode:characters_to_binary([Code], utf8) of
                        Bin when is_binary(Bin) ->
                            parse_string(T2, lists:reverse(binary_to_list(Bin), AccRev));
                        _ ->
                            %% Ogiltig unicode-sekvens -> hoppa över tecknet
                            parse_string(T2, AccRev)
                    end;
                _ ->
                    parse_string(T, AccRev)
            end;
        _ ->
            parse_string(T, [Esc | AccRev])
    end;
parse_string([C | T], AccRev) ->
    parse_string(T, [C | AccRev]);
parse_string([], AccRev) ->
    {list_to_binary(lists:reverse(AccRev)), []}.

hex4_to_int(A,B,C,D) ->
    (hex_to_int(A) bsl 12) bor (hex_to_int(B) bsl 8) bor (hex_to_int(C) bsl 4) bor hex_to_int(D).

hex_to_int(C) when C >= $0, C =< $9 -> C - $0;
hex_to_int(C) when C >= $A, C =< $F -> 10 + (C - $A);
hex_to_int(C) when C >= $a, C =< $f -> 10 + (C - $a);
hex_to_int(_) -> 0.

parse_number(L) ->
    {Tok, Rest} = take_number_token(L, []),
    TokStr = lists:reverse(Tok),
    case lists:member($., TokStr) orelse lists:member($e, TokStr) orelse lists:member($E, TokStr) of
        true ->
            {list_to_float_safe(TokStr), Rest};
        false ->
            {list_to_integer_safe(TokStr), Rest}
    end.

take_number_token([C|T], Acc) when (C >= $0 andalso C =< $9) orelse C =:= $- orelse C =:= $+ orelse C =:= $. orelse C =:= $e orelse C =:= $E ->
    take_number_token(T, [C|Acc]);
take_number_token(Rest, Acc) ->
    {Acc, Rest}.

list_to_integer_safe(Str) ->
    try list_to_integer(Str) catch _:_ -> 0 end.

list_to_float_safe(Str) ->
    try list_to_float(Str) catch _:_ -> 0.0 end.

%% Query string parsing (OTP 22 compatible)
parse_querystring(QS) when is_list(QS) ->
    Parts = string:tokens(QS, "&"),
    Pairs = [parse_qs_kv(P) || P <- Parts, P =/= ""],
    maps:from_list(Pairs);
parse_querystring(_) ->
    #{}.

parse_qs_kv(S) ->
    case string:tokens(S, "=") of
        [K,V|_] -> {to_bin(url_decode(K)), to_bin(url_decode(V))};
        [K] -> {to_bin(url_decode(K)), <<>>};
        _ -> {<<>>, <<>>}
    end.

url_decode(S) when is_list(S) ->
    url_decode_list(S, []).

url_decode_list([], Acc) ->
    lists:reverse(Acc);
url_decode_list([$+|T], Acc) ->
    url_decode_list(T, [$\s|Acc]);
url_decode_list([$%,A,B|T], Acc) ->
    V = (hex_to_int(A) bsl 4) bor hex_to_int(B),
    url_decode_list(T, [V|Acc]);
url_decode_list([C|T], Acc) ->
    url_decode_list(T, [C|Acc]).

request_path(A) ->
    %% Kompatibilitet: vissa Yaws-versioner saknar yaws_api:request_path/1.
    case erlang:function_exported(yaws_api, request_path, 1) of
        true ->
            yaws_api:request_path(A);
        false ->
            %% #arg.server_path är normaliserad path (utan querystring)
            case A#arg.server_path of
                undefined -> "/";
                B when is_binary(B) -> B;
                L when is_list(L) -> L;
                _ -> "/"
            end
    end.

