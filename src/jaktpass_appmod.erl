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
-include_lib("yaws/include/yaws_api.hrl").
-include_lib("yaws/include/yaws.hrl").

%%====================================================================
%% Entry
%%====================================================================

out(A) ->
    try
        Method = ((A#arg.req)#http_request.method),
        Path0  = yaws_api:request_path(A),
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
    handle_get_set(SetId);
dispatch('GET', ["sets", SetId, "quiz"], A) ->
    handle_get_quiz(SetId, A);
dispatch('GET', ["media", "sets", SetId, "image"], _A) ->
    handle_get_image(SetId);

%% Admin
dispatch('POST', ["admin", "sets"], A) ->
    with_admin(A, fun() -> handle_post_admin_sets(A) end);
dispatch('POST', ["admin", "sets", SetId, "image"], A) ->
    with_admin(A, fun() -> handle_post_admin_set_image(SetId, A) end);
dispatch('POST', ["admin", "sets", SetId, "stands"], A) ->
    with_admin(A, fun() -> handle_post_admin_set_stands(SetId, A) end);
dispatch('PATCH', ["admin", "stands", StandId], A) ->
    with_admin(A, fun() -> handle_patch_admin_stand(StandId, A) end);
dispatch('DELETE', ["admin", "stands", StandId], A) ->
    with_admin(A, fun() -> handle_delete_admin_stand(StandId) end);

dispatch('POST', ["admin", "sets", SetId, "areas"], A) ->
    with_admin(A, fun() -> handle_post_admin_set_areas(SetId, A) end);
dispatch('PATCH', ["admin", "areas", AreaId], A) ->
    with_admin(A, fun() -> handle_patch_admin_area(AreaId, A) end);
dispatch('DELETE', ["admin", "areas", AreaId], A) ->
    with_admin(A, fun() -> handle_delete_admin_area(AreaId) end);

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
    AreaId = maps:get(<<"areaId">>, Q, undefined),
    Count0 = maps:get(<<"count">>, Q, <<"10">>),
    Count = clamp_int(Count0, 1, 200, 10),
    _Mode = maps:get(<<"mode">>, Q, <<"rand">>),
    case load_set_meta(SetId) of
        {ok, Meta} ->
            Stands0 = maps:get(<<"stands">>, Meta, []),
            Areas0  = maps:get(<<"areas">>, Meta, []),
            case
                (case AreaId of
                     undefined -> {ok, Stands0};
                     <<>> -> {ok, Stands0};
                     _ ->
                         case find_by_id(Areas0, AreaId) of
                             {ok, Area} ->
                                 Poly = maps:get(<<"polygon">>, Area, []),
                                 {ok, filter_stands_in_poly(Stands0, Poly)};
                             not_found ->
                                 {error, area_not_found}
                         end
                 end)
            of
                {error, area_not_found} ->
                    json_error(404, <<"area_not_found">>, #{<<"areaId">> => AreaId});
                {ok, VisibleStands} ->
                    VisibleDots = [#{<<"id">> => maps:get(<<"id">>, S),
                                     <<"x">> => maps:get(<<"x">>, S),
                                     <<"y">> => maps:get(<<"y">>, S)} || S <- VisibleStands],
                    seed_rand(),
                    Sample = take_n(shuffle(VisibleStands), Count),
                    Questions = [#{<<"standId">> => maps:get(<<"id">>, S),
                                   <<"name">> => maps:get(<<"name">>, S)} || S <- Sample],
                    json_ok(200, #{<<"visibleStands">> => VisibleDots,
                                   <<"questions">> => Questions})
            end;
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
                        <<"stands">> => [],
                        <<"areas">> => []
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

handle_post_admin_set_areas(SetId, A) ->
    with_set_lock(SetId, fun() ->
        case {load_set_meta(SetId), read_json_body(A)} of
            {{ok, Meta0}, {ok, Body}} ->
                Name0 = maps:get(<<"name">>, Body, undefined),
                Poly0 = maps:get(<<"polygon">>, Body, undefined),
                case {validate_nonempty_string(Name0), validate_polygon(Poly0)} of
                    {{ok, Name}, {ok, Poly}} ->
                        Now = now_rfc3339(),
                        Area = #{
                            <<"id">> => to_bin(uuid_v4()),
                            <<"name">> => Name,
                            <<"polygon">> => Poly,
                            <<"createdAt">> => Now,
                            <<"updatedAt">> => Now
                        },
                        Areas0 = maps:get(<<"areas">>, Meta0, []),
                        Meta = Meta0#{<<"areas">> => [Area | Areas0]},
                        case save_set_meta(SetId, Meta) of
                            ok -> json_ok(201, Area);
                            {error, Reason} -> json_error(500, <<"failed_to_save_meta">>, #{<<"reason">> => to_bin(Reason)})
                        end;
                    _ ->
                        json_error(400, <<"invalid_payload">>, #{<<"expected">> => <<"name + polygon(min 3 points)">>})
                end;
            {{error, enoent}, _} ->
                json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
            {{error, Reason}, _} ->
                json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)});
            {_, {error, Msg}} ->
                json_error(400, <<"invalid_json">>, #{<<"details">> => Msg})
        end
    end).

handle_patch_admin_area(AreaId, A) ->
    case read_json_body(A) of
        {ok, Body} ->
            patch_entity_by_id(<<"areas">>, AreaId, fun(Area0) ->
                Now = now_rfc3339(),
                case maybe_updates([
                        {<<"name">>, fun validate_nonempty_string/1},
                        {<<"polygon">>, fun validate_polygon/1}
                    ], Body, Area0) of
                    {error, Msg} -> {error, Msg};
                    {ok, Area2} -> {ok, Area2#{<<"updatedAt">> => Now}}
                end
            end);
        {error, Msg} ->
            json_error(400, <<"invalid_json">>, #{<<"details">> => Msg})
    end.

handle_delete_admin_area(AreaId) ->
    delete_entity_by_id(<<"areas">>, AreaId).

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
     {content, "application/json", iolist_to_binary(json:encode(#{
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
    getenv_default("JAKTPASS_DATA_DIR", "./data").

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
                {ok, json:decode(Bin)}
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
    Bin = iolist_to_binary(json:encode(Term)),
    case file:write_file(Tmp, Bin) of
        ok -> file:rename(Tmp, Path);
        {error, Reason} -> {error, Reason}
    end.

%% Per-set lock using global:trans (single-node assumption).
with_set_lock(SetId, Fun) ->
    global:trans({jaktpass_set, SetId}, Fun, [node()], 30000).

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

find_by_id(List0, Id0) ->
    Id = to_bin(Id0),
    case lists:filter(fun(E) -> maps:get(<<"id">>, E, undefined) =:= Id end, List0) of
        [E | _] -> {ok, E};
        [] -> not_found
    end.

%%====================================================================
%% Geometry (point in polygon)
%%====================================================================

filter_stands_in_poly(Stands, Poly0) ->
    Poly = [to_xy(P) || P <- Poly0],
    lists:filter(fun(S) ->
        {X, Y} = {maps:get(<<"x">>, S), maps:get(<<"y">>, S)},
        point_in_polygon({X, Y}, Poly)
    end, Stands).

to_xy(#{<<"x">> := X, <<"y">> := Y}) -> {X, Y};
to_xy(#{x := X, y := Y}) -> {X, Y};
to_xy(#{<<"x">> := X, y := Y}) -> {X, Y};
to_xy(#{x := X, <<"y">> := Y}) -> {X, Y};
to_xy(_) -> {0.0, 0.0}.

point_in_polygon({_Px, _Py}, []) -> false;
point_in_polygon({Px, Py}, Poly) when length(Poly) < 3 -> false;
point_in_polygon({Px, Py}, Poly) ->
    Edges = edges(Poly),
    Cnt =
        lists:foldl(
          fun({{X1, Y1}, {X2, Y2}}, Acc) ->
              %% Ray casting: count intersections with horizontal ray to +inf
              IntersectsY = ((Y1 > Py) =/= (Y2 > Py)),
              if
                  IntersectsY ->
                      Xinters = (X2 - X1) * (Py - Y1) / (Y2 - Y1 + 0.0) + X1,
                      if Px < Xinters -> Acc + 1; true -> Acc end;
                  true ->
                      Acc
              end
          end, 0, Edges),
    (Cnt rem 2) =:= 1.

edges([First | _] = Poly) ->
    lists:zip(Poly, tl(Poly) ++ [First]).

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

jpeg_scan(<<16#FF, Marker:8, Len:16/big, Payload/binary>>) when Marker =:= 16#C0; Marker =:= 16#C2 ->
    %% SOF0 / SOF2: [precision][height][width]...
    case Payload of
        <<_Precision:8, H:16/big, W:16/big, _/binary>> ->
            {W, H};
        _ ->
            {undefined, undefined}
    end;
jpeg_scan(<<16#FF, Marker:8, Len:16/big, Rest/binary>>) ->
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
                {ok, json:decode(Bin)}
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
    case binary:trim(B) of
        <<>> -> {error, <<"empty">>};
        T -> {ok, T}
    end;
validate_nonempty_string(L) when is_list(L) ->
    validate_nonempty_string(list_to_binary(L));
validate_nonempty_string(_) -> {error, <<"invalid_type">>}.

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

validate_polygon(Poly) when is_list(Poly) ->
    case length(Poly) >= 3 of
        false -> {error, <<"too_few_points">>};
        true ->
            case lists:all(fun is_valid_point/1, Poly) of
                true ->
                    %% Normalize to [{"x":float,"y":float},...]
                    {ok, [#{<<"x">> => X, <<"y">> => Y} || {X,Y} <- [to_xy(P) || P <- Poly]]};
                false ->
                    {error, <<"invalid_points">>}
            end
    end;
validate_polygon(_) ->
    {error, <<"invalid_type">>}.

is_valid_point(P) ->
    {X, Y} = to_xy(P),
    is_number(X) andalso is_number(Y) andalso X >= 0.0 andalso X =< 1.0 andalso Y >= 0.0 andalso Y =< 1.0.

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
            try
                Pairs = uri_string:dissect_query(Q0),
                maps:from_list([{to_bin(K), to_bin(V)} || {K, V} <- Pairs])
            catch _:_ ->
                #{}
            end
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

clamp_int(BinOrNum, Min, Max, Default) ->
    N =
        case BinOrNum of
            I when is_integer(I) -> I;
            F when is_float(F) -> trunc(F);
            B when is_binary(B) ->
                case catch binary_to_integer(B) of
                    I2 when is_integer(I2) -> I2;
                    _ -> Default
                end;
            L when is_list(L) ->
                clamp_int(list_to_binary(L), Min, Max, Default);
            _ -> Default
        end,
    erlang:max(Min, erlang:min(Max, N)).

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
    calendar:system_time_to_rfc3339(erlang:system_time(second), [{offset, "Z"}]).

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
%% Response helpers
%%====================================================================

json_ok(Code, Data) ->
    Body = iolist_to_binary(json:encode(#{<<"ok">> => true, <<"data">> => Data})),
    [{status, Code},
     {header, {"Content-Type", "application/json"}},
     {content, "application/json", Body}].

json_error(Code, Err, Details) ->
    Body = iolist_to_binary(json:encode(#{<<"ok">> => false, <<"error">> => Err, <<"details">> => Details})),
    [{status, Code},
     {header, {"Content-Type", "application/json"}},
     {content, "application/json", Body}].


