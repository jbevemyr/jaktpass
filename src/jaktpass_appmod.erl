%%%-------------------------------------------------------------------
%%% jaktpass_appmod.erl - Yaws appmod for jaktpass MVP
%%%
%%% All API routing goes via /api (yaws.conf: appmods = <"/api", jaktpass_appmod>)
%%% Persistence: JSON + image files on disk under JAKTPASS_DATA_DIR (default ./data)
%%% Admin protection: Basic Auth for /api/admin/*
%%%-------------------------------------------------------------------

-module(jaktpass_appmod).
-export([out/1, start/0, stop/0]).

%% Vissa Yaws-versioner anropar Appmod:start/0 vid load.
start() -> ok.
stop() -> ok.

%% Yaws records (#arg, #http_request, #headers, ...)
%% OTP 22: använd lokal header (incheckad i repo) istället för include_lib(...)
-include("yaws_api.hrl").

%% Multipart continuation state (Yaws parse_multipart_post/1)
-record(mp_state, {count = 0, acc = []}).

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
            io:format("~p:~p~n~p~n", [Class,Reason, Stack]),
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
dispatch('GET', ["sets", SetId, "leaderboard"], A) ->
    with_valid_set_id(SetId, fun(SId) -> handle_get_leaderboard(SId, A) end);
dispatch('POST', ["sets", SetId, "leaderboard"], A) ->
    with_valid_set_id(SetId, fun(SId) -> handle_post_leaderboard(SId, A) end);
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

%% V2 (multi-admin) - separat namespace under /api/v2/*
dispatch('POST', ["v2", "register"], A) ->
    handle_v2_register(A);
dispatch('POST', ["v2", "login"], A) ->
    handle_v2_login(A);
dispatch('POST', ["v2", "logout"], A) ->
    handle_v2_logout(A);
dispatch('GET', ["v2", "me"], A) ->
    handle_v2_me(A);

%% V2 admin-protected (session cookie)
dispatch('GET', ["v2", "sets"], A) ->
    with_v2_admin(A, fun(Admin) -> handle_v2_get_sets(Admin) end);
dispatch('POST', ["v2", "sets"], A) ->
    with_v2_admin(A, fun(Admin) -> handle_v2_post_sets(Admin, A) end);
dispatch('GET', ["v2", "sets", SetId], A) ->
    with_v2_admin(A, fun(Admin) -> with_valid_set_id(SetId, fun(SId) -> handle_v2_get_set(Admin, SId) end) end);
dispatch('POST', ["v2", "sets", SetId, "image"], A) ->
    with_v2_admin(A, fun(Admin) -> with_valid_set_id(SetId, fun(SId) -> handle_v2_post_set_image(Admin, SId, A) end) end);
dispatch('POST', ["v2", "sets", SetId, "stands"], A) ->
    with_v2_admin(A, fun(Admin) -> with_valid_set_id(SetId, fun(SId) -> handle_v2_post_set_stands(Admin, SId, A) end) end);
dispatch('PATCH', ["v2", "sets", SetId, "stands", StandId], A) ->
    with_v2_admin(A, fun(Admin) -> with_valid_set_id(SetId, fun(SId) -> handle_v2_patch_stand(Admin, SId, StandId, A) end) end);
dispatch('DELETE', ["v2", "sets", SetId, "stands", StandId], A) ->
    with_v2_admin(A, fun(Admin) -> with_valid_set_id(SetId, fun(SId) -> handle_v2_delete_stand(Admin, SId, StandId) end) end);
dispatch('POST', ["v2", "sets", SetId, "share"], A) ->
    with_v2_admin(A, fun(Admin) -> with_valid_set_id(SetId, fun(SId) -> handle_v2_post_share(Admin, SId) end) end);

%% V2 public (share token)
dispatch('GET', ["v2", "quiz", ShareId, "leaderboard"], A) ->
    handle_v2_get_leaderboard(ShareId, A);
dispatch('POST', ["v2", "quiz", ShareId, "leaderboard"], A) ->
    handle_v2_post_leaderboard(ShareId, A);
dispatch('GET', ["v2", "quiz", ShareId], A) ->
    handle_v2_get_quiz(ShareId, A);
dispatch('GET', ["v2", "media", "shares", ShareId, "image"], _A) ->
    handle_v2_get_share_image(ShareId);

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
                             <<"y">> => maps:get(<<"y">>, S),
                             <<"symbol">> => maps:get(<<"symbol">>, S, <<"dot">>)} || S <- Sample],
            Questions = [#{<<"standId">> => maps:get(<<"id">>, S),
                           <<"name">> => maps:get(<<"name">>, S)} || S <- Sample],
            json_ok(200, #{<<"visibleStands">> => VisibleDots,
                           <<"questions">> => Questions});
        {error, enoent} ->
            json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
        {error, Reason} ->
            json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
    end.

handle_get_leaderboard(SetId, A) ->
    Q = query_map(A),
    Mode0 = maps:get(<<"mode">>, Q, <<"all">>),
    Mode = normalize_quiz_mode(Mode0),
    with_set_lock(SetId, fun() ->
        case load_leaderboard(SetId) of
            {ok, Items0} ->
                Items1 = [I || I <- Items0, maps:get(<<"mode">>, I, <<"all">>) =:= Mode],
                Items = take_n(sort_leaderboard(Items1), 20),
                json_ok(200, #{<<"mode">> => Mode, <<"items">> => Items});
            {error, Reason} ->
                json_error(500, <<"failed_to_load_leaderboard">>, #{<<"reason">> => to_bin(Reason)})
        end
    end).

handle_post_leaderboard(SetId, A) ->
    with_set_lock(SetId, fun() ->
        case read_json_body(A) of
            {ok, Body} ->
                Name0 = maps:get(<<"name">>, Body, undefined),
                Score0 = maps:get(<<"score">>, Body, undefined),
                Mode0 = maps:get(<<"mode">>, Body, <<"all">>),
                case {validate_player_name(Name0), validate_score(Score0)} of
                    {{ok, Name}, {ok, Score}} ->
                        Mode = normalize_quiz_mode(Mode0),
                        Now = now_rfc3339(),
                        Item = #{
                            <<"name">> => Name,
                            <<"score">> => Score,
                            <<"mode">> => Mode,
                            <<"createdAt">> => Now
                        },
                        Items0 =
                            case load_leaderboard(SetId) of
                                {ok, L} when is_list(L) -> L;
                                _ -> []
                            end,
                        Items1 = [Item | Items0],
                        Items2 = take_n(sort_leaderboard(Items1), 200),
                        case save_leaderboard(SetId, Items2) of
                            ok ->
                                Top = take_n([I || I <- Items2, maps:get(<<"mode">>, I, <<"all">>) =:= Mode], 20),
                                json_ok(201, #{<<"saved">> => true, <<"mode">> => Mode, <<"items">> => Top});
                            {error, Reason} ->
                                json_error(500, <<"failed_to_save_leaderboard">>, #{<<"reason">> => to_bin(Reason)})
                        end;
                    {{error, Msg}, _} ->
                        json_error(400, <<"invalid_name">>, #{<<"details">> => Msg});
                    {_, {error, Msg}} ->
                        json_error(400, <<"invalid_score">>, #{<<"details">> => Msg})
                end;
            {error, Msg} ->
                json_error(400, <<"invalid_json">>, #{<<"details">> => Msg})
        end
    end).

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
    %% Viktigt: multipart kan komma som continuation i Yaws.
    %% Vi kan inte hålla set-lock över flera get_more-roundtrips.
    case parse_multipart_file(A, "file") of
        {get_more, Cont, PState} ->
            {get_more, Cont, PState};
        {ok, #{filename := OrigName, data := Bin}} ->
            with_set_lock(SetId, fun() ->
                case load_set_meta(SetId) of
                    {ok, Meta0} ->
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
                    {error, enoent} ->
                        json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
                    {error, Reason} ->
                        json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
                end
            end);
        {error, Msg} ->
            json_error(400, <<"invalid_multipart">>, #{<<"details">> => Msg})
    end.

handle_post_admin_set_stands(SetId, A) ->
    with_set_lock(SetId, fun() ->
        case {load_set_meta(SetId), read_json_body(A)} of
            {{ok, Meta0}, {ok, Body}} ->
                Name0 = maps:get(<<"name">>, Body, undefined),
                X0 = maps:get(<<"x">>, Body, undefined),
                Y0 = maps:get(<<"y">>, Body, undefined),
                Note0 = maps:get(<<"note">>, Body, undefined),
                Sym0 = maps:get(<<"symbol">>, Body, undefined),
                case {validate_nonempty_string(Name0),
                      validate_norm_coord(X0),
                      validate_norm_coord(Y0),
                      validate_symbol(Sym0)} of
                    {{ok, Name}, {ok, X}, {ok, Y}, {ok, Sym}} ->
                        Now = now_rfc3339(),
                        Stand = #{
                            <<"id">> => to_bin(uuid_v4()),
                            <<"name">> => Name,
                            <<"x">> => X,
                            <<"y">> => Y,
                            <<"symbol">> => Sym,
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
                        json_error(400, <<"invalid_payload">>, #{<<"expected">> => <<"name + x + y (0..1) + symbol?">>})
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
                        {<<"y">>, fun validate_norm_coord/1},
                        {<<"symbol">>, fun validate_symbol/1}
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

%%====================================================================
%% V2 auth (multi-admin) - cookie session
%%====================================================================

with_v2_admin(A, Fun) ->
    case v2_current_admin(A) of
        {ok, Admin} -> Fun(Admin);
        _ -> v2_unauthorized()
    end.

v2_unauthorized() ->
    [{status, 401},
     {header, {"Content-Type", "application/json"}},
     {content, "application/json", iolist_to_binary(json_encode(#{
         <<"ok">> => false,
         <<"error">> => <<"unauthorized">>,
         <<"details">> => <<"Not logged in">>
     }))}].

handle_v2_me(A) ->
    case v2_current_admin(A) of
        {ok, Admin} ->
            json_ok(200, #{<<"admin">> => v2_admin_public(Admin)});
        _ ->
            v2_unauthorized()
    end.

handle_v2_logout(A) ->
    _ = v2_delete_session(A),
    json_ok_headers(200, #{<<"loggedOut">> => true}, [v2_set_cookie_header_expire()]).

handle_v2_register(A) ->
    case read_json_body(A) of
        {ok, Body} ->
            Email0 = maps:get(<<"email">>, Body, undefined),
            Pass0 = maps:get(<<"password">>, Body, undefined),
            case {validate_email(Email0), validate_password(Pass0)} of
                {{ok, Email}, {ok, Pass}} ->
                    v2_with_lock(fun() ->
                        case v2_lookup_admin_by_email(Email) of
                            {ok, _ExistingId} ->
                                json_error(409, <<"email_taken">>, #{});
                            not_found ->
                                AdminId = uuid_v4(),
                                Salt = crypto:strong_rand_bytes(16),
                                Hash = v2_password_hash(Pass, Salt),
                                Admin = #{
                                    <<"id">> => to_bin(AdminId),
                                    <<"email">> => Email,
                                    <<"pw">> => #{
                                        <<"alg">> => <<"pbkdf2_sha256">>,
                                        <<"iter">> => 100000,
                                        <<"salt">> => base64:encode(Salt),
                                        <<"hash">> => base64:encode(Hash)
                                    },
                                    <<"createdAt">> => now_rfc3339()
                                },
                                ok = v2_save_admin(AdminId, Admin),
                                ok = v2_index_put_email(Email, AdminId),
                                {SessTok, SessHdr} = v2_new_session(AdminId),
                                json_ok_headers(201,
                                    #{<<"admin">> => v2_admin_public(Admin), <<"session">> => #{<<"token">> => to_bin(SessTok)}},
                                    [SessHdr])
                        end
                    end);
                {{error, Msg}, _} ->
                    json_error(400, <<"invalid_email">>, #{<<"details">> => Msg});
                {_, {error, Msg}} ->
                    json_error(400, <<"invalid_password">>, #{<<"details">> => Msg})
            end;
        {error, Msg} ->
            json_error(400, <<"invalid_json">>, #{<<"details">> => Msg})
    end.

handle_v2_login(A) ->
    case read_json_body(A) of
        {ok, Body} ->
            Email0 = maps:get(<<"email">>, Body, undefined),
            Pass0 = maps:get(<<"password">>, Body, undefined),
            v2_auth_dbg("login body email_type=~p pass_type=~p", [type_tag(Email0), type_tag(Pass0)]),
            case {validate_email(Email0), validate_password(Pass0)} of
                {{ok, Email}, {ok, Pass}} ->
                    v2_auth_dbg("login validate ok email=~p pass_bytes=~p", [Email, byte_size(Pass)]),
                    v2_with_lock(fun() ->
                        case v2_lookup_admin_by_email(Email) of
                            {ok, AdminId} ->
                                v2_auth_dbg("login found adminId=~p", [AdminId]),
                                case v2_load_admin(AdminId) of
                                    {ok, Admin} ->
                                        v2_auth_dbg("login loaded admin ok keys=~p", [maps:keys(Admin)]),
                                        case v2_password_verify(Pass, Admin) of
                                            true ->
                                                v2_auth_dbg("login password_verify=true", []),
                                                {SessTok, SessHdr} = v2_new_session(AdminId),
                                                json_ok_headers(200,
                                                    #{<<"admin">> => v2_admin_public(Admin), <<"session">> => #{<<"token">> => to_bin(SessTok)}},
                                                    [SessHdr]);
                                            false ->
                                                v2_auth_dbg("login password_verify=false", []),
                                                v2_unauthorized()
                                        end;
                                    _ ->
                                        v2_auth_dbg("login failed to load admin", []),
                                        v2_unauthorized()
                                end;
                            not_found ->
                                v2_auth_dbg("login email not_found", []),
                                v2_unauthorized()
                        end
                    end);
                _ ->
                    v2_auth_dbg("login validate failed", []),
                    v2_unauthorized()
            end;
        _ ->
            v2_auth_dbg("login invalid_json", []),
            v2_unauthorized()
    end.

%%====================================================================
%% V2 handlers (multi-admin)
%%====================================================================

v2_admin_id(Admin) ->
    binary_to_list(to_bin(maps:get(<<"id">>, Admin, <<"">>))).

with_v2_set_lock(AdminId, SetId, Fun) ->
    global:trans({jaktpass_v2_set, {AdminId, SetId}}, Fun, [node()], 30000).

handle_v2_get_sets(Admin) ->
    AdminId = v2_admin_id(Admin),
    Root = v2_admin_sets_dir(AdminId),
    ok = filelib:ensure_dir(filename:join([Root, "dummy"])),
    case file:list_dir(Root) of
        {ok, Entries} ->
            Sets = lists:foldl(
                     fun(SetId, Acc) ->
                         case v2_load_set_meta(AdminId, SetId) of
                             {ok, Meta} ->
                                 Name = get_in(Meta, [<<"set">>, <<"name">>]),
                                 HasImage =
                                     case get_in(Meta, [<<"image">>, <<"filename">>]) of
                                         undefined -> false;
                                         null -> false;
                                         <<>> -> false;
                                         _ -> true
                                     end,
                                 ShareId = maps:get(<<"shareId">>, Meta, null),
                                 [#{<<"id">> => to_bin(SetId), <<"name">> => Name, <<"hasImage">> => HasImage, <<"shareId">> => ShareId} | Acc];
                             _ -> Acc
                         end
                     end, [], Entries),
            json_ok(200, lists:reverse(Sets));
        {error, enoent} ->
            json_ok(200, []);
        {error, Reason} ->
            json_error(500, <<"failed_to_list_sets">>, #{<<"reason">> => to_bin(Reason)})
    end.

handle_v2_post_sets(Admin, A) ->
    AdminId = v2_admin_id(Admin),
    case read_json_body(A) of
        {ok, Body} ->
            Name0 = maps:get(<<"name">>, Body, undefined),
            case validate_nonempty_string(Name0) of
                {ok, Name} ->
                    SetId = uuid_v4(),
                    Now = now_rfc3339(),
                    %% Skapa shareId direkt (en share per set)
                    ShareId = v2_new_share(AdminId, SetId),
                    Meta = #{
                        <<"set">> => #{<<"id">> => to_bin(SetId), <<"name">> => Name, <<"createdAt">> => Now},
                        <<"image">> => null,
                        <<"stands">> => [],
                        <<"shareId">> => to_bin(ShareId)
                    },
                    case v2_save_set_meta(AdminId, SetId, Meta) of
                        ok ->
                            Url = v2_share_url(ShareId),
                            json_ok(201, #{<<"id">> => to_bin(SetId), <<"shareId">> => to_bin(ShareId), <<"shareUrl">> => Url});
                        {error, Reason} ->
                            json_error(500, <<"failed_to_create_set">>, #{<<"reason">> => to_bin(Reason)})
                    end;
                {error, Msg} ->
                    json_error(400, <<"invalid_name">>, #{<<"details">> => Msg})
            end;
        {error, Msg} ->
            json_error(400, <<"invalid_json">>, #{<<"details">> => Msg})
    end.

handle_v2_get_set(Admin, SetId) ->
    AdminId = v2_admin_id(Admin),
    with_v2_set_lock(AdminId, SetId, fun() ->
        case v2_load_set_meta(AdminId, SetId) of
            {ok, Meta0} ->
                ShareId = maps:get(<<"shareId">>, Meta0, null),
                ImageUrl =
                    case {ShareId, get_in(Meta0, [<<"image">>, <<"filename">>])} of
                        {null, _} -> null;
                        {_, undefined} -> null;
                        {_, null} -> null;
                        {_, <<>>} -> null;
                        {SId, _} -> <<"/api/v2/media/shares/", (to_bin(SId))/binary, "/image">>
                    end,
                Meta = Meta0#{<<"imageUrl">> => ImageUrl},
                json_ok(200, Meta);
            {error, enoent} ->
                json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
            {error, Reason} ->
                json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
        end
    end).

handle_v2_post_set_image(Admin, SetId, A) ->
    %% Multipart kan komma som continuation i Yaws (get_more).
    case parse_multipart_file(A, "file") of
        {get_more, Cont, PState} ->
            {get_more, Cont, PState};
        {ok, #{filename := OrigName, data := Bin}} ->
            AdminId = v2_admin_id(Admin),
            with_v2_set_lock(AdminId, SetId, fun() ->
                case v2_load_set_meta(AdminId, SetId) of
                    {ok, Meta0} ->
                        case image_ext(OrigName) of
                            {ok, Ext} ->
                                Filename = "image." ++ Ext,
                                Path = filename:join([v2_set_dir(AdminId, SetId), Filename]),
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
                                case v2_save_set_meta(AdminId, SetId, Meta) of
                                    ok -> json_ok(200, ImageMeta);
                                    {error, Reason} -> json_error(500, <<"failed_to_update_meta">>, #{<<"reason">> => to_bin(Reason)})
                                end;
                            {error, invalid_ext} ->
                                json_error(400, <<"invalid_image_extension">>, #{<<"allowed">> => [<<"png">>,<<"jpg">>,<<"jpeg">>,<<"webp">>]})
                        end;
                    {error, enoent} ->
                        json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
                    {error, Reason} ->
                        json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
                end
            end);
        {error, Msg} ->
            json_error(400, <<"invalid_multipart">>, #{<<"details">> => Msg})
    end.

handle_v2_post_set_stands(Admin, SetId, A) ->
    AdminId = v2_admin_id(Admin),
    with_v2_set_lock(AdminId, SetId, fun() ->
        v2_auth_dbg("v2 stands clidata=~p cont=~p", [type_tag(A#arg.clidata), A#arg.cont]),
        case {v2_load_set_meta(AdminId, SetId), read_json_body(A)} of
            {{ok, Meta0}, {ok, Body}} ->
                Name0 = maps:get(<<"name">>, Body, undefined),
                X0 = maps:get(<<"x">>, Body, undefined),
                Y0 = maps:get(<<"y">>, Body, undefined),
                Sym0 = maps:get(<<"symbol">>, Body, undefined),
                case {validate_nonempty_string(Name0), validate_norm_coord(X0), validate_norm_coord(Y0), validate_symbol(Sym0)} of
                    {{ok, Name}, {ok, X}, {ok, Y}, {ok, Sym}} ->
                        Now = now_rfc3339(),
                        Stand = #{
                            <<"id">> => to_bin(uuid_v4()),
                            <<"name">> => Name,
                            <<"x">> => X,
                            <<"y">> => Y,
                            <<"symbol">> => Sym,
                            <<"createdAt">> => Now,
                            <<"updatedAt">> => Now
                        },
                        Stands0 = maps:get(<<"stands">>, Meta0, []),
                        Meta = Meta0#{<<"stands">> => [Stand | Stands0]},
                        case v2_save_set_meta(AdminId, SetId, Meta) of
                            ok -> json_ok(201, Stand);
                            {error, Reason} -> json_error(500, <<"failed_to_update_meta">>, #{<<"reason">> => to_bin(Reason)})
                        end;
                    _ ->
                        json_error(400, <<"invalid_stand">>, #{})
                end;
            {{error, enoent}, _} ->
                json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
            {_, {error, Msg}} ->
                json_error(400, <<"invalid_json">>, #{<<"details">> => Msg});
            {_, {ok, _}} ->
                json_error(500, <<"failed_to_load_set">>, #{})
        end
    end).

handle_v2_patch_stand(Admin, SetId, StandId0, A) ->
    AdminId = v2_admin_id(Admin),
    StandId = to_bin(StandId0),
    with_v2_set_lock(AdminId, SetId, fun() ->
        case {v2_load_set_meta(AdminId, SetId), read_json_body(A)} of
            {{ok, Meta0}, {ok, Body}} ->
                Stands0 = maps:get(<<"stands">>, Meta0, []),
                case split_by_id(Stands0, StandId) of
                    {ok, Stand0, Rest} ->
                        Specs = [
                            {<<"name">>, fun validate_nonempty_string/1},
                            {<<"x">>, fun validate_norm_coord/1},
                            {<<"y">>, fun validate_norm_coord/1},
                            {<<"symbol">>, fun validate_symbol/1}
                        ],
                        case maybe_updates(Specs, Body, Stand0) of
                            {ok, Stand1} ->
                                Stand2 = Stand1#{<<"updatedAt">> => now_rfc3339()},
                                Meta = Meta0#{<<"stands">> => [Stand2 | Rest]},
                                case v2_save_set_meta(AdminId, SetId, Meta) of
                                    ok -> json_ok(200, Stand2);
                                    {error, Reason} -> json_error(500, <<"failed_to_update_meta">>, #{<<"reason">> => to_bin(Reason)})
                                end;
                            {error, Msg} ->
                                json_error(400, <<"invalid_patch">>, #{<<"details">> => Msg})
                        end;
                    not_found ->
                        json_error(404, <<"stand_not_found">>, #{<<"standId">> => StandId})
                end;
            {{error, enoent}, _} ->
                json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
            {_, {error, Msg}} ->
                json_error(400, <<"invalid_json">>, #{<<"details">> => Msg})
        end
    end).

handle_v2_delete_stand(Admin, SetId, StandId0) ->
    AdminId = v2_admin_id(Admin),
    StandId = to_bin(StandId0),
    with_v2_set_lock(AdminId, SetId, fun() ->
        case v2_load_set_meta(AdminId, SetId) of
            {ok, Meta0} ->
                Stands0 = maps:get(<<"stands">>, Meta0, []),
                case split_by_id(Stands0, StandId) of
                    {ok, _Stand, Rest} ->
                        Meta = Meta0#{<<"stands">> => Rest},
                        case v2_save_set_meta(AdminId, SetId, Meta) of
                            ok -> json_ok(200, #{<<"deleted">> => true, <<"standId">> => StandId});
                            {error, Reason} -> json_error(500, <<"failed_to_update_meta">>, #{<<"reason">> => to_bin(Reason)})
                        end;
                    not_found ->
                        json_error(404, <<"stand_not_found">>, #{<<"standId">> => StandId})
                end;
            {error, enoent} ->
                json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
            {error, Reason} ->
                json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
        end
    end).

handle_v2_post_share(Admin, SetId) ->
    AdminId = v2_admin_id(Admin),
    with_v2_set_lock(AdminId, SetId, fun() ->
        case v2_load_set_meta(AdminId, SetId) of
            {ok, Meta0} ->
                case maps:get(<<"shareId">>, Meta0, undefined) of
                    S when is_binary(S), byte_size(S) > 0 ->
                        json_ok(200, #{<<"shareId">> => S, <<"shareUrl">> => v2_share_url(binary_to_list(S))});
                    _ ->
                        ShareId = v2_new_share(AdminId, SetId),
                        Meta = Meta0#{<<"shareId">> => to_bin(ShareId)},
                        _ = v2_save_set_meta(AdminId, SetId, Meta),
                        json_ok(201, #{<<"shareId">> => to_bin(ShareId), <<"shareUrl">> => v2_share_url(ShareId)})
                end;
            {error, enoent} ->
                json_error(404, <<"set_not_found">>, #{<<"setId">> => to_bin(SetId)});
            {error, Reason} ->
                json_error(500, <<"failed_to_load_set">>, #{<<"reason">> => to_bin(Reason)})
        end
    end).

handle_v2_get_quiz(ShareId0, A) ->
    Q = query_map(A),
    Mode0 = maps:get(<<"mode">>, Q, <<"rand10">>),
    Mode = normalize_quiz_mode(Mode0),
    case v2_load_share(ShareId0) of
        {ok, #{<<"adminId">> := AdminIdB, <<"setId">> := SetIdB}} ->
            AdminId = binary_to_list(to_bin(AdminIdB)),
            SetId = binary_to_list(to_bin(SetIdB)),
            case v2_load_set_meta(AdminId, SetId) of
                {ok, Meta} ->
                    Stands0 = maps:get(<<"stands">>, Meta, []),
                    seed_rand(),
                    N0 = length(Stands0),
                    Count =
                        case Mode of
                            <<"all">> -> N0;
                            <<"randHalf">> -> (N0 + 1) div 2;
                            <<"rand10">> -> 10;
                            _ -> 10
                        end,
                    Sample = take_n(shuffle(Stands0), Count),
                    VisibleDots = [#{<<"id">> => maps:get(<<"id">>, S),
                                     <<"x">> => maps:get(<<"x">>, S),
                                     <<"y">> => maps:get(<<"y">>, S),
                                     <<"symbol">> => maps:get(<<"symbol">>, S, <<"dot">>)} || S <- Sample],
                    Questions = [#{<<"standId">> => maps:get(<<"id">>, S),
                                   <<"name">> => maps:get(<<"name">>, S)} || S <- Sample],
                    ImageUrl = <<"/api/v2/media/shares/", (to_bin(v2_norm_share_id(ShareId0)))/binary, "/image">>,
                    SetName = get_in(Meta, [<<"set">>, <<"name">>]),
                    json_ok(200, #{
                        <<"mode">> => Mode,
                        <<"set">> => #{<<"id">> => to_bin(SetId), <<"name">> => SetName},
                        <<"imageUrl">> => ImageUrl,
                        <<"visibleStands">> => VisibleDots,
                        <<"questions">> => Questions
                    });
                _ ->
                    json_error(404, <<"set_not_found">>, #{})
            end;
        _ ->
            json_error(404, <<"share_not_found">>, #{})
    end.

handle_v2_get_share_image(ShareId0) ->
    case v2_load_share(ShareId0) of
        {ok, #{<<"adminId">> := AdminIdB, <<"setId">> := SetIdB}} ->
            AdminId = binary_to_list(to_bin(AdminIdB)),
            SetId = binary_to_list(to_bin(SetIdB)),
            case v2_load_set_meta(AdminId, SetId) of
                {ok, Meta} ->
                    case get_in(Meta, [<<"image">>, <<"filename">>]) of
                        undefined -> json_error(404, <<"image_not_found">>, #{});
                        null -> json_error(404, <<"image_not_found">>, #{});
                        <<>> -> json_error(404, <<"image_not_found">>, #{});
                        FilenameBin ->
                            Filename = binary_to_list(FilenameBin),
                            Path = filename:join([v2_set_dir(AdminId, SetId), Filename]),
                            case file:read_file(Path) of
                                {ok, Bin} ->
                                    CT = content_type_from_filename(Filename),
                                    [{status, 200},
                                     {header, {"Content-Type", CT}},
                                     {content, CT, Bin}];
                                {error, enoent} ->
                                    json_error(404, <<"image_not_found">>, #{});
                                {error, Reason} ->
                                    json_error(500, <<"failed_to_read_image">>, #{<<"reason">> => to_bin(Reason)})
                            end
                    end;
                _ ->
                    json_error(404, <<"set_not_found">>, #{})
            end;
        _ ->
            json_error(404, <<"share_not_found">>, #{})
    end.

%%--------------------------------------------------------------------
%% V2 leaderboard (public via shareId)
%%--------------------------------------------------------------------

handle_v2_get_leaderboard(ShareId0, A) ->
    Q = query_map(A),
    Mode0 = maps:get(<<"mode">>, Q, <<"all">>),
    Mode = normalize_quiz_mode(Mode0),
    case v2_load_share(ShareId0) of
        {ok, #{<<"adminId">> := AdminIdB, <<"setId">> := SetIdB}} ->
            AdminId = binary_to_list(to_bin(AdminIdB)),
            SetId = binary_to_list(to_bin(SetIdB)),
            with_v2_set_lock(AdminId, SetId, fun() ->
                case v2_load_leaderboard(AdminId, SetId) of
                    {ok, Items0} ->
                        Items1 = [I || I <- Items0, maps:get(<<"mode">>, I, <<"all">>) =:= Mode],
                        Items = take_n(sort_leaderboard(Items1), 20),
                        json_ok(200, #{<<"mode">> => Mode, <<"items">> => Items});
                    {error, Reason} ->
                        json_error(500, <<"failed_to_load_leaderboard">>, #{<<"reason">> => to_bin(Reason)})
                end
            end);
        _ ->
            json_error(404, <<"share_not_found">>, #{})
    end.

handle_v2_post_leaderboard(ShareId0, A) ->
    case v2_load_share(ShareId0) of
        {ok, #{<<"adminId">> := AdminIdB, <<"setId">> := SetIdB}} ->
            AdminId = binary_to_list(to_bin(AdminIdB)),
            SetId = binary_to_list(to_bin(SetIdB)),
            with_v2_set_lock(AdminId, SetId, fun() ->
                case read_json_body(A) of
                    {ok, Body} ->
                        Name0 = maps:get(<<"name">>, Body, undefined),
                        Score0 = maps:get(<<"score">>, Body, undefined),
                        Mode0 = maps:get(<<"mode">>, Body, <<"all">>),
                        case {validate_nonempty_string(Name0), validate_score(Score0)} of
                            {{ok, Name}, {ok, Score}} ->
                                Mode = normalize_quiz_mode(Mode0),
                                Now = now_rfc3339(),
                                Item = #{
                                    <<"name">> => Name,
                                    <<"score">> => Score,
                                    <<"mode">> => Mode,
                                    <<"createdAt">> => Now
                                },
                                Items0 =
                                    case v2_load_leaderboard(AdminId, SetId) of
                                        {ok, L} when is_list(L) -> L;
                                        _ -> []
                                    end,
                                Items1 = [Item | Items0],
                                Items2 = take_n(sort_leaderboard(Items1), 200),
                                case v2_save_leaderboard(AdminId, SetId, Items2) of
                                    ok ->
                                        Top = take_n([I || I <- Items2, maps:get(<<"mode">>, I, <<"all">>) =:= Mode], 20),
                                        json_ok(201, #{<<"saved">> => true, <<"mode">> => Mode, <<"items">> => Top});
                                    {error, Reason} ->
                                        json_error(500, <<"failed_to_save_leaderboard">>, #{<<"reason">> => to_bin(Reason)})
                                end;
                            {{error, Msg}, _} ->
                                json_error(400, <<"invalid_name">>, #{<<"details">> => Msg});
                            {_, {error, Msg}} ->
                                json_error(400, <<"invalid_score">>, #{<<"details">> => Msg})
                        end;
                    {error, Msg} ->
                        json_error(400, <<"invalid_json">>, #{<<"details">> => Msg})
                end
            end);
        _ ->
            json_error(404, <<"share_not_found">>, #{})
    end.

v2_save_set_meta(AdminId, SetId, Meta) ->
    Path = v2_set_meta_path(AdminId, SetId),
    ok = filelib:ensure_dir(Path),
    write_json_atomic(Path, Meta).

v2_load_set_meta(AdminId, SetId) ->
    Path = v2_set_meta_path(AdminId, SetId),
    case file:read_file(Path) of
        {ok, Bin} ->
            try {ok, json_decode(Bin)} catch _:_ -> {error, invalid_json} end;
        {error, Reason} ->
            {error, Reason}
    end.

v2_load_leaderboard(AdminId, SetId) ->
    Path = v2_leaderboard_path(AdminId, SetId),
    case file:read_file(Path) of
        {ok, Bin} ->
            try {ok, json_decode(Bin)} catch _:_ -> {ok, []} end;
        {error, enoent} ->
            {ok, []};
        {error, Reason} ->
            {error, Reason}
    end.

v2_save_leaderboard(AdminId, SetId, Items) ->
    Path = v2_leaderboard_path(AdminId, SetId),
    ok = filelib:ensure_dir(Path),
    write_json_atomic(Path, Items).

v2_norm_share_id(ShareId0) ->
    case ShareId0 of
        B when is_binary(B) -> B;
        L when is_list(L) -> list_to_binary(L);
        _ -> <<>>
    end.

v2_share_url(ShareId) when is_list(ShareId) ->
    %% Hash-routing så Yaws inte behöver special-casing
    <<"/v2/#/quiz/", (to_bin(ShareId))/binary>>;
v2_share_url(ShareId) when is_binary(ShareId) ->
    v2_share_url(binary_to_list(ShareId)).

v2_new_share(AdminId, SetId) ->
    Tok = base64url_encode(crypto:strong_rand_bytes(18)),
    Share = #{<<"adminId">> => to_bin(AdminId), <<"setId">> => to_bin(SetId), <<"createdAt">> => now_rfc3339()},
    Path = v2_share_path(Tok),
    ok = filelib:ensure_dir(Path),
    ok = write_json_atomic(Path, Share),
    Tok.

v2_load_share(ShareId0) ->
    ShareId = case ShareId0 of
                  B when is_binary(B) -> binary_to_list(B);
                  L when is_list(L) -> L;
                  _ -> ""
              end,
    Path = v2_share_path(ShareId),
    case file:read_file(Path) of
        {ok, Bin} ->
            try {ok, json_decode(Bin)} catch _:_ -> {error, invalid_json} end;
        {error, enoent} ->
            {error, enoent};
        {error, Reason} ->
            {error, Reason}
    end.

check_admin_auth(A) ->
    AdminUser = getenv_default("JAKTPASS_ADMIN_USER", "admin"),
    AdminPass = getenv_default("JAKTPASS_ADMIN_PASS", "admin"),
    case get_basic_auth(A#arg.headers) of
        {ok, {User, Pass}} when User =:= AdminUser, Pass =:= AdminPass ->
            ok;
        _ ->
            {error, unauthorized()}
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

%% Yaws kan redan ha parsat Basic Auth till ett tuple-fält:
%%   #headers.authorization = {User, Pass, RawHeader}
%% I andra fall kan authorization vara en sträng ("Basic ...") eller saknas.
get_basic_auth(H) when is_record(H, headers) ->
    case H#headers.authorization of
        {User, Pass, _Raw} when is_list(User), is_list(Pass) ->
            {ok, {User, Pass}};
        {User, Pass} when is_list(User), is_list(Pass) ->
            {ok, {User, Pass}};
        undefined ->
            %% Fallback: leta i "other" efter Authorization-headern
            case find_other_header_value("authorization", H#headers.other) of
                undefined -> error;
                Val -> parse_basic_auth(Val)
            end;
        Val ->
            %% Kan vara "Basic ...."
            parse_basic_auth(Val)
    end;
get_basic_auth(_Other) ->
    error.

find_other_header_value(_NameLower, []) ->
    undefined;
find_other_header_value(NameLower, [{http_header, _I, Name, _Reserved, Val} | Rest]) ->
    case string:lowercase(header_name_to_list(Name)) of
        NameLower -> Val;
        _ -> find_other_header_value(NameLower, Rest)
    end;
find_other_header_value(NameLower, [_ | Rest]) ->
    find_other_header_value(NameLower, Rest).

header_name_to_list(N) when is_atom(N) -> atom_to_list(N);
header_name_to_list(N) when is_list(N) -> N;
header_name_to_list(N) when is_binary(N) -> binary_to_list(N);
header_name_to_list(_) -> "".

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

leaderboard_path(SetId) ->
    filename:join([set_dir(SetId), "leaderboard.json"]).

%% V2 paths (multi-admin, separat från v1)
v2_dir() ->
    filename:join([data_dir(), "v2"]).

v2_admins_dir() ->
    filename:join([v2_dir(), "admins"]).

v2_admin_dir(AdminId) ->
    filename:join([v2_admins_dir(), AdminId]).

v2_admin_path(AdminId) ->
    filename:join([v2_admin_dir(AdminId), "admin.json"]).

v2_admin_sets_dir(AdminId) ->
    filename:join([v2_admin_dir(AdminId), "sets"]).

v2_set_dir(AdminId, SetId) ->
    filename:join([v2_admin_sets_dir(AdminId), SetId]).

v2_set_meta_path(AdminId, SetId) ->
    filename:join([v2_set_dir(AdminId, SetId), "meta.json"]).

v2_leaderboard_path(AdminId, SetId) ->
    filename:join([v2_set_dir(AdminId, SetId), "leaderboard.json"]).

v2_sessions_dir() ->
    filename:join([v2_dir(), "sessions"]).

v2_session_path(Token) ->
    filename:join([v2_sessions_dir(), Token ++ ".json"]).

v2_shares_dir() ->
    filename:join([v2_dir(), "shares"]).

v2_share_path(ShareId) ->
    filename:join([v2_shares_dir(), ShareId ++ ".json"]).

v2_index_path() ->
    filename:join([v2_dir(), "admin_index.json"]).

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

load_leaderboard(SetId) ->
    Path = leaderboard_path(SetId),
    case file:read_file(Path) of
        {ok, Bin} ->
            try
                {ok, json_decode(Bin)}
            catch _:_ ->
                {ok, []}
            end;
        {error, enoent} ->
            {ok, []};
        {error, Reason} ->
            {error, Reason}
    end.

save_leaderboard(SetId, Items) ->
    Path = leaderboard_path(SetId),
    ok = filelib:ensure_dir(Path),
    write_json_atomic(Path, Items).

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
    %% Egen multipart-parser för kompatibilitet mellan Yaws-versioner.
    %% Läser hela body som binär och plockar ut fältet "file".
    CT0 = header_value(A#arg.headers, "content-type"),
    multipart_dbg("content-type=~p", [CT0]),
    multipart_dbg("clidata_bytes=~p clidata_tag=~p cont=~p state_tag=~p", [
        clidata_bytes(A#arg.clidata),
        clidata_tag(A#arg.clidata),
        A#arg.cont,
        state_tag(A#arg.state)
    ]),

    %% Försök först med Yaws inbyggda multipart-parser (om den finns).
    %% OBS: Den kan returnera continuation: {cont, Cont, Res} och kräver {get_more, Cont, State}.
    case erlang:function_exported(yaws_api, parse_multipart_post, 1) of
        true ->
            case yaws_api:parse_multipart_post(A) of
                [] ->
                    {error, <<"broken_post">>};
                {cont, Cont, Res} ->
                    P0 = case A#arg.state of
                             S when is_record(S, mp_state) -> S;
                             _ -> #mp_state{}
                         end,
                    New = P0#mp_state{count = P0#mp_state.count + 1,
                                      acc = P0#mp_state.acc ++ Res},
                    multipart_dbg("yaws cont count=~p parts=~p", [New#mp_state.count, length(New#mp_state.acc)]),
                    {get_more, Cont, New};
                {result, Res} ->
                    P0 = case A#arg.state of
                             S when is_record(S, mp_state) -> S;
                             _ -> #mp_state{}
                         end,
                    Parts = P0#mp_state.acc ++ Res,
                    multipart_dbg("yaws result parts=~p keys=~p", [length(Parts), summarize_part_keys(Parts, 12)]),
                    case pick_file_part_yaws(Parts, FieldName) of
                        {ok, File = #{filename := FN, data := Data}} ->
                            multipart_dbg("yaws found file filename=~p bytes=~p", [FN, byte_size(Data)]),
                            {ok, File};
                        _ ->
                            multipart_dbg("yaws missing file field want=~p keys=~p", [FieldName, summarize_part_keys(Parts, 12)]),
                            {error, <<"missing_file_field">>}
                    end;
                Parts when is_list(Parts) ->
                    multipart_dbg("yaws parts(list) parts=~p keys=~p", [length(Parts), summarize_part_keys(Parts, 12)]),
                    case pick_file_part_yaws(Parts, FieldName) of
                        {ok, File = #{filename := FN, data := Data}} ->
                            multipart_dbg("yaws found file filename=~p bytes=~p", [FN, byte_size(Data)]),
                            {ok, File};
                        _ ->
                            multipart_dbg("yaws missing file field want=~p keys=~p", [FieldName, summarize_part_keys(Parts, 12)]),
                            {error, <<"missing_file_field">>}
                    end;
                Other ->
                    multipart_dbg("yaws_api:parse_multipart_post unexpected=~p", [Other]),
                    parse_multipart_file_manual(A, FieldName, CT0)
            end;
        false ->
            parse_multipart_file_manual(A, FieldName, CT0)
    end.

parse_multipart_file_manual(A, FieldName, CT0) ->
    case multipart_boundary(CT0) of
        {ok, Boundary} ->
            multipart_dbg("boundary=~p", [Boundary]),
            case recv_body_bin(A) of
                {ok, Bin} ->
                    multipart_dbg("body bytes=~p first32=~p", [byte_size(Bin), binary:part(Bin, 0, erlang:min(32, byte_size(Bin)))]),
                    case multipart_find_file(Bin, Boundary, FieldName) of
                        {ok, Filename, Data} ->
                            multipart_dbg("found file field=~p filename=~p bytes=~p", [FieldName, Filename, byte_size(Data)]),
                            {ok, #{filename => Filename, data => Data}};
                        {error, Reason} ->
                            multipart_dbg("missing file field=~p reason=~p", [FieldName, Reason]),
                            {error, Reason}
                    end;
                {error, Msg} ->
                    {error, Msg}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

pick_file_part_yaws(Parts, FieldName) when is_list(Parts) ->
    %% Yaws kan returnera antingen:
    %% 1) "Färdiga" parts: {file, {Filename, CT, Bin}}
    %% 2) En event-ström: {head, ...}, {part_body, ...}, ...
    case Parts of
        [{head, _} | _] ->
            multipart_dbg("yaws multipart mode=events (starts with head)", []),
            pick_file_part_yaws_events(Parts, FieldName);
        [{part_body, _} | _] ->
            multipart_dbg("yaws multipart mode=events (starts with part_body)", []),
            pick_file_part_yaws_events(Parts, FieldName);
        _ -> pick_file_part_yaws_kv(Parts, FieldName)
    end.

pick_file_part_yaws_kv([], _FieldName) ->
    {error, missing};
pick_file_part_yaws_kv([P | Rest], FieldName) ->
    Want = normalize_field_name(FieldName),
    case P of
        {K, V} ->
            case normalize_field_name(K) =:= Want of
                true ->
                    case V of
                        {Filename, _CT, Body0} ->
                            case yaws_body_bin(Body0) of
                                {ok, Body} -> {ok, #{filename => Filename, data => Body}};
                                error -> pick_file_part_yaws_kv(Rest, FieldName)
                            end;
                        {Filename, _CT, _Charset, Body0} ->
                            case yaws_body_bin(Body0) of
                                {ok, Body} -> {ok, #{filename => Filename, data => Body}};
                                error -> pick_file_part_yaws_kv(Rest, FieldName)
                            end;
                        _ ->
                            pick_file_part_yaws_kv(Rest, FieldName)
                    end;
                false ->
                    pick_file_part_yaws_kv(Rest, FieldName)
            end;
        _ ->
            pick_file_part_yaws_kv(Rest, FieldName)
    end.

pick_file_part_yaws_events(Events, FieldName) ->
    %% Tolkning av event-ström från yaws_api:parse_multipart_post/1 (Yaws 2.0.8).
    %% Vi letar efter en part där Content-Disposition har name="file" och samlar part_body tills nästa head.
    pick_file_part_yaws_events(Events, FieldName, false, "upload.bin", []).

pick_file_part_yaws_events([], _FieldName, true, Filename, BodyAcc) ->
    %% EOF medan vi samlar: returnera det vi har.
    {ok, #{filename => Filename, data => iolist_to_binary(lists:reverse(BodyAcc))}};
pick_file_part_yaws_events([], _FieldName, false, _Filename, _BodyAcc) ->
    {error, missing};
pick_file_part_yaws_events([{head, Head0} | Rest], FieldName, Collecting, Filename, BodyAcc) ->
    %% Ny head -> om vi redan samlade så är förra parten klar.
    case Collecting of
        true ->
            {ok, #{filename => Filename, data => iolist_to_binary(lists:reverse(BodyAcc))}};
        false ->
            Hdrs = yaws_head_to_hdrmap(Head0),
            multipart_dbg("yaws head keys=~p cd=~p", [
                maps:keys(Hdrs),
                maps:get("content-disposition", Hdrs, undefined)
            ]),
            case part_is_field(Hdrs, FieldName) of
                {true, FN} ->
                    multipart_dbg("yaws head matched via content-disposition field=~p filename=~p", [FieldName, FN]),
                    pick_file_part_yaws_events(Rest, FieldName, true, FN, []);
                false ->
                    %% Yaws 2.0.8 kan ge head som redan associerar fältnamnet direkt (t.ex. key="file")
                    Want = normalize_field_name(FieldName),
                    PN = maps:get("__yaws_part_name", Hdrs, undefined),
                    V = maps:get(Want, Hdrs, undefined),
                    case {PN, V} of
                        {PN1, _} when is_list(PN1) ->
                            case normalize_field_name(PN1) =:= Want of
                                true ->
                                    FN0 = yaws_filename_from_hdrs(Hdrs),
                                    multipart_dbg("yaws head matched via __yaws_part_name field=~p filename=~p", [FieldName, FN0]),
                                    pick_file_part_yaws_events(Rest, FieldName, true, FN0, []);
                                false ->
                                    pick_file_part_yaws_events_match_head_value(Rest, FieldName, Head0, V)
                            end;
                        _ ->
                            pick_file_part_yaws_events_match_head_value(Rest, FieldName, Head0, V)
                    end
            end
    end;
pick_file_part_yaws_events([{part_body, Chunk0} | Rest], FieldName, Collecting, Filename, BodyAcc) ->
    case Collecting of
        true ->
            %% Chunk kan vara bin eller list/iodata
            pick_file_part_yaws_events(Rest, FieldName, true, Filename, [Chunk0 | BodyAcc]);
        false ->
            pick_file_part_yaws_events(Rest, FieldName, false, Filename, BodyAcc)
    end;
pick_file_part_yaws_events([{body, Chunk0} | Rest], FieldName, Collecting, Filename, BodyAcc) ->
    %% Vissa Yaws-varianter använder 'body' som sista chunk istället för 'part_body'
    pick_file_part_yaws_events([{part_body, Chunk0} | Rest], FieldName, Collecting, Filename, BodyAcc);
pick_file_part_yaws_events([_Other | Rest], FieldName, Collecting, Filename, BodyAcc) ->
    pick_file_part_yaws_events(Rest, FieldName, Collecting, Filename, BodyAcc).

pick_file_part_yaws_events_match_head_value(Rest, FieldName, Head0, V) ->
    case V =/= undefined of
        true ->
            %% Gissa filnamn från head-värdet (om möjligt), annars fall back.
            FN2 = yaws_guess_filename(V),
            multipart_dbg("yaws head matched via head-key field=~p filename=~p", [FieldName, FN2]),
            pick_file_part_yaws_events(Rest, FieldName, true, FN2, []);
        false ->
            multipart_dbg("yaws head did not match field=~p raw=~p", [FieldName, Head0]),
            pick_file_part_yaws_events(Rest, FieldName, false, "upload.bin", [])
    end.

yaws_head_to_hdrmap(H) when is_binary(H) ->
    %% Kan vara rå header-block som binär
    parse_part_headers(binary_to_list(H));
yaws_head_to_hdrmap(H) when is_list(H) ->
    case H of
        [] -> #{};
        [I | _] when is_integer(I) ->
            %% Charlist header-block
            parse_part_headers(H);
        _ ->
            %% Lista med header-tupler (eller http_header-tupler)
            lists:foldl(
              fun(E, Acc) ->
                  case E of
                      {http_header, _I, Name, _Reserved, Val} ->
                          Acc#{normalize_header_name(Name) => string:trim(v_to_list(Val))};
                      {K, V} ->
                          Acc#{normalize_header_name(K) => string:trim(v_to_list(V))};
                      _ ->
                          Acc
                  end
              end,
              #{},
              H)
    end;
yaws_head_to_hdrmap({Name, Hdrs}) ->
    %% Ibland är head = {FieldName, Headers}
    M = yaws_head_to_hdrmap(Hdrs),
    M#{"__yaws_part_name" => v_to_list(Name)};
yaws_head_to_hdrmap(_Other) ->
    #{}.

yaws_guess_filename(V) ->
    %% Försök plocka ut filename om head innehåller mer än bara ett markeringsvärde.
    case V of
        {Filename, _CT} -> v_to_list(Filename);
        {Filename, _CT, _} -> v_to_list(Filename);
        {Filename, _CT, _, _} -> v_to_list(Filename);
        Filename when is_binary(Filename); is_list(Filename); is_atom(Filename) ->
            v_to_list(Filename);
        _ ->
            "upload.bin"
    end.

yaws_filename_from_hdrs(Hdrs) when is_map(Hdrs) ->
    %% Yaws 2.0.8 event-head kan innehålla filename/name/content-type som redan-parsade fält.
    FN0 = maps:get("filename", Hdrs, ""),
    FN = case FN0 of
             B when is_binary(B) -> binary_to_list(B);
             L when is_list(L) -> L;
             A when is_atom(A) -> atom_to_list(A);
             _ -> ""
         end,
    case string:trim(FN) of
        "" -> "upload.bin";
        S -> S
    end;
yaws_filename_from_hdrs(_Other) ->
    "upload.bin".

v_to_list(B) when is_binary(B) -> binary_to_list(B);
v_to_list(L) when is_list(L) -> L;
v_to_list(A) when is_atom(A) -> atom_to_list(A);
v_to_list(I) when is_integer(I) -> integer_to_list(I);
v_to_list(T) -> io_lib:format("~p", [T]).

normalize_header_name(V) ->
    %% Normalisera headernamn till "content-disposition" (små bokstäver, '_' -> '-')
    S0 = string:lowercase(string:trim(v_to_list(V))),
    [case C of $_ -> $-; _ -> C end || C <- S0].

normalize_field_name(V) when is_atom(V) ->
    normalize_field_name(atom_to_list(V));
normalize_field_name(V) when is_binary(V) ->
    normalize_field_name(binary_to_list(V));
normalize_field_name(V) when is_list(V) ->
    string:to_lower(V);
normalize_field_name(_Other) ->
    "".

yaws_body_bin(B) when is_binary(B) ->
    {ok, B};
yaws_body_bin(L) when is_list(L) ->
    %% Yaws kan ge file-data som iolist/lista beroende på version/konfig.
    try {ok, iolist_to_binary(L)} catch _:_ -> error end;
yaws_body_bin(_Other) ->
    error.

summarize_part_keys(Parts, Limit) ->
    %% Returnera en kort lista av fältnamn/nycklar för debug (utan att dumpa data).
    summarize_part_keys(Parts, Limit, []).

summarize_part_keys(_Parts, 0, Acc) ->
    lists:reverse(Acc);
summarize_part_keys([], _Limit, Acc) ->
    lists:reverse(Acc);
summarize_part_keys([P | Rest], Limit, Acc) ->
    K =
        case P of
            {Key0, _V} -> normalize_field_name(Key0);
            _ -> "?"
        end,
    summarize_part_keys(Rest, Limit - 1, [K | Acc]).

clidata_tag(B) when is_binary(B) -> binary;
clidata_tag({partial, _}) -> partial;
clidata_tag({file, _}) -> file;
clidata_tag({file, _, _}) -> file;
clidata_tag({tmpfile, _}) -> tmpfile;
clidata_tag(undefined) -> undefined;
clidata_tag(_) -> other.

clidata_bytes(B) when is_binary(B) -> byte_size(B);
clidata_bytes({partial, D}) when is_binary(D) -> byte_size(D);
clidata_bytes({file, _Path}) -> -1;
clidata_bytes({file, _Path, Len}) when is_integer(Len) -> Len;
clidata_bytes({tmpfile, _Path}) -> -1;
clidata_bytes(_) -> 0.

state_tag(S) when is_record(S, mp_state) -> mp_state;
state_tag(undefined) -> undefined;
state_tag(_) -> other.

header_value(H, NameLower) when is_record(H, headers) ->
    %% Försök först via recordfält
    case NameLower of
        "content-type" ->
            case H#headers.content_type of
                undefined -> header_other_value(NameLower, H#headers.other);
                V -> V
            end;
        _ ->
            header_other_value(NameLower, H#headers.other)
    end;
header_value(_, _NameLower) ->
    undefined.

header_other_value(_NameLower, []) ->
    undefined;
header_other_value(NameLower, [{http_header, _I, Name, _Reserved, Val} | Rest]) ->
    case string:lowercase(header_name_to_list(Name)) of
        NameLower -> Val;
        _ -> header_other_value(NameLower, Rest)
    end;
header_other_value(NameLower, [_ | Rest]) ->
    header_other_value(NameLower, Rest).

multipart_boundary(undefined) ->
    {error, <<"missing_content_type">>};
multipart_boundary(CT0) ->
    CT = case CT0 of
             B when is_binary(B) -> binary_to_list(B);
             L when is_list(L) -> L;
             _ -> ""
         end,
    %% Ex: multipart/form-data; boundary=----WebKitFormBoundary...
    case re:run(CT, "boundary=([^;\\s]+)", [{capture, [1], list}]) of
        {match, [B0]} ->
            %% OTP22-safe: boundary kan ibland vara "...." (med citationstecken)
            B1 = strip_dquotes(B0),
            {ok, B1};
        _ ->
            {error, <<"invalid_multipart_content_type">>}
    end.

strip_dquotes(S) when is_list(S) ->
    case S of
        [$\" | _] ->
            case lists:reverse(S) of
                [$\" | RevRest] -> lists:reverse(RevRest);
                _ -> S
            end;
        _ ->
            S
    end;
strip_dquotes(B) when is_binary(B) ->
    strip_dquotes(binary_to_list(B));
strip_dquotes(Other) ->
    to_bin(Other).

multipart_find_file(Bin, Boundary, FieldName) when is_binary(Bin), is_list(Boundary) ->
    Delim = list_to_binary(["--", Boundary]),
    Parts0 = binary:split(Bin, Delim, [global]),
    Parts = [P || P <- Parts0, P =/= <<>>, P =/= <<"--">>, P =/= <<"\r\n">>],
    multipart_dbg("parts0=~p parts=~p", [length(Parts0), length(Parts)]),
    multipart_find_file_parts(Parts, FieldName).

multipart_find_file_parts([], _FieldName) ->
    {error, <<"missing_file_field">>};
multipart_find_file_parts([Chunk0 | Rest], FieldName) ->
    Chunk1 = strip_crlf(Chunk0),
    case binary:split(Chunk1, <<"\r\n\r\n">>, []) of
        [HdrBin, Body0] ->
            Body = strip_trailing_crlf(Body0),
            Headers = parse_part_headers(binary_to_list(HdrBin)),
            case maps:get("content-disposition", Headers, undefined) of
                undefined -> multipart_dbg("part headers keys=~p (no content-disposition)", [maps:keys(Headers)]);
                CD -> multipart_dbg("content-disposition=~s", [CD])
            end,
            case part_is_field(Headers, FieldName) of
                {true, Filename} ->
                    {ok, Filename, Body};
                false ->
                    multipart_find_file_parts(Rest, FieldName)
            end;
        _ ->
            multipart_find_file_parts(Rest, FieldName)
    end.

strip_crlf(<<"\r\n", Rest/binary>>) -> Rest;
strip_crlf(B) -> B.

strip_trailing_crlf(Bin) ->
    Sz = byte_size(Bin),
    case Sz >= 2 andalso binary:part(Bin, Sz - 2, 2) =:= <<"\r\n">> of
        true -> binary:part(Bin, 0, Sz - 2);
        false -> Bin
    end.

parse_part_headers(Str) ->
    %% return map lower-name -> value
    Lines = string:tokens(Str, "\r\n"),
    lists:foldl(
      fun(Line, Acc) ->
          case string:tokens(Line, ":") of
              [K | Vs] ->
                  V = string:trim(string:join(Vs, ":")),
                  Acc#{string:lowercase(string:trim(K)) => V};
              _ ->
                  Acc
          end
      end, #{}, Lines).

part_is_field(Hdrs, FieldName) ->
    case maps:get("content-disposition", Hdrs, undefined) of
        undefined -> false;
        CD ->
            %% Ex: form-data; name="file"; filename="x.png"
            Name = normalize_fieldname(multipart_cd_param(CD, "name")),
            Want = normalize_fieldname(FieldName),
            case Name =:= Want of
                true ->
                    Filename0 = multipart_cd_param(CD, "filename"),
                    Filename = case Filename0 of "" -> "upload.bin"; _ -> Filename0 end,
                    {true, Filename};
                false ->
                    false
            end
    end.

normalize_fieldname(undefined) -> "";
normalize_fieldname(B) when is_binary(B) -> normalize_fieldname(binary_to_list(B));
normalize_fieldname(L) when is_list(L) -> string:lowercase(string:trim(L));
normalize_fieldname(_) -> "".

multipart_cd_param(CD0, Key) ->
    CD = case CD0 of
             B when is_binary(B) -> binary_to_list(B);
             L when is_list(L) -> L
         end,
    %% Robust (OTP22): parsa Content-Disposition som key=value-parametrar
    %% Ex: form-data; name="file"; filename="x.jpg"
    KeyLower = string:lowercase(Key),
    Params = parse_cd_params(CD),
    maps:get(KeyLower, Params, "").

parse_cd_params(CD0) ->
    CD = case CD0 of
             B when is_binary(B) -> binary_to_list(B);
             L when is_list(L) -> L
         end,
    Parts = [string:trim(P) || P <- string:tokens(CD, ";")],
    lists:foldl(
      fun(P, Acc) ->
          case string:chr(P, $=) of
              0 ->
                  Acc;
              _ ->
                  case string:tokens(P, "=") of
                      [K | Vs] ->
                          V0 = string:trim(string:join(Vs, "=")),
                          V1 = strip_dquotes(V0),
                          Acc#{string:lowercase(string:trim(K)) => V1};
                      _ ->
                          Acc
                  end
          end
      end,
      #{},
      Parts).

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
                V = json_decode(Bin),
                case is_map(V) of
                    true -> {ok, V};
                    false -> {error, <<"expected_json_object">>}
                end
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
                %% Yaws kan ha lagt body (helt eller delvis) i clidata eller via cont (continuation).
                case A#arg.clidata of
                    {file, Path} ->
                        file:read_file(path_to_list(Path));
                    {file, Path, _Len} ->
                        file:read_file(path_to_list(Path));
                    {tmpfile, Path} ->
                        file:read_file(path_to_list(Path));
                    B when is_binary(B), byte_size(B) > 0 ->
                        {ok, B};
                    L when is_list(L), length(L) > 0 ->
                        {ok, list_to_binary(L)};
                    _ ->
                        case A#arg.cont of
                            undefined -> recv_body_loop(A, []);
                            Cont -> recv_body_loop(Cont, [])
                        end
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

path_to_list(B) when is_binary(B) -> binary_to_list(B);
path_to_list(L) when is_list(L) -> L;
path_to_list(T) -> io_lib:format("~s", [T]).

recv_body_loop(ArgOrCont, Acc) ->
    case yaws_api:recv_body(ArgOrCont) of
        {ok, B} when is_binary(B) ->
            {ok, iolist_to_binary(lists:reverse([B | Acc]))};
        {ok, L} when is_list(L) ->
            {ok, iolist_to_binary(lists:reverse([list_to_binary(L) | Acc]))};
        {cont, Next, B} when is_binary(B) ->
            recv_body_loop(Next, [B | Acc]);
        {cont, Next, L} when is_list(L) ->
            recv_body_loop(Next, [list_to_binary(L) | Acc]);
        %% Vissa Yaws-versioner kan returnera extra metadata i cont-tuple.
        {cont, Next, B, _} when is_binary(B) ->
            recv_body_loop(Next, [B | Acc]);
        {cont, Next, _Len, B} when is_integer(_Len), is_binary(B) ->
            recv_body_loop(Next, [B | Acc]);
        {cont, Next} ->
            recv_body_loop(Next, Acc);
        B when is_binary(B) ->
            {ok, iolist_to_binary(lists:reverse([B | Acc]))};
        L when is_list(L) ->
            {ok, iolist_to_binary(lists:reverse([list_to_binary(L) | Acc]))};
        _ ->
            {ok, iolist_to_binary(lists:reverse(Acc))}
    end.

multipart_dbg(Fmt, Args) ->
    case getenv_default("JAKTPASS_DEBUG_MULTIPART", "false") of
        "1" -> error_logger:info_msg("jaktpass multipart: " ++ Fmt ++ "~n", Args);
        "true" -> error_logger:info_msg("jaktpass multipart: " ++ Fmt ++ "~n", Args);
        "yes" -> error_logger:info_msg("jaktpass multipart: " ++ Fmt ++ "~n", Args);
        _ -> ok
    end.

v2_auth_dbg(Fmt, Args) ->
    case getenv_default("JAKTPASS_DEBUG_V2_AUTH", "false") of
        "1" -> error_logger:info_msg("jaktpass v2 auth: " ++ Fmt ++ "~n", Args);
        "true" -> error_logger:info_msg("jaktpass v2 auth: " ++ Fmt ++ "~n", Args);
        "yes" -> error_logger:info_msg("jaktpass v2 auth: " ++ Fmt ++ "~n", Args);
        _ -> ok
    end.

type_tag(V) when is_binary(V) -> binary;
type_tag(V) when is_list(V) -> list;
type_tag(V) when is_atom(V) -> atom;
type_tag(V) when is_integer(V) -> integer;
type_tag(V) when is_map(V) -> map;
type_tag(_) -> other.

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

validate_player_name(undefined) -> {error, <<"missing">>};
validate_player_name(null) -> {error, <<"missing">>};
validate_player_name(B) when is_binary(B) ->
    Name = bin_trim(B),
    case Name of
        <<>> -> {error, <<"empty">>};
        _ ->
            %% max 32 tecken
            case byte_size(Name) =< 64 of
                true -> {ok, Name};
                false -> {error, <<"too_long">>}
            end
    end;
validate_player_name(L) when is_list(L) ->
    validate_player_name(list_to_binary(L));
validate_player_name(_) ->
    {error, <<"invalid_type">>}.

validate_score(S) when is_integer(S) ->
    if S >= 0, S =< 100 -> {ok, S}; true -> {error, <<"out_of_range">>} end;
validate_score(B) when is_binary(B) ->
    case catch binary_to_integer(B) of
        I when is_integer(I) -> validate_score(I);
        _ -> {error, <<"invalid_number">>}
    end;
validate_score(L) when is_list(L) ->
    validate_score(list_to_binary(L));
validate_score(_) ->
    {error, <<"invalid_type">>}.

normalize_quiz_mode(<<"rand10">>) -> <<"rand10">>;
normalize_quiz_mode(<<"randHalf">>) -> <<"randHalf">>;
normalize_quiz_mode(<<"all">>) -> <<"all">>;
normalize_quiz_mode(<<"half">>) -> <<"randHalf">>;
normalize_quiz_mode(<<"rand">>) -> <<"rand10">>;
normalize_quiz_mode(B) when is_binary(B) -> normalize_quiz_mode(bin_trim(B));
normalize_quiz_mode(L) when is_list(L) -> normalize_quiz_mode(list_to_binary(L));
normalize_quiz_mode(_) -> <<"all">>.

%% Stand symbol (UI-shape). Default: "dot"
validate_symbol(undefined) -> {ok, <<"dot">>};
validate_symbol(null) -> {ok, <<"dot">>};
validate_symbol(<<>>) -> {ok, <<"dot">>};
validate_symbol(B) when is_binary(B) ->
    validate_symbol(bin_trim(B), B);
validate_symbol(L) when is_list(L) ->
    validate_symbol(list_to_binary(L));
validate_symbol(_) ->
    {error, <<"invalid_symbol">>}.

validate_symbol(Bin0, _Orig) ->
    Bin = bin_trim(Bin0),
    case Bin of
        <<"dot">> -> {ok, <<"dot">>};
        <<"circle">> -> {ok, <<"dot">>}; %% alias
        <<"square">> -> {ok, <<"square">>};
        <<"triangle">> -> {ok, <<"triangle">>};
        <<"cross">> -> {ok, <<"cross">>};
        <<"star">> -> {ok, <<"star">>};
        _ -> {error, <<"invalid_symbol">>}
    end.

sort_leaderboard(Items) ->
    %% Högre score först, sedan nyast först.
    lists:sort(
      fun(A, B) ->
          SA = maps:get(<<"score">>, A, 0),
          SB = maps:get(<<"score">>, B, 0),
          case SA =:= SB of
              true ->
                  maps:get(<<"createdAt">>, A, <<>>) >= maps:get(<<"createdAt">>, B, <<>>);
              false ->
                  SA > SB
          end
      end,
      Items).

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

%%====================================================================
%% V2 storage/auth helpers
%%====================================================================

v2_with_lock(Fun) ->
    global:trans({jaktpass_v2, lock}, Fun, [node()], 30000).

v2_index_load() ->
    Path = v2_index_path(),
    case file:read_file(Path) of
        {ok, Bin} ->
            try
                V = json_decode(Bin),
                case is_map(V) of true -> {ok, V}; false -> {ok, #{}} end
            catch _:_ ->
                {ok, #{}}
            end;
        {error, enoent} ->
            {ok, #{}};
        {error, Reason} ->
            {error, Reason}
    end.

v2_index_save(Map) ->
    Path = v2_index_path(),
    ok = filelib:ensure_dir(Path),
    write_json_atomic(Path, Map).

v2_index_put_email(EmailBin, AdminId0) ->
    AdminId = to_bin(AdminId0),
    {ok, M0} = v2_index_load(),
    M1 = M0#{EmailBin => AdminId},
    v2_index_save(M1).

v2_lookup_admin_by_email(EmailBin) ->
    case v2_index_load() of
        {ok, M} ->
            case maps:get(EmailBin, M, undefined) of
                undefined -> not_found;
                V -> {ok, binary_to_list(to_bin(V))}
            end;
        _ ->
            not_found
    end.

v2_save_admin(AdminId0, Admin) ->
    AdminId = to_bin(AdminId0),
    Path = v2_admin_path(binary_to_list(AdminId)),
    ok = filelib:ensure_dir(Path),
    write_json_atomic(Path, Admin).

v2_load_admin(AdminId0) ->
    AdminId = to_bin(AdminId0),
    Path = v2_admin_path(binary_to_list(AdminId)),
    case file:read_file(Path) of
        {ok, Bin} ->
            try {ok, json_decode(Bin)} catch _:_ -> {error, invalid_json} end;
        {error, Reason} ->
            {error, Reason}
    end.

v2_admin_public(Admin) ->
    #{<<"id">> => maps:get(<<"id">>, Admin, null),
      <<"email">> => maps:get(<<"email">>, Admin, null),
      <<"createdAt">> => maps:get(<<"createdAt">>, Admin, null)}.

validate_email(undefined) -> {error, <<"missing">>};
validate_email(null) -> {error, <<"missing">>};
validate_email(B) when is_binary(B) ->
    E = bin_trim(B),
    case re:run(binary_to_list(E), "^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", [{capture, none}]) of
        match -> {ok, E};
        nomatch -> {error, <<"invalid_format">>}
    end;
validate_email(L) when is_list(L) ->
    validate_email(list_to_binary(L));
validate_email(_) ->
    {error, <<"invalid_type">>}.

validate_password(undefined) -> {error, <<"missing">>};
validate_password(null) -> {error, <<"missing">>};
validate_password(B) when is_binary(B) ->
    P = bin_trim(B),
    case byte_size(P) >= 8 of
        true -> {ok, P};
        false -> {error, <<"too_short">>}
    end;
validate_password(L) when is_list(L) ->
    validate_password(list_to_binary(L));
validate_password(_) ->
    {error, <<"invalid_type">>}.

v2_password_hash(PassBin, SaltBin) ->
    Iter = 100000,
    case erlang:function_exported(crypto, pbkdf2_hmac, 5) of
        true ->
            crypto:pbkdf2_hmac(sha256, PassBin, SaltBin, Iter, 32);
        false ->
            crypto:hash(sha256, <<SaltBin/binary, PassBin/binary>>)
    end.

v2_password_verify(PassBin, Admin) ->
    Pw = maps:get(<<"pw">>, Admin, #{}),
    SaltB64 = maps:get(<<"salt">>, Pw, <<>>),
    HashB64 = maps:get(<<"hash">>, Pw, <<>>),
    %% OTP22 + vår JSON-decoder kan ge listor för strängar → säkerställ binary före base64-decode.
    SaltBinB64 = to_bin(SaltB64),
    HashBinB64 = to_bin(HashB64),
    Salt = try base64:decode(SaltBinB64) catch _:_ -> <<>> end,
    Want = try base64:decode(HashBinB64) catch _:_ -> <<>> end,
    UsePbkdf2 = erlang:function_exported(crypto, pbkdf2_hmac, 5),
    v2_auth_dbg("pwverify salt_b64_type=~p hash_b64_type=~p salt_b64_bytes=~p hash_b64_bytes=~p salt_bytes=~p want_bytes=~p pbkdf2=~p",
                [type_tag(SaltB64), type_tag(HashB64), byte_size(SaltBinB64), byte_size(HashBinB64), byte_size(Salt), byte_size(Want), UsePbkdf2]),
    Got = v2_password_hash(to_bin(PassBin), Salt),
    v2_auth_dbg("pwverify got_bytes=~p match=~p", [byte_size(Got), Got =:= Want]),
    Got =:= Want.

v2_cookie_name() -> "jaktpass_v2".

v2_cookie_secure() ->
    case string:lowercase(getenv_default("JAKTPASS_COOKIE_SECURE", "false")) of
        "1" -> true;
        "true" -> true;
        "yes" -> true;
        _ -> false
    end.

v2_set_cookie_header(Token) when is_list(Token) ->
    Base = "jaktpass_v2=" ++ Token ++ "; Path=/; HttpOnly; SameSite=Lax",
    Val = case v2_cookie_secure() of true -> Base ++ "; Secure"; false -> Base end,
    {header, {"Set-Cookie", Val}}.

v2_set_cookie_header_expire() ->
    %% Expire cookie
    {header, {"Set-Cookie", "jaktpass_v2=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"}}.

v2_new_session(AdminId0) ->
    AdminId = to_bin(AdminId0),
    TokBin = crypto:strong_rand_bytes(24),
    Tok = base64url_encode(TokBin),
    Sess = #{<<"adminId">> => AdminId, <<"createdAt">> => now_rfc3339()},
    Path = v2_session_path(Tok),
    ok = filelib:ensure_dir(Path),
    ok = write_json_atomic(Path, Sess),
    {Tok, v2_set_cookie_header(Tok)}.

v2_delete_session(A) ->
    case v2_get_cookie(A#arg.headers, v2_cookie_name()) of
        undefined -> ok;
        Tok ->
            Path = v2_session_path(Tok),
            _ = file:delete(Path),
            ok
    end.

v2_current_admin(A) ->
    Tok0 = v2_get_cookie(A#arg.headers, v2_cookie_name()),
    v2_auth_dbg("me cookie_tok_present=~p cookie_repr=~p", [Tok0 =/= undefined, v2_cookie_repr(A#arg.headers)]),
    case Tok0 of
        undefined -> error;
        Tok ->
            Path = v2_session_path(Tok),
            case file:read_file(Path) of
                {ok, Bin} ->
                    try
                        Sess = json_decode(Bin),
                        AdminIdB = maps:get(<<"adminId">>, Sess, undefined),
                        case AdminIdB of
                            undefined -> error;
                            _ ->
                                case v2_load_admin(binary_to_list(to_bin(AdminIdB))) of
                                    {ok, Admin} -> {ok, Admin};
                                    _ -> error
                                end
                        end
                    catch _:_ ->
                        error
                    end;
                _ ->
                    v2_auth_dbg("me session_not_found tok_prefix=~p path=~p", [v2_tok_prefix(Tok), Path]),
                    error
            end
    end.

v2_get_cookie(H, Name) when is_record(H, headers) ->
    %% Försök först Yaws inbyggda cookie-hjälp (mer robust mellan versioner)
    Cookies = H#headers.cookie,
    case erlang:function_exported(yaws_api, find_cookie_val, 2) of
        true ->
            try
                case yaws_api:find_cookie_val(Name, Cookies) of
                    [] -> v2_get_cookie_fallback(H, Name);
                    undefined -> v2_get_cookie_fallback(H, Name);
                    V when is_list(V); is_binary(V) -> v2_cookie_to_token(V);
                    _ -> v2_get_cookie_fallback(H, Name)
                end
            catch _:_ ->
                v2_get_cookie_fallback(H, Name)
            end;
        false ->
            v2_get_cookie_fallback(H, Name)
    end;
v2_get_cookie(_, _) ->
    undefined.

v2_get_cookie_fallback(H, Name) ->
    %% 1) vår tidigare loop över parsed cookies
    case v2_get_cookie_loop(H#headers.cookie, Name) of
        undefined ->
            %% 2) fallback: parsa raw Cookie-header om Yaws inte fyllde H#headers.cookie
            Raw = header_value(H, "cookie"),
            v2_parse_cookie_header(Raw, Name);
        V ->
            v2_cookie_to_token(V)
    end.

v2_get_cookie_loop([], _Name) -> undefined;
v2_get_cookie_loop([C | Rest], Name) ->
    case C of
        #cookie{key = K, value = V} ->
            case K =:= Name of true -> V; false -> v2_get_cookie_loop(Rest, Name) end;
        {K, V} ->
            case K =:= Name of true -> V; false -> v2_get_cookie_loop(Rest, Name) end;
        _ ->
            v2_get_cookie_loop(Rest, Name)
    end.

v2_cookie_to_token(V) when is_binary(V) -> binary_to_list(V);
v2_cookie_to_token(V) when is_list(V) -> V;
v2_cookie_to_token(_) -> undefined.

v2_parse_cookie_header(undefined, _Name) -> undefined;
v2_parse_cookie_header(Bin, Name) when is_binary(Bin) ->
    v2_parse_cookie_header(binary_to_list(Bin), Name);
v2_parse_cookie_header(Str, Name) when is_list(Str) ->
    %% Ex: "a=b; jaktpass_v2=tok; c=d"
    Parts = [string:trim(P) || P <- string:tokens(Str, ";")],
    v2_parse_cookie_parts(Parts, Name);
v2_parse_cookie_header(_, _) ->
    undefined.

v2_parse_cookie_parts([], _Name) -> undefined;
v2_parse_cookie_parts([P | Rest], Name) ->
    case string:tokens(P, "=") of
        [K, V] ->
            case string:trim(K) =:= Name of
                true -> string:trim(V);
                false -> v2_parse_cookie_parts(Rest, Name)
            end;
        _ -> v2_parse_cookie_parts(Rest, Name)
    end.

v2_tok_prefix(Tok) when is_list(Tok) ->
    lists:sublist(Tok, 6);
v2_tok_prefix(_Tok) ->
    "".

v2_cookie_repr(H) when is_record(H, headers) ->
    %% Lätt debug för att se om cookies ens kommer in
    C = H#headers.cookie,
    case C of
        [] -> {empty, header_value(H, "cookie")};
        _ -> {parsed, length(C)}
    end;
v2_cookie_repr(_H) ->
    undefined.

base64url_encode(Bin) ->
    Enc0 = binary_to_list(base64:encode(Bin)),
    Enc1 = [case C of $+ -> $-; $/ -> $_; $= -> $\s; _ -> C end || C <- Enc0],
    lists:filter(fun(C) -> C =/= $\s end, Enc1).

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

json_ok_headers(Code, Data, ExtraHeaders) ->
    Body = iolist_to_binary(json_encode(#{<<"ok">> => true, <<"data">> => Data})),
    [{status, Code},
     {header, {"Content-Type", "application/json"}}] ++
    ExtraHeaders ++
    [{content, "application/json", Body}].

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

