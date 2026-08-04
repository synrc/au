-module(audit_core_tests).
-include_lib("eunit/include/eunit.hrl").
-include("audit.hrl").

core_unconfigured_security_key_test() ->
    MacKey = audit_crypto:generate_mac_key(),
    BootTime = erlang:system_time(millisecond),
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    EncKey = audit_crypto:generate_enc_key(),

    {ok, Pid} = audit_core:start_link(#{
        node_id => <<"test-node">>,
        mac_key => MacKey,
        boot_time => BootTime
    }),
    R = audit_record:new(security, <<"admin">>, ev, <<"res">>, act, success, #{<<"key">> => <<"val">>}),
    ?assertEqual({error, security_key_not_configured}, audit_core:log_critical_event(R)),

    ?assertEqual(ok, audit_core:log_event(R)),

    % Cover error return from log_event
    MockErrR = audit_record:new(system, <<"admin">>, mock_error_event, <<"res">>, act, success, #{}),
    ?assertEqual({error, mock_event_error}, audit_core:log_event(MockErrR)),

    ?assert(is_binary(audit_core:get_head_hash())),
    Records = audit_core:get_records(),
    ?assertEqual(1, length(Records)),

    CP = audit_core:get_checkpoint(),
    ?assertMatch(#audit_checkpoint{}, CP),

    ?assertEqual({error, unknown_call}, gen_server:call(audit_core, unknown_msg)),

    ?assertEqual(ok, audit_core:set_security_keys(PubKey, PrivKey)),
    ?assertEqual(ok, audit_core:log_critical_event(R)),

    ?assertEqual(ok, audit_core:set_encryption_key(EncKey)),
    ?assertEqual(EncKey, audit_core:get_encryption_key()),
    ?assertEqual(ok, audit_core:log_event(R)),
    ?assertEqual(ok, audit_core:log_critical_event(R)),

    % Cover gen_server callbacks
    Pid ! cast_info_msg,
    gen_server:cast(Pid, cast_msg),
    ?assertEqual({ok, state}, audit_core:code_change(old_vsn, state, extra)),
    ?assertEqual(ok, audit_core:terminate(normal, state)),

    ?assertEqual(ok, audit_core:stop()),
    ?assertNot(erlang:is_process_alive(Pid)),

    % Cover start_link/0 with sec_keypair option map
    {ok, _Pid2} = audit_core:start_link(#{sec_keypair => {PubKey, PrivKey}}),
    audit_core:stop(),
    ?assertMatch({error, {audit_failed, _}}, audit_core:log_event(R)),
    ?assertMatch({error, {audit_failed, _}}, audit_core:log_critical_event(R)).
