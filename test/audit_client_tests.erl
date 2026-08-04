-module(audit_client_tests).
-include_lib("eunit/include/eunit.hrl").

client_api_test() ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    {ok, _Pid} = audit_core:start_link(#{
        node_id => <<"client-node">>,
        sec_keypair => {PubKey, PrivKey}
    }),

    ?assertEqual(ok, audit_client:log(<<"subj">>, login, <<"res">>, act, success, #{})),
    ?assertEqual(ok, audit_client:log(system, <<"subj">>, event, <<"res">>, act, success, #{})),
    ?assertEqual(ok, audit_client:log_critical(security, <<"subj">>, cert, <<"res">>, act, success, #{})),

    audit_core:stop().
