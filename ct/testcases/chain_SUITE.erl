-module(chain_SUITE).
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include("audit.hrl").

all() ->
    [
        test_core_process_lifecycle,
        test_fail_secure_logging,
        test_critical_event_signing
    ].

init_per_suite(Config) ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    [{sec_pub, PubKey}, {sec_priv, PrivKey} | Config].

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    PubKey = ?config(sec_pub, Config),
    PrivKey = ?config(sec_priv, Config),
    {ok, _Pid} = audit_core:start_link(#{
        node_id => <<"ct-node">>,
        sec_keypair => {PubKey, PrivKey}
    }),
    Config.

end_per_testcase(_TC, _Config) ->
    catch audit_core:stop(),
    ok.

test_core_process_lifecycle(_Config) ->
    ok = audit_client:log(application, <<"user1">>, login, <<"sess">>, auth, success, #{}),
    ok = audit_client:log(system, <<"sys">>, mount, <<"/data">>, mount, success, #{}),
    Records = audit_core:get_records(),
    2 = length(Records),
    HeadHash = audit_core:get_head_hash(),
    true = (HeadHash =/= <<>>).

test_fail_secure_logging(_Config) ->
    %% Submitting valid records returns ok synchronously
    ok = audit_client:log(application, <<"app1">>, query, <<"db">>, read, success, #{}),
    %% Check records in ETS
    [_R1] = audit_core:get_records().

test_critical_event_signing(_Config) ->
    ok = audit_client:log_critical(security, <<"sec_admin">>, key_unseal, <<"hsm">>, unseal, success, #{}),
    [Record] = audit_core:get_records(),
    true = (Record#audit_record.sig =/= undefined),
    true = (Record#audit_record.tsp =/= undefined).
