-module(multi_node_SUITE).
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include("audit.hrl").

all() ->
    [
        test_multi_node_crdt_log_aggregation
    ].

init_per_suite(Config) ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    [{sec_pub, PubKey}, {sec_priv, PrivKey} | Config].

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    Config.

end_per_testcase(_TC, _Config) ->
    ok.

test_multi_node_crdt_log_aggregation(Config) ->
    PubKey = ?config(sec_pub, Config),
    PrivKey = ?config(sec_priv, Config),
    MacKey = audit_crypto:generate_mac_key(),

    %% Simulate Node A log creation
    G_A = audit_chain:genesis_hash(<<"DC1-NodeA">>, 0),
    R_A1 = audit_chain:append_record(audit_record:new(system, <<"sysA">>, boot, <<"k">>, start, success, #{}), G_A, MacKey),
    CP_A = audit_checkpoint:create(<<"DC1-NodeA">>, [R_A1], R_A1#audit_record.prev_hash, PrivKey),

    %% Simulate Node B log creation
    G_B = audit_chain:genesis_hash(<<"DC2-NodeB">>, 0),
    R_B1 = audit_chain:append_record(audit_record:new(application, <<"appB">>, login, <<"sess">>, auth, success, #{}), G_B, MacKey),
    CP_B = audit_checkpoint:create(<<"DC2-NodeB">>, [R_B1], R_B1#audit_record.prev_hash, PrivKey),

    %% Build G-Sets
    GSet_A = audit_merge:add_node_log(audit_merge:new_log_set(), CP_A, [R_A1]),
    GSet_B = audit_merge:add_node_log(audit_merge:new_log_set(), CP_B, [R_B1]),

    MergedSet = audit_merge:merge(GSet_A, GSet_B),
    true = audit_merge:verify_merged(MergedSet, PubKey),

    Linearized = audit_merge:linearize(MergedSet),
    2 = length(Linearized).
