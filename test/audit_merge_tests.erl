-module(audit_merge_tests).
-include_lib("eunit/include/eunit.hrl").
-include("audit.hrl").

multi_node_crdt_merge_test() ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    MacKey = audit_crypto:generate_mac_key(),

    %% Node 1 chain
    G1 = audit_chain:genesis_hash(<<"node-1">>, 0),
    R11 = audit_chain:append_record(audit_record:new(system, <<"sys1">>, start, <<"res">>, run, success, #{}), G1, MacKey),
    CP1 = audit_checkpoint:create(<<"node-1">>, [R11], R11#audit_record.prev_hash, PrivKey),

    %% Node 2 chain
    G2 = audit_chain:genesis_hash(<<"node-2">>, 0),
    R21 = audit_chain:append_record(audit_record:new(application, <<"app2">>, login, <<"sess">>, auth, success, #{}), G2, MacKey),
    CP2 = audit_checkpoint:create(<<"node-2">>, [R21], R21#audit_record.prev_hash, PrivKey),

    Set1 = audit_merge:add_node_log(audit_merge:new_log_set(), CP1, [R11]),
    Set2 = audit_merge:add_node_log(audit_merge:new_log_set(), CP2, [R21]),

    Merged = audit_merge:merge(Set1, Set2),
    ?assertEqual(2, maps:size(Merged)),

    SortedLinear = audit_merge:linearize(Merged),
    ?assertEqual(2, length(SortedLinear)),

    ?assert(audit_merge:verify_merged(Merged, PubKey)).
