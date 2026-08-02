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

linearize_with_options_test() ->
    MacKey = audit_crypto:generate_mac_key(),
    G1 = audit_chain:genesis_hash(<<"node-1">>, 0),

    R1 = (audit_chain:append_record(audit_record:new(application, <<"u1">>, e1, <<"r1">>, a1, success, #{}), G1, MacKey))#audit_record{ts = 100},
    R2 = (audit_chain:append_record(audit_record:new(security, <<"u2">>, e2, <<"r2">>, a2, success, #{}), R1#audit_record.prev_hash, MacKey))#audit_record{ts = 200},
    R3 = (audit_chain:append_record(audit_record:new(system, <<"u3">>, e3, <<"r3">>, a3, success, #{}), R2#audit_record.prev_hash, MacKey))#audit_record{ts = 300},

    CP = audit_checkpoint:create(<<"node-1">>, [R1, R2, R3], R3#audit_record.prev_hash, undefined),
    Set = audit_merge:add_node_log(audit_merge:new_log_set(), CP, [R1, R2, R3]),

    % Filter by timestamp range (from_ts and to_ts individually)
    TSFiltered = audit_merge:linearize(Set, #{from_ts => 150, to_ts => 350}),
    ?assertEqual(2, length(TSFiltered)),

    ToTSOnly = audit_merge:linearize(Set, #{to_ts => 150}),
    ?assertEqual(1, length(ToTSOnly)),

    % Filter by plane
    SecFiltered = audit_merge:linearize(Set, #{plane => security}),
    ?assertEqual(1, length(SecFiltered)),

    % Filter with limit
    Limited = audit_merge:linearize(Set, #{limit => 2}),
    ?assertEqual(2, length(Limited)),

    % Linearize with duplicate record IDs
    SetWithDup = audit_merge:add_node_log(Set, CP, [R1, R1, R2, R3]),
    LinearDup = audit_merge:linearize(SetWithDup, #{limit => undefined}),
    ?assertEqual(3, length(LinearDup)),

    % Merge where CP2 has higher record count than CP1
    CP_Higher = CP#audit_checkpoint{record_count = 100},
    SetCP2Higher = audit_merge:add_node_log(Set, CP_Higher, [R1, R2, R3]),
    MergedCP2 = audit_merge:merge(Set, SetCP2Higher),
    ?assertEqual(100, (element(1, maps:get(<<"node-1">>, MergedCP2)))#audit_checkpoint.record_count).

global_merkle_root_test() ->
    {_PubKey, PrivKey} = audit_crypto:generate_keypair(),
    MacKey = audit_crypto:generate_mac_key(),

    EmptyRoot = audit_merge:global_merkle_root(audit_merge:new_log_set()),
    ?assert(is_binary(EmptyRoot)),

    G1 = audit_chain:genesis_hash(<<"node-1">>, 0),
    R1 = audit_chain:append_record(audit_record:new(system, <<"s1">>, e1, <<"r1">>, a1, success, #{}), G1, MacKey),
    CP1 = audit_checkpoint:create(<<"node-1">>, [R1], R1#audit_record.prev_hash, PrivKey),

    G2 = audit_chain:genesis_hash(<<"node-2">>, 0),
    R2 = audit_chain:append_record(audit_record:new(system, <<"s2">>, e2, <<"r2">>, a2, success, #{}), G2, MacKey),
    CP2 = audit_checkpoint:create(<<"node-2">>, [R2], R2#audit_record.prev_hash, PrivKey),

    Set = audit_merge:merge(
        audit_merge:add_node_log(audit_merge:new_log_set(), CP1, [R1]),
        audit_merge:add_node_log(audit_merge:new_log_set(), CP2, [R2])
    ),

    GlobalRoot = audit_merge:global_merkle_root(Set),
    ?assert(is_binary(GlobalRoot)),
    ?assertEqual(48, byte_size(GlobalRoot)).

diff_and_delta_test() ->
    MacKey = audit_crypto:generate_mac_key(),
    G1 = audit_chain:genesis_hash(<<"node-1">>, 0),

    R1 = audit_chain:append_record(audit_record:new(application, <<"u1">>, e1, <<"r1">>, a1, success, #{}), G1, MacKey),
    R2 = audit_chain:append_record(audit_record:new(application, <<"u2">>, e2, <<"r2">>, a2, success, #{}), R1#audit_record.prev_hash, MacKey),

    CP1 = audit_checkpoint:create(<<"node-1">>, [R1], R1#audit_record.prev_hash, undefined),
    CP2 = audit_checkpoint:create(<<"node-1">>, [R1, R2], R2#audit_record.prev_hash, undefined),

    SetA = audit_merge:add_node_log(audit_merge:new_log_set(), CP1, [R1]),
    SetB = audit_merge:add_node_log(audit_merge:new_log_set(), CP2, [R1, R2]),

    Diff = audit_merge:diff(SetA, SetB),
    ?assertEqual(1, maps:size(Diff)),

    Delta = audit_merge:delta(SetB, #{<<"node-1">> => 1}),
    ?assertEqual(1, maps:size(Delta)),

    Applied = audit_merge:apply_delta(SetA, Delta),
    ?assertEqual(2, length(audit_merge:linearize(Applied))).

stats_test() ->
    MacKey = audit_crypto:generate_mac_key(),
    G1 = audit_chain:genesis_hash(<<"node-1">>, 0),

    R1 = audit_chain:append_record(audit_record:new(system, <<"s">>, e, <<"r">>, a, success, #{}), G1, MacKey),
    CP1 = audit_checkpoint:create(<<"node-1">>, [R1], R1#audit_record.prev_hash, undefined),

    Set = audit_merge:add_node_log(audit_merge:new_log_set(), CP1, [R1]),
    Stats = audit_merge:stats(Set),

    ?assertEqual(1, maps:get(<<"node_count">>, Stats)),
    ?assertEqual(1, maps:get(<<"total_records">>, Stats)),
    ?assert(maps:is_key(<<"global_merkle_root">>, Stats)),

    % Cover empty stats
    EmptyStats = audit_merge:stats(audit_merge:new_log_set()),
    ?assertEqual(0, maps:get(<<"total_records">>, EmptyStats)),

    % Cover adding existing node to update log entry
    CP2 = audit_checkpoint:create(<<"node-1">>, [R1, R1], R1#audit_record.prev_hash, undefined),
    SetUpdated = audit_merge:add_node_log(Set, CP2, [R1, R1]),
    ?assertEqual(1, maps:size(SetUpdated)),

    % Cover verify_merged with corrupted record in merged set
    R1Corrupt = R1#audit_record{prev_hash = <<"bad_prev_hash_corrupted_value_string_here_384_bit">>},
    CPCorrupt = audit_checkpoint:create(<<"node-1">>, [R1Corrupt], R1Corrupt#audit_record.prev_hash, undefined),
    BadSet = audit_merge:add_node_log(audit_merge:new_log_set(), CPCorrupt, [R1Corrupt]),
    ?assertNot(audit_merge:verify_merged(BadSet, undefined)),

    % Cover delta when known records >= existing records
    NoDelta = audit_merge:delta(Set, #{<<"node-1">> => 10}),
    ?assertEqual(0, maps:size(NoDelta)),

    % Cover diff when sets are identical
    NoDiff = audit_merge:diff(Set, Set),
    ?assertEqual(0, maps:size(NoDiff)).
