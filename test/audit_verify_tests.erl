-module(audit_verify_tests).
-include_lib("eunit/include/eunit.hrl").
-include("audit.hrl").

pure_offline_chain_verify_test() ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    MacKey = audit_crypto:generate_mac_key(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 1000),

    R1 = audit_chain:append_record(audit_record:new(system, <<"s1">>, boot, <<"k">>, start, success, #{}), Genesis, MacKey),
    R2 = audit_chain:append_critical_record(audit_record:new(security, <<"admin">>, cert, <<"c">>, issue, success, #{}), R1#audit_record.prev_hash, MacKey, PrivKey),

    Records = [R1, R2],
    ?assertEqual(ok, audit_verify:verify_chain(Records, Genesis, MacKey, PubKey)),

    %% Corrupt second record's prev_hash
    R2Corrupt = R2#audit_record{prev_hash = <<"corrupted_prev_hash_data_string_here_384_bit">>},
    CorruptRecords = [R1, R2Corrupt],
    ?assertMatch({error, {tampered_record, 2, _}}, audit_verify:verify_chain(CorruptRecords, Genesis, MacKey, PubKey)).

verify_checkpoint_and_inclusion_test() ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    MacKey = audit_crypto:generate_mac_key(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 0),

    R1 = audit_chain:append_record(audit_record:new(system, <<"s1">>, boot, <<"k">>, start, success, #{}), Genesis, MacKey),
    CP = audit_checkpoint:create(<<"node-1">>, [R1], R1#audit_record.prev_hash, PrivKey),

    ?assert(audit_verify:verify_checkpoint(CP, PubKey)),
    ?assert(audit_verify:verify_inclusion(R1, CP)),
    ?assertEqual(ok, audit_verify:verify_chain([], Genesis, MacKey, PubKey)).
