-module(audit_checkpoint_tests).
-include_lib("eunit/include/eunit.hrl").
-include("audit.hrl").

checkpoint_creation_and_verify_test() ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    MacKey = audit_crypto:generate_mac_key(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 1000),

    R1 = audit_chain:append_record(audit_record:new(system, <<"sys">>, boot, <<"k">>, start, success, #{}), Genesis, MacKey),
    R2 = audit_chain:append_record(audit_record:new(application, <<"app">>, req, <<"r">>, get, success, #{}), R1#audit_record.prev_hash, MacKey),

    Records = [R1, R2],
    CP = audit_checkpoint:create(<<"node-1">>, Records, R2#audit_record.prev_hash, PrivKey),

    ?assertEqual(<<"node-1">>, CP#audit_checkpoint.node_id),
    ?assertEqual(2, CP#audit_checkpoint.record_count),
    ?assert(is_binary(CP#audit_checkpoint.merkle_root)),
    ?assert(audit_checkpoint:verify(CP, PubKey)).

tampered_checkpoint_verify_test() ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    MacKey = audit_crypto:generate_mac_key(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 1000),

    R1 = audit_chain:append_record(audit_record:new(system, <<"sys">>, boot, <<"k">>, start, success, #{}), Genesis, MacKey),
    CP = audit_checkpoint:create(<<"node-1">>, [R1], R1#audit_record.prev_hash, PrivKey),

    TamperedCP = CP#audit_checkpoint{record_count = 99},
    ?assertNot(audit_checkpoint:verify(TamperedCP, PubKey)).
