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
    CPNoPriv = audit_checkpoint:create(<<"node-1">>, Records, R2#audit_record.prev_hash, undefined),
    ?assertEqual(undefined, CPNoPriv#audit_checkpoint.sig),
    ?assert(audit_checkpoint:verify(CPNoPriv, PubKey)),

    %% Checkpoint with TSP token
    PayloadToSign = <<(CPNoPriv#audit_checkpoint.node_id)/binary,
                      (CPNoPriv#audit_checkpoint.from_id)/binary,
                      (CPNoPriv#audit_checkpoint.to_id)/binary,
                      (CPNoPriv#audit_checkpoint.head_hash)/binary,
                      (CPNoPriv#audit_checkpoint.record_count):64/big,
                      (CPNoPriv#audit_checkpoint.merkle_root)/binary>>,
    Digest = audit_crypto:hash(PayloadToSign),
    ValidTspToken = audit_crypto:hash(sha512, <<"TSP-RFC3161:", Digest/binary>>),
    CPWithTSP = CPNoPriv#audit_checkpoint{sig = audit_crypto:sign(PrivKey, PayloadToSign), tsp = ValidTspToken},
    ?assert(audit_checkpoint:verify(CPWithTSP, PubKey)),

    CPRawTSP = CPNoPriv#audit_checkpoint{sig = audit_crypto:sign(PrivKey, PayloadToSign), tsp = crypto:strong_rand_bytes(48)},
    ?assert(audit_checkpoint:verify(CPRawTSP, PubKey)).

tampered_checkpoint_verify_test() ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    MacKey = audit_crypto:generate_mac_key(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 0),

    R1 = audit_chain:append_record(audit_record:new(system, <<"sys">>, boot, <<"k">>, start, success, #{}), Genesis, MacKey),
    R2 = audit_chain:append_record(audit_record:new(system, <<"sys">>, boot, <<"k">>, start, success, #{}), R1#audit_record.prev_hash, MacKey),
    R3 = audit_chain:append_record(audit_record:new(system, <<"sys">>, boot, <<"k">>, start, success, #{}), R2#audit_record.prev_hash, MacKey),

    %% 3 records test pair_nodes([A], Acc) odd number of leaves
    CP3 = audit_checkpoint:create(<<"node-1">>, [R1, R2, R3], R3#audit_record.prev_hash, PrivKey),
    ?assert(audit_checkpoint:verify(CP3, PubKey)),

    %% Signed checkpoint with undefined PubKey -> false
    ?assertNot(audit_checkpoint:verify(CP3, undefined)),

    %% Checkpoint with undefined signature -> true
    CPNoSig = CP3#audit_checkpoint{sig = undefined},
    ?assert(audit_checkpoint:verify(CPNoSig, PubKey)),

    TamperedCP = CP3#audit_checkpoint{record_count = 99},
    ?assertNot(audit_checkpoint:verify(TamperedCP, PubKey)).
