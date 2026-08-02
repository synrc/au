-module(audit_chain_tests).
-include_lib("eunit/include/eunit.hrl").
-include("audit.hrl").

genesis_hash_test() ->
    G1 = audit_chain:genesis_hash(<<"node-1">>, 1000),
    G2 = audit_chain:genesis_hash(<<"node-1">>, 1000),
    G3 = audit_chain:genesis_hash(<<"node-2">>, 1000),
    ?assertEqual(G1, G2),
    ?assertNotEqual(G1, G3).

append_and_verify_record_test() ->
    MacKey = audit_crypto:generate_mac_key(),
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 1000),

    R1 = audit_record:new(system, <<"sys">>, boot, <<"kernel">>, start, success, #{}),
    R1Chained = audit_chain:append_record(R1, Genesis, MacKey),
    ?assert(audit_chain:verify_record(R1Chained, Genesis, MacKey, PubKey)),

    R2 = audit_record:new(security, <<"admin">>, key_unseal, <<"tpm">>, unseal, success, #{}),
    R2Chained = audit_chain:append_critical_record(R2, R1Chained#audit_record.prev_hash, MacKey, PrivKey),
    ?assert(audit_chain:verify_record(R2Chained, R1Chained#audit_record.prev_hash, MacKey, PubKey)).

tamper_detection_test() ->
    MacKey = audit_crypto:generate_mac_key(),
    {PubKey, _PrivKey} = audit_crypto:generate_keypair(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 1000),

    R1 = audit_record:new(system, <<"sys">>, boot, <<"kernel">>, start, success, #{}),
    R1Chained = audit_chain:append_record(R1, Genesis, MacKey),

    %% Tamper subject
    TamperedR1 = R1Chained#audit_record{subject = <<"hacker">>},
    ?assertNot(audit_chain:verify_record(TamperedR1, Genesis, MacKey, PubKey)).
