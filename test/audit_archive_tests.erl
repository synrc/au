-module(audit_archive_tests).
-include_lib("eunit/include/eunit.hrl").
-include("audit.hrl").

cut_and_seal_segment_test() ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    MacKey = audit_crypto:generate_mac_key(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 0),

    R1 = (audit_chain:append_record(audit_record:new(system, <<"s">>, e1, <<"r">>, a, success, #{}), Genesis, MacKey))#audit_record{ts = 100},
    R2 = (audit_chain:append_record(audit_record:new(system, <<"s">>, e2, <<"r">>, a, success, #{}), R1#audit_record.prev_hash, MacKey))#audit_record{ts = 200},

    {Archived, Active} = audit_archive:cut_segment([R1, R2], 150),
    ?assertEqual([R1], Archived),
    ?assertEqual([R2], Active),

    CP = audit_archive:seal_segment(Archived, <<"node-1">>, PrivKey),
    ?assert(audit_checkpoint:verify(CP, PubKey)),

    EmptyCP = audit_archive:seal_segment([], <<"node-1">>, PrivKey),
    ?assert(audit_checkpoint:verify(EmptyCP, PubKey)).

serialize_deserialize_test() ->
    {_PubKey, PrivKey} = audit_crypto:generate_keypair(),
    MacKey = audit_crypto:generate_mac_key(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 0),

    R1 = audit_chain:append_record(audit_record:new(system, <<"s">>, e1, <<"r">>, a, success, #{}), Genesis, MacKey),
    CP = audit_checkpoint:create(<<"node-1">>, [R1], R1#audit_record.prev_hash, PrivKey),

    Serialized = audit_archive:serialize_archive([R1], CP),
    ?assert(is_binary(Serialized)),

    {ok, CP2, [R1_2]} = audit_archive:deserialize_archive(Serialized),
    ?assertEqual(CP, CP2),
    ?assertEqual(R1, R1_2),

    ?assertEqual({error, corrupt_archive_binary}, audit_archive:deserialize_archive(<<"not_a_term">>)),
    ?assertEqual({error, invalid_archive_format}, audit_archive:deserialize_archive(term_to_binary({wrong_term}))).

encrypted_archive_test() ->
    {_PubKey, PrivKey} = audit_crypto:generate_keypair(),
    MacKey = audit_crypto:generate_mac_key(),
    EncKey = audit_crypto:generate_enc_key(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 0),

    R1 = audit_chain:append_record(audit_record:new(system, <<"s">>, e1, <<"r">>, a, success, #{}), Genesis, MacKey),
    CP = audit_checkpoint:create(<<"node-1">>, [R1], R1#audit_record.prev_hash, PrivKey),

    EncryptedSerialized = audit_archive:serialize_archive([R1], CP, EncKey),
    ?assert(is_binary(EncryptedSerialized)),

    {ok, CP2, [R1_2]} = audit_archive:deserialize_archive(EncryptedSerialized, EncKey),
    ?assertEqual(CP, CP2),
    ?assertEqual(R1, R1_2),

    WrongKey = audit_crypto:generate_enc_key(),
    ?assertEqual({error, decrypt_failed}, audit_archive:deserialize_archive(EncryptedSerialized, WrongKey)).
