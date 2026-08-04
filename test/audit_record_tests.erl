-module(audit_record_tests).
-include_lib("eunit/include/eunit.hrl").
-include("audit.hrl").

new_record_validation_test() ->
    R = audit_record:new(security, <<"user1">>, cert_issue, <<"cert-42">>, issue, success, #{<<"ip">> => <<"10.0.0.1">>}),
    ?assertEqual(security, R#audit_record.plane),
    ?assertEqual(<<"user1">>, R#audit_record.subject),
    ?assertEqual(cert_issue, R#audit_record.event),
    ?assertEqual(ok, audit_record:validate(R)).

invalid_record_plane_test() ->
    ?assertError({invalid_audit_record, invalid_plane},
                 audit_record:new(invalid_plane, <<"u">>, ev, <<"r">>, act, success, #{})).

encode_decode_test() ->
    R = audit_record:new(application, <<"app-sec">>, login, <<"session-1">>, create, success, #{}),
    Encoded = audit_record:encode(R),
    ?assert(is_binary(Encoded)),
    {ok, Decoded} = audit_record:decode(Encoded),
    ?assertEqual(R, Decoded).

canonical_payload_determinism_test() ->
    R1 = audit_record:new(system, <<"sys">>, mount, <<"/dev/sda">>, mount, success, #{<<"a">> => <<"1">>, <<"b">> => <<"2">>}),
    R2 = R1#audit_record{meta = #{<<"b">> => <<"2">>, <<"a">> => <<"1">>}},
    Payload1 = audit_record:canonical_payload(R1),
    Payload2 = audit_record:canonical_payload(R2),
    ?assertEqual(Payload1, Payload2).

validation_error_cases_test() ->
    R = audit_record:new(security, <<"user">>, ev, <<"res">>, act, success, #{}),
    ?assertEqual({error, invalid_id}, audit_record:validate(R#audit_record{id = <<>>})),
    ?assertEqual({error, invalid_timestamp}, audit_record:validate(R#audit_record{ts = 0})),
    ?assertEqual({error, invalid_plane}, audit_record:validate(R#audit_record{plane = bad_plane})),
    ?assertEqual({error, invalid_subject}, audit_record:validate(R#audit_record{subject = 123})),
    ?assertEqual({error, invalid_event}, audit_record:validate(R#audit_record{event = <<"not_an_atom">>})),
    ?assertEqual({error, invalid_resource}, audit_record:validate(R#audit_record{resource = 123})),
    ?assertEqual({error, invalid_action}, audit_record:validate(R#audit_record{action = <<"not_an_atom">>})),
    ?assertEqual({error, invalid_outcome}, audit_record:validate(R#audit_record{outcome = unknown})),
    ?assertEqual({error, not_a_record}, audit_record:validate(not_a_record)),
    ?assertEqual({error, invalid_binary}, audit_record:decode(<<"corrupt">>)),

    %% Decode valid binary term but invalid audit record schema
    InvalidRecordBin = term_to_binary({audit_record, <<>>, 0, invalid, 123, bad, 456, wrong, nil, #{}, <<>>, <<>>, nil, nil}),
    ?assertEqual({error, invalid_id}, audit_record:decode(InvalidRecordBin)),

    R2 = audit_record:new(security, "string_subject", ev, atom_resource, act, success, not_a_map),
    ?assertEqual(<<"string_subject">>, R2#audit_record.subject),
    ?assertEqual(<<"atom_resource">>, R2#audit_record.resource),

    PayloadNonMap = audit_record:canonical_payload(R2#audit_record{meta = undefined}),
    ?assert(is_binary(PayloadNonMap)).

payload_encryption_test() ->
    EncKey = audit_crypto:generate_enc_key(),
    Meta = #{<<"secret_key">> => <<"val123">>, <<"user_ip">> => <<"192.168.1.50">>},
    R = audit_record:new(security, <<"user1">>, login, <<"session1">>, auth, success, Meta),

    EncR = audit_record:encrypt_payload(R, EncKey),
    ?assertNotEqual(Meta, EncR#audit_record.meta),
    ?assert(maps:is_key(<<"$encrypted_meta">>, EncR#audit_record.meta)),

    {ok, DecR} = audit_record:decrypt_payload(EncR, EncKey),
    ?assertEqual(Meta, DecR#audit_record.meta),

    WrongKey = audit_crypto:generate_enc_key(),
    ?assertEqual({error, invalid_tag}, audit_record:decrypt_payload(EncR, WrongKey)),

    %% Decrypting non-encrypted record passes through
    ?assertEqual({ok, R}, audit_record:decrypt_payload(R, EncKey)),

    %% Decrypting record with corrupted encrypted meta binary
    CorruptMetaEncR = R#audit_record{meta = #{<<"$encrypted_meta">> => <<"short_invalid">>}},
    ?assertEqual({error, invalid_ciphertext_format}, audit_record:decrypt_payload(CorruptMetaEncR, EncKey)),

    %% Non-map decrypted meta
    NonMapEncMeta = audit_crypto:encrypt(EncKey, term_to_binary(not_a_map), R#audit_record.id),
    NonMapEncR = R#audit_record{meta = #{<<"$encrypted_meta">> => NonMapEncMeta}},
    ?assertEqual({error, invalid_decrypted_meta}, audit_record:decrypt_payload(NonMapEncR, EncKey)),

    %% Corrupt binary inside decrypted meta
    CorruptBinEncMeta = audit_crypto:encrypt(EncKey, <<"not_a_valid_term_binary">>, R#audit_record.id),
    CorruptBinEncR = R#audit_record{meta = #{<<"$encrypted_meta">> => CorruptBinEncMeta}},
    ?assertEqual({error, corrupt_decrypted_meta}, audit_record:decrypt_payload(CorruptBinEncR, EncKey)).
