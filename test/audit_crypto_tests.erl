-module(audit_crypto_tests).
-include_lib("eunit/include/eunit.hrl").

key_generation_and_sign_verify_test() ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    ?assert(is_binary(PubKey)),
    ?assert(is_binary(PrivKey)),
    Data = <<"Critical Audit Event Payload">>,
    Sig = audit_crypto:sign(PrivKey, Data),
    ?assert(is_binary(Sig)),
    ?assert(audit_crypto:verify(PubKey, Data, Sig)),
    ?assertNot(audit_crypto:verify(PubKey, <<"Tampered Data">>, Sig)).

invalid_signature_test() ->
    {PubKey1, _} = audit_crypto:generate_keypair(),
    {_, PrivKey2} = audit_crypto:generate_keypair(),
    Data = <<"Some Event">>,
    Sig2 = audit_crypto:sign(PrivKey2, Data),
    ?assertNot(audit_crypto:verify(PubKey1, Data, Sig2)).

hmac_test() ->
    Key = audit_crypto:generate_mac_key(),
    Data = <<"Audit Log Link">>,
    Hmac1 = audit_crypto:hmac(Key, Data),
    Hmac2 = audit_crypto:hmac(Key, Data),
    ?assertEqual(Hmac1, Hmac2),
    ?assertNotEqual(Hmac1, audit_crypto:hmac(Key, <<"Modified Data">>)).

hash_test() ->
    Data = <<"Test Binary">>,
    H384 = audit_crypto:hash(Data),
    H512 = audit_crypto:hash(sha512, Data),
    ?assertEqual(48, byte_size(H384)),
    ?assertEqual(64, byte_size(H512)),
    ?assertNot(audit_crypto:verify(<<"invalid_key">>, Data, <<"invalid_sig">>)).

aes_256_gcm_encryption_test() ->
    EncKey = audit_crypto:generate_enc_key(),
    ?assertEqual(32, byte_size(EncKey)),
    Plaintext = <<"Confidential Audit Payload SC-28 AU-9(3)">>,
    AAD = <<"record_id_123">>,
    
    Encrypted = audit_crypto:encrypt(EncKey, Plaintext, AAD),
    ?assert(is_binary(Encrypted)),
    ?assert(byte_size(Encrypted) > byte_size(Plaintext)),

    {ok, Decrypted} = audit_crypto:decrypt(EncKey, Encrypted, AAD),
    ?assertEqual(Plaintext, Decrypted),

    %% Test without explicit AAD
    Encrypted2 = audit_crypto:encrypt(EncKey, Plaintext),
    {ok, Decrypted2} = audit_crypto:decrypt(EncKey, Encrypted2),
    ?assertEqual(Plaintext, Decrypted2),

    %% Test invalid tag / AAD mismatch
    ?assertEqual({error, invalid_tag}, audit_crypto:decrypt(EncKey, Encrypted, <<"wrong_aad">>)),

    %% Test corrupted ciphertext
    <<IV:12/binary, Tag:16/binary, _Rest/binary>> = Encrypted,
    CorruptCipher = <<IV:12/binary, Tag:16/binary, "corrupted_bytes_00000">>,
    ?assertEqual({error, invalid_tag}, audit_crypto:decrypt(EncKey, CorruptCipher, AAD)),

    %% Test invalid ciphertext binary format (too short)
    ?assertEqual({error, invalid_ciphertext_format}, audit_crypto:decrypt(EncKey, <<"short_bin">>)),

    %% Test decrypt catch path (decrypt_failed) when passing invalid key size
    InvalidKeySize = <<"bad_key_length">>,
    ?assertEqual({error, decrypt_failed}, audit_crypto:decrypt(InvalidKeySize, Encrypted)).

timestamp_token_test() ->
    Digest = audit_crypto:hash(<<"some_data">>),
    TS = erlang:system_time(millisecond),
    Token = audit_crypto:timestamp_token(Digest, TS),
    ?assert(audit_crypto:verify_timestamp(Token, Digest, TS)),
    ?assertNot(audit_crypto:verify_timestamp(Token, Digest, TS + 1000)).
