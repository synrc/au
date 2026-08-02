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
