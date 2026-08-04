-module(audit_crypto).
-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Generates a new ECDSA keypair using NIST P-384 curve.
-spec generate_keypair() -> {PublicKey :: binary(), PrivateKey :: binary()}.
generate_keypair() ->
    crypto:generate_key(ecdh, secp384r1).

%% @doc Generates a 256-bit symmetric MAC key.
-spec generate_mac_key() -> binary().
generate_mac_key() ->
    crypto:strong_rand_bytes(32).

%% @doc Generates a 256-bit symmetric encryption key (AES-256-GCM for SC-28 / AU-9(3)).
-spec generate_enc_key() -> binary().
generate_enc_key() ->
    crypto:strong_rand_bytes(32).

%% @doc Encrypts data using AES-256-GCM (SC-28 / AU-9(3) / SC-8).
-spec encrypt(binary(), binary()) -> binary().
encrypt(Key, Plaintext) ->
    encrypt(Key, Plaintext, <<>>).

-spec encrypt(binary(), binary(), binary()) -> binary().
encrypt(Key, Plaintext, AAD) when is_binary(Key), byte_size(Key) =:= 32, is_binary(Plaintext), is_binary(AAD) ->
    IV = crypto:strong_rand_bytes(12),
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Plaintext, AAD, true),
    <<IV:12/binary, Tag:16/binary, Ciphertext/binary>>.

%% @doc Decrypts AES-256-GCM payload with AEAD tag authentication.
-spec decrypt(binary(), binary()) -> {ok, binary()} | {error, term()}.
decrypt(Key, EncryptedBin) ->
    decrypt(Key, EncryptedBin, <<>>).

-spec decrypt(binary(), binary(), binary()) -> {ok, binary()} | {error, term()}.
decrypt(Key, <<IV:12/binary, Tag:16/binary, Ciphertext/binary>>, AAD)
  when is_binary(Key), is_binary(AAD) ->
    try crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Ciphertext, AAD, Tag, false) of
        error -> {error, invalid_tag};
        Plaintext when is_binary(Plaintext) -> {ok, Plaintext}
    catch
        _:_ -> {error, decrypt_failed}
    end;
decrypt(_Key, _InvalidBin, _AAD) ->
    {error, invalid_ciphertext_format}.

%% @doc Computes SHA-384 hash of given binary data (default hash for audit chain).
-spec hash(binary()) -> binary().
hash(Data) when is_binary(Data) ->
    crypto:hash(sha384, Data).

%% @doc Computes specified hash (sha384 or sha512) of binary data.
-spec hash(sha384 | sha512, binary()) -> binary().
hash(Algo, Data) when (Algo =:= sha384 orelse Algo =:= sha512), is_binary(Data) ->
    crypto:hash(Algo, Data).

%% @doc Computes HMAC-SHA-512 over Data using Key.
-spec hmac(binary(), binary()) -> binary().
hmac(Key, Data) when is_binary(Key), is_binary(Data) ->
    crypto:mac(hmac, sha512, Key, Data).

%% @doc Signs Data using ECDSA P-384 with SHA-384 digest.
-spec sign(binary(), binary()) -> binary().
sign(PrivKey, Data) when is_binary(PrivKey), is_binary(Data) ->
    Digest = hash(Data),
    crypto:sign(ecdsa, sha384, {digest, Digest}, [PrivKey, secp384r1]).

%% @doc Verifies an ECDSA P-384 signature over Data using PubKey.
-spec verify(binary(), binary(), binary()) -> boolean().
verify(PubKey, Data, Signature) when is_binary(PubKey), is_binary(Data), is_binary(Signature) ->
    Digest = hash(Data),
    try
        crypto:verify(ecdsa, sha384, {digest, Digest}, Signature, [PubKey, secp384r1])
    catch
        _:_ -> false
    end.

%% @doc Generates a simulated RFC 3161 TimeStampToken for a given digest/signature.
-spec timestamp_token(binary(), integer()) -> binary().
timestamp_token(Digest, TS) when is_binary(Digest), is_integer(TS) ->
    Payload = <<"TSP-RFC3161:", (integer_to_binary(TS))/binary, ":", Digest/binary>>,
    hash(sha512, Payload).

%% @doc Verifies an RFC 3161 simulated timestamp token against digest and timestamp.
-spec verify_timestamp(binary(), binary(), integer()) -> boolean().
verify_timestamp(Token, Digest, TS) when is_binary(Token), is_binary(Digest), is_integer(TS) ->
    Expected = timestamp_token(Digest, TS),
    Token =:= Expected.
