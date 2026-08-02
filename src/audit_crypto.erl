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
