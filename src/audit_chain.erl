-module(audit_chain).
-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Computes genesis hash for a node's audit chain.
-spec genesis_hash(binary(), integer()) -> binary().
genesis_hash(NodeId, BootTime) when is_binary(NodeId), is_integer(BootTime) ->
    BootBin = integer_to_binary(BootTime),
    audit_crypto:hash(<<"ERP.1-AUDIT-ROOT:", NodeId/binary, ":", BootBin/binary>>).

%% @doc Appends a standard record to the local chain, setting prev_hash and HMAC.
-spec append_record(#audit_record{}, binary(), binary()) -> #audit_record{}.
append_record(#audit_record{} = Record, PrevHash, MacKey)
  when is_binary(PrevHash), is_binary(MacKey) ->
    Payload = audit_record:canonical_payload(Record),
    NextPrevHash = audit_crypto:hash(<<PrevHash/binary, Payload/binary>>),
    Hmac = audit_crypto:hmac(MacKey, <<NextPrevHash/binary, Payload/binary>>),
    Record#audit_record{
        prev_hash = NextPrevHash,
        hmac      = Hmac
    }.

%% @doc Appends a critical record requiring Security Admin ECDSA signature and RFC 3161 timestamp.
-spec append_critical_record(#audit_record{}, binary(), binary(), binary()) -> #audit_record{}.
append_critical_record(#audit_record{} = Record, PrevHash, MacKey, SecPrivKey)
  when is_binary(PrevHash), is_binary(MacKey), is_binary(SecPrivKey) ->
    Record1 = append_record(Record, PrevHash, MacKey),
    Payload = audit_record:canonical_payload(Record1),
    SigData = <<(Record1#audit_record.prev_hash)/binary, Payload/binary>>,
    Sig = audit_crypto:sign(SecPrivKey, SigData),
    TSP = audit_crypto:timestamp_token(audit_crypto:hash(SigData), Record1#audit_record.ts),
    Record1#audit_record{
        sig = Sig,
        tsp = TSP
    }.

%% @doc Verifies chain link continuity, HMAC, and optional Security Admin signature.
-spec verify_record(#audit_record{}, binary(), binary(), binary() | undefined) -> boolean().
verify_record(#audit_record{prev_hash = RecPrevHash, hmac = RecHmac,
                            sig = Sig, tsp = TSP} = Record,
              PrevPrevHash, MacKey, SecPubKey) ->
    Payload = audit_record:canonical_payload(Record),
    ExpectedPrevHash = audit_crypto:hash(<<PrevPrevHash/binary, Payload/binary>>),
    ExpectedHmac = audit_crypto:hmac(MacKey, <<ExpectedPrevHash/binary, Payload/binary>>),
    HashValid = (RecPrevHash =:= ExpectedPrevHash),
    HmacValid = (RecHmac =:= ExpectedHmac),
    SigData = <<RecPrevHash/binary, Payload/binary>>,
    SigValid = case {Sig, SecPubKey} of
        {undefined, _} -> true;
        {_, undefined} -> false;
        {SigBin, PubKeyBin} ->
            audit_crypto:verify(PubKeyBin, SigData, SigBin)
    end,
    TspValid = case {TSP, Sig} of
        {undefined, _} -> true;
        {TspBin, _} ->
            audit_crypto:verify_timestamp(TspBin, audit_crypto:hash(SigData), Record#audit_record.ts)
    end,
    HashValid andalso HmacValid andalso SigValid andalso TspValid.
