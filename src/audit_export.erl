-module(audit_export).
-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Exports a list of records or single record to formatted JSON.
-spec to_json(#audit_record{} | [#audit_record{}]) -> binary().
to_json(#audit_record{} = R) ->
    iolist_to_binary(format_json_record(R));
to_json(Records) when is_list(Records) ->
    Formatted = [ format_json_record(R) || R <- Records ],
    Joined = lists:join(",\n", Formatted),
    iolist_to_binary(["[\n", Joined, "\n]"]).

%% @doc Encrypts audit record stream into secure authenticated transit frames (SC-8 / SC-8(1)).
-spec to_secure_stream(#audit_record{} | [#audit_record{}], binary()) -> binary().
to_secure_stream(RecordOrRecords, EncKey) when is_binary(EncKey) ->
    JsonPayload = to_json(RecordOrRecords),
    TS = integer_to_binary(erlang:system_time(millisecond)),
    AAD = <<"SC-8-AUDIT-STREAM-v1:", TS/binary>>,
    EncryptedPayload = audit_crypto:encrypt(EncKey, JsonPayload, AAD),
    term_to_binary({secure_stream, TS, EncryptedPayload}).

%% @doc Decrypts and parses secure transit frame stream (SC-8 / SC-8(1)).
-spec from_secure_stream(binary(), binary()) -> {ok, binary()} | {error, term()}.
from_secure_stream(StreamBin, EncKey) when is_binary(StreamBin), is_binary(EncKey) ->
    try binary_to_term(StreamBin, [safe]) of
        {secure_stream, TS, EncryptedPayload} when is_binary(TS), is_binary(EncryptedPayload) ->
            AAD = <<"SC-8-AUDIT-STREAM-v1:", TS/binary>>,
            case audit_crypto:decrypt(EncKey, EncryptedPayload, AAD) of
                {ok, PlainJson} -> {ok, PlainJson};
                {error, Reason} -> {error, Reason}
            end;
        _ ->
            {error, invalid_stream_format}
    catch
        _:_ ->
            {error, corrupt_stream_binary}
    end.

%% @doc Exports audit records to Syslog / Wazuh CEF SIEM line format.
-spec to_siem(#audit_record{}) -> binary().
to_siem(#audit_record{id = Id, ts = TS, plane = Plane, subject = Subj,
                      event = Ev, resource = Res, action = Act, outcome = Out,
                      prev_hash = PrevHash}) ->
    TSStr = integer_to_binary(TS),
    PlaneStr = atom_to_binary(Plane, utf8),
    EvStr = atom_to_binary(Ev, utf8),
    ActStr = atom_to_binary(Act, utf8),
    OutStr = atom_to_binary(Out, utf8),
    PrevHex = binary_to_hex(PrevHash),
    IdHex = binary_to_hex(Id),
    iolist_to_binary([
        "CEF:0|SYNRC|ERP1_Audit|1.0|", EvStr, "|", ActStr, "|1|",
        "rt=", TSStr, " plane=", PlaneStr, " suser=", Subj,
        " res=", Res, " outcome=", OutStr, " prev_hash=", PrevHex,
        " record_id=", IdHex
    ]).

%% @doc Formats checkpoint and records into OSCAL assessment evidence map.
-spec to_oscal(#audit_checkpoint{}, [#audit_record{}]) -> map().
to_oscal(#audit_checkpoint{node_id = NodeId, record_count = Count, head_hash = HeadHash,
                           merkle_root = MerkleRoot, sig = Sig}, Records) ->
    #{
        <<"assessment-results">> => #{
            <<"title">> => <<"NIST SP 800-53 AU Evidence Log">>,
            <<"node-id">> => NodeId,
            <<"record-count">> => Count,
            <<"head-hash">> => binary_to_hex(HeadHash),
            <<"merkle-root">> => binary_to_hex(MerkleRoot),
            <<"signed">> => (Sig =/= undefined),
            <<"evidence-records">> => [ record_to_map(R) || R <- Records ]
        }
    }.

%% ===================================================================
%% Internal Helpers
%% ===================================================================

format_json_record(#audit_record{id = Id, ts = TS, plane = Plane, subject = Subj,
                                 event = Ev, resource = Res, action = Act, outcome = Out,
                                 prev_hash = PrevHash, hmac = Hmac, sig = Sig}) ->
    [
        "  {\n",
        "    \"id\": \"", binary_to_hex(Id), "\",\n",
        "    \"ts\": ", integer_to_binary(TS), ",\n",
        "    \"plane\": \"", atom_to_binary(Plane, utf8), "\",\n",
        "    \"subject\": \"", Subj, "\",\n",
        "    \"event\": \"", atom_to_binary(Ev, utf8), "\",\n",
        "    \"resource\": \"", Res, "\",\n",
        "    \"action\": \"", atom_to_binary(Act, utf8), "\",\n",
        "    \"outcome\": \"", atom_to_binary(Out, utf8), "\",\n",
        "    \"prev_hash\": \"", binary_to_hex(PrevHash), "\",\n",
        "    \"hmac\": \"", binary_to_hex(Hmac), "\",\n",
        "    \"sig\": \"", (case Sig of undefined -> "none"; _ -> binary_to_hex(Sig) end), "\"\n",
        "  }"
    ].

record_to_map(#audit_record{id = Id, ts = TS, plane = Plane, subject = Subj,
                            event = Ev, resource = Res, action = Act, outcome = Out,
                            prev_hash = PrevHash}) ->
    #{
        <<"id">> => binary_to_hex(Id),
        <<"ts">> => TS,
        <<"plane">> => atom_to_binary(Plane, utf8),
        <<"subject">> => Subj,
        <<"event">> => atom_to_binary(Ev, utf8),
        <<"resource">> => Res,
        <<"action">> => atom_to_binary(Act, utf8),
        <<"outcome">> => atom_to_binary(Out, utf8),
        <<"prev_hash">> => binary_to_hex(PrevHash)
    }.

binary_to_hex(undefined) -> <<"">>;
binary_to_hex(<<>>) -> <<"">>;
binary_to_hex(Bin) when is_binary(Bin) ->
    << <<(integer_to_hex_byte(X))/binary>> || <<X:4>> <= Bin >>.

integer_to_hex_byte(X) when X < 10 -> <<($0 + X)>>;
integer_to_hex_byte(X) -> <<($a + X - 10)>>.
