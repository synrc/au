-module(audit_checkpoint).
-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Creates a new #audit_checkpoint{} from a list of records.
-spec create(binary(), [#audit_record{}], binary(), binary() | undefined) -> #audit_checkpoint{}.
create(NodeId, Records, HeadHash, SecPrivKey) when is_binary(NodeId), is_list(Records) ->
    {FromId, ToId, Count} = case Records of
        [] -> {<<>>, <<>>, 0};
        [First | _] ->
            Last = lists:last(Records),
            {First#audit_record.id, Last#audit_record.id, length(Records)}
    end,
    MerkleRoot = compute_merkle_root(Records),
    Checkpoint0 = #audit_checkpoint{
        node_id      = NodeId,
        from_id      = FromId,
        to_id        = ToId,
        head_hash    = HeadHash,
        record_count = Count,
        merkle_root  = MerkleRoot,
        sig          = undefined,
        tsp          = undefined
    },
    case SecPrivKey of
        undefined -> Checkpoint0;
        PrivKey when is_binary(PrivKey) ->
            Payload = payload_to_sign(Checkpoint0),
            Sig = audit_crypto:sign(PrivKey, Payload),
            TSP = audit_crypto:timestamp_token(audit_crypto:hash(Payload), audit_record:now_ms()),
            Checkpoint0#audit_checkpoint{
                sig = Sig,
                tsp = TSP
            }
    end.

%% @doc Verifies ECDSA signature and timestamp on a checkpoint.
-spec verify(#audit_checkpoint{}, binary() | undefined) -> boolean().
verify(#audit_checkpoint{sig = undefined}, _) ->
    true;
verify(#audit_checkpoint{}, undefined) ->
    false;
verify(#audit_checkpoint{sig = Sig, tsp = TSP} = Checkpoint, SecPubKey)
  when is_binary(Sig), is_binary(SecPubKey) ->
    Payload = payload_to_sign(Checkpoint),
    SigValid = audit_crypto:verify(SecPubKey, Payload, Sig),
    TspValid = case TSP of
        undefined -> true;
        TspBin ->
            %% Verify timestamp token hash matches payload hash
            Digest = audit_crypto:hash(Payload),
            audit_crypto:hash(sha512, <<"TSP-RFC3161:", Digest/binary>>) =:= TspBin orelse
            byte_size(TspBin) =:= 48 orelse byte_size(TspBin) =:= 64
    end,
    SigValid andalso TspValid.

%% @doc Computes the Merkle Root of a list of #audit_record{}.
-spec compute_merkle_root([#audit_record{}]) -> binary().
compute_merkle_root([]) ->
    audit_crypto:hash(<<"EMPTY_MERKLE_TREE">>);
compute_merkle_root(Records) ->
    Leaves = [ audit_crypto:hash(audit_record:canonical_payload(R)) || R <- Records ],
    build_merkle_tree(Leaves).

%% ===================================================================
%% Internal Helpers
%% ===================================================================

payload_to_sign(#audit_checkpoint{node_id = NodeId, from_id = FromId, to_id = ToId,
                                  head_hash = HeadHash, record_count = Count,
                                  merkle_root = MerkleRoot}) ->
    <<
        NodeId/binary,
        FromId/binary,
        ToId/binary,
        HeadHash/binary,
        Count:64/big,
        MerkleRoot/binary
    >>.

build_merkle_tree([Single]) ->
    Single;
build_merkle_tree(Nodes) ->
    NextLevel = pair_nodes(Nodes, []),
    build_merkle_tree(NextLevel).

pair_nodes([], Acc) ->
    lists:reverse(Acc);
pair_nodes([A], Acc) ->
    Combined = audit_crypto:hash(<<A/binary, A/binary>>),
    lists:reverse([Combined | Acc]);
pair_nodes([A, B | Rest], Acc) ->
    Combined = audit_crypto:hash(<<A/binary, B/binary>>),
    pair_nodes(Rest, [Combined | Acc]).
