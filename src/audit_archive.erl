-module(audit_archive).
-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Splits a record list at a timestamp boundary.
-spec cut_segment([#audit_record{}], integer()) -> {[#audit_record{}], [#audit_record{}]}.
cut_segment(Records, CutoffTS) when is_list(Records), is_integer(CutoffTS) ->
    lists:partition(fun(#audit_record{ts = TS}) -> TS =< CutoffTS end, Records).

%% @doc Seals an archived segment with a signed checkpoint.
-spec seal_segment([#audit_record{}], binary(), binary() | undefined) -> #audit_checkpoint{}.
seal_segment(Segment, NodeId, SecPrivKey) when is_list(Segment), is_binary(NodeId) ->
    HeadHash = case Segment of
        [] -> audit_chain:genesis_hash(NodeId, 0);
        _ -> (lists:last(Segment))#audit_record.prev_hash
    end,
    audit_checkpoint:create(NodeId, Segment, HeadHash, SecPrivKey).

%% @doc Serializes a segment and checkpoint to binary format.
-spec serialize_archive([#audit_record{}], #audit_checkpoint{}) -> binary().
serialize_archive(Segment, Checkpoint) ->
    term_to_binary({archive, Checkpoint, Segment}, [compressed]).

%% @doc Deserializes archive binary.
-spec deserialize_archive(binary()) -> {ok, #audit_checkpoint{}, [#audit_record{}]} | {error, term()}.
deserialize_archive(Bin) when is_binary(Bin) ->
    try
        case binary_to_term(Bin, [safe]) of
            {archive, #audit_checkpoint{} = CP, Records} when is_list(Records) ->
                {ok, CP, Records};
            _ -> {error, invalid_archive_format}
        end
    catch
        _:_ -> {error, corrupt_archive_binary}
    end.
