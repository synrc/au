-module(audit_merge).
-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

-type node_entry() :: {#audit_checkpoint{}, [#audit_record{}]}.
-type log_set() :: #{ binary() => node_entry() }.

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Returns an empty G-Set of node logs.
-spec new_log_set() -> log_set().
new_log_set() ->
    #{}.

%% @doc Adds or updates a node log inside a G-Set, merging records if node already exists.
-spec add_node_log(log_set(), #audit_checkpoint{}, [#audit_record{}]) -> log_set().
add_node_log(LogSet, Checkpoint, Records) when is_map(LogSet) ->
    NodeId = Checkpoint#audit_checkpoint.node_id,
    case maps:find(NodeId, LogSet) of
        error ->
            maps:put(NodeId, {Checkpoint, Records}, LogSet);
        {ok, {OldCP, OldRecs}} ->
            MergedEntry = merge_node_entries({OldCP, OldRecs}, {Checkpoint, Records}),
            maps:put(NodeId, MergedEntry, LogSet)
    end.

%% @doc Merges two G-Set log sets deterministically (CRDT G-Set union).
-spec merge(log_set(), log_set()) -> log_set().
merge(LogSetA, LogSetB) when is_map(LogSetA), is_map(LogSetB) ->
    maps:merge_with(fun(_NodeId, Entry1, Entry2) ->
        merge_node_entries(Entry1, Entry2)
    end, LogSetA, LogSetB).

%% @doc Materializes a total order linearization of all records across all nodes in the G-Set.
-spec linearize(log_set()) -> [#audit_record{}].
linearize(LogSet) when is_map(LogSet) ->
    linearize(LogSet, #{}).

%% @doc Filtered total order linearization with options map.
%% Options: #{ from_ts => int(), to_ts => int(), plane => plane(), limit => int() }
-spec linearize(log_set(), map()) -> [#audit_record{}].
linearize(LogSet, Opts) when is_map(LogSet), is_map(Opts) ->
    AllRecords = lists:flatten([ Recs || {_NodeId, {_CP, Recs}} <- maps:to_list(LogSet) ]),
    Deduplicated = deduplicate_records(AllRecords),
    Sorted = lists:sort(fun(#audit_record{ts = TS1, id = Id1, meta = M1},
                            #audit_record{ts = TS2, id = Id2, meta = M2}) ->
        Node1 = maps:get(<<"node_id">>, M1, <<>>),
        Node2 = maps:get(<<"node_id">>, M2, <<>>),
        if
            TS1 < TS2 -> true;
            TS1 > TS2 -> false;
            Node1 < Node2 -> true;
            Node1 > Node2 -> false;
            true -> Id1 =< Id2
        end
    end, Deduplicated),

    Filtered = filter_records(Sorted, Opts),
    apply_limit(Filtered, maps:get(limit, Opts, undefined)).

%% @doc Computes a cluster-wide global Merkle root over all node head hashes in canonical order.
-spec global_merkle_root(log_set()) -> binary().
global_merkle_root(LogSet) when is_map(LogSet) ->
    NodeIds = lists:sort(maps:keys(LogSet)),
    HeadHashes = [ (element(1, maps:get(NodeId, LogSet)))#audit_checkpoint.head_hash || NodeId <- NodeIds ],
    case HeadHashes of
        [] -> audit_crypto:hash(<<"EMPTY_CLUSTER_MERKLE_ROOT">>);
        _ ->
            Leaves = [ audit_crypto:hash(H) || H <- HeadHashes ],
            build_merkle_tree(Leaves)
    end.

%% @doc Verifies all checkpoints and record chains inside a merged log set.
-spec verify_merged(log_set(), binary() | undefined) -> boolean().
verify_merged(LogSet, SecPubKey) when is_map(LogSet) ->
    maps:fold(fun(_NodeId, {CP, Recs}, AccValid) ->
        CpValid = audit_checkpoint:verify(CP, SecPubKey),
        ChainValid = case Recs of
            [] -> true;
            [_ | _] ->
                GenesisPrev = audit_chain:genesis_hash(CP#audit_checkpoint.node_id, 0),
                verify_recs(Recs, GenesisPrev)
        end,
        AccValid andalso CpValid andalso ChainValid
    end, true, LogSet).

%% @doc Computes the difference (missing entries) between LogSetA and LogSetB.
-spec diff(log_set(), log_set()) -> log_set().
diff(LogSetA, LogSetB) when is_map(LogSetA), is_map(LogSetB) ->
    maps:fold(fun(NodeId, {CP_B, Recs_B}, Acc) ->
        case maps:find(NodeId, LogSetA) of
            error ->
                maps:put(NodeId, {CP_B, Recs_B}, Acc);
            {ok, {_CP_A, Recs_A}} ->
                MissingRecs = [ R || R <- Recs_B, not lists:keymember(R#audit_record.id, #audit_record.id, Recs_A) ],
                case MissingRecs of
                    [] -> Acc;
                    _ -> maps:put(NodeId, {CP_B, MissingRecs}, Acc)
                end
        end
    end, #{}, LogSetB).

%% @doc Generates a delta log set containing only records newer than the provided node counts map.
-spec delta(log_set(), #{ binary() => non_neg_integer() }) -> log_set().
delta(LogSet, KnownCounts) when is_map(LogSet), is_map(KnownCounts) ->
    maps:fold(fun(NodeId, {_CP, Recs}, Acc) ->
        Known = maps:get(NodeId, KnownCounts, 0),
        if
            length(Recs) > Known ->
                NewerRecs = lists:nthtail(Known, Recs),
                NewCP = audit_checkpoint:create(NodeId, NewerRecs, (lists:last(NewerRecs))#audit_record.prev_hash, undefined),
                maps:put(NodeId, {NewCP, NewerRecs}, Acc);
            true ->
                Acc
        end
    end, #{}, LogSet).

%% @doc Applies a delta log set to a local log set.
-spec apply_delta(log_set(), log_set()) -> log_set().
apply_delta(LocalSet, DeltaSet) when is_map(LocalSet), is_map(DeltaSet) ->
    merge(LocalSet, DeltaSet).

%% @doc Returns statistical metrics for a merged log set.
-spec stats(log_set()) -> map().
stats(LogSet) when is_map(LogSet) ->
    AllRecs = linearize(LogSet),
    NodeCount = maps:size(LogSet),
    TotalRecs = length(AllRecs),
    {MinTS, MaxTS} = case AllRecs of
        [] -> {0, 0};
        _ ->
            TSList = [ R#audit_record.ts || R <- AllRecs ],
            {lists:min(TSList), lists:max(TSList)}
    end,
    GlobalRoot = global_merkle_root(LogSet),
    #{
        <<"node_count">> => NodeCount,
        <<"total_records">> => TotalRecs,
        <<"min_timestamp">> => MinTS,
        <<"max_timestamp">> => MaxTS,
        <<"global_merkle_root">> => GlobalRoot
    }.

%% ===================================================================
%% Internal Helpers
%% ===================================================================

merge_node_entries({CP1, Recs1}, {CP2, Recs2}) ->
    CombinedRecs = deduplicate_records(Recs1 ++ Recs2),
    SortedRecs = lists:sort(fun(R1, R2) -> R1#audit_record.ts =< R2#audit_record.ts end, CombinedRecs),
    NewCP = if
        CP1#audit_checkpoint.record_count >= CP2#audit_checkpoint.record_count -> CP1;
        true -> CP2
    end,
    {NewCP, SortedRecs}.

deduplicate_records(Records) ->
    dedup_acc(Records, #{}, []).

dedup_acc([], _SeenMap, Acc) ->
    lists:reverse(Acc);
dedup_acc([R | Rest], SeenMap, Acc) ->
    Id = R#audit_record.id,
    case maps:find(Id, SeenMap) of
        {ok, _} -> dedup_acc(Rest, SeenMap, Acc);
        error -> dedup_acc(Rest, maps:put(Id, true, SeenMap), [R | Acc])
    end.

filter_records(Records, Opts) ->
    FromTS = maps:get(from_ts, Opts, undefined),
    ToTS = maps:get(to_ts, Opts, undefined),
    Plane = maps:get(plane, Opts, undefined),
    lists:filter(fun(R) ->
        TSOk = (FromTS =:= undefined orelse R#audit_record.ts >= FromTS) andalso
               (ToTS =:= undefined orelse R#audit_record.ts =< ToTS),
        PlaneOk = (Plane =:= undefined orelse R#audit_record.plane =:= Plane),
        TSOk andalso PlaneOk
    end, Records).

apply_limit(Records, undefined) -> Records;
apply_limit(Records, Limit) when is_integer(Limit), Limit >= 0 ->
    lists:sublist(Records, Limit).

verify_recs([], _Prev) ->
    true;
verify_recs([R | Rest], PrevHash) ->
    Payload = audit_record:canonical_payload(R),
    Expected = audit_crypto:hash(<<PrevHash/binary, Payload/binary>>),
    case R#audit_record.prev_hash =:= Expected of
        true -> verify_recs(Rest, R#audit_record.prev_hash);
        false -> false
    end.

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
