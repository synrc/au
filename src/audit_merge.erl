-module(audit_merge).
-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

-type log_set() :: #{ binary() => {#audit_checkpoint{}, [#audit_record{}]} }.

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Returns an empty G-Set of node logs.
-spec new_log_set() -> log_set().
new_log_set() ->
    #{}.

%% @doc Adds or updates a node log inside a G-Set.
-spec add_node_log(log_set(), #audit_checkpoint{}, [#audit_record{}]) -> log_set().
add_node_log(LogSet, Checkpoint, Records) when is_map(LogSet) ->
    NodeId = Checkpoint#audit_checkpoint.node_id,
    case maps:find(NodeId, LogSet) of
        error ->
            maps:put(NodeId, {Checkpoint, Records}, LogSet);
        {ok, {OldCP, OldRecs}} ->
            NewEntry = select_newer({OldCP, OldRecs}, {Checkpoint, Records}),
            maps:put(NodeId, NewEntry, LogSet)
    end.

%% @doc Merges two G-Set log sets deterministically (CRDT G-Set union).
-spec merge(log_set(), log_set()) -> log_set().
merge(LogSetA, LogSetB) when is_map(LogSetA), is_map(LogSetB) ->
    maps:merge_with(fun(_NodeId, Entry1, Entry2) ->
        select_newer(Entry1, Entry2)
    end, LogSetA, LogSetB).

%% @doc Materializes a total order linearization of all records across all nodes in the G-Set.
-spec linearize(log_set()) -> [#audit_record{}].
linearize(LogSet) when is_map(LogSet) ->
    AllRecords = lists:flatten([ Recs || {_NodeId, {_CP, Recs}} <- maps:to_list(LogSet) ]),
    lists:sort(fun(#audit_record{ts = TS1, id = Id1}, #audit_record{ts = TS2, id = Id2}) ->
        if
            TS1 < TS2 -> true;
            TS1 > TS2 -> false;
            true -> Id1 =< Id2
        end
    end, AllRecords).

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

%% ===================================================================
%% Internal Helpers
%% ===================================================================

select_newer({CP1, _Recs1} = E1, {CP2, _Recs2} = E2) ->
    if
        CP1#audit_checkpoint.record_count >= CP2#audit_checkpoint.record_count -> E1;
        true -> E2
    end.

verify_recs([], _Prev) ->
    true;
verify_recs([R | Rest], PrevHash) ->
    Payload = audit_record:canonical_payload(R),
    Expected = audit_crypto:hash(<<PrevHash/binary, Payload/binary>>),
    case R#audit_record.prev_hash =:= Expected of
        true -> verify_recs(Rest, R#audit_record.prev_hash);
        false -> false
    end.
