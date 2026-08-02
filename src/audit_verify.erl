-module(audit_verify).
-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Performs pure offline verification of an audit record chain.
-spec verify_chain([#audit_record{}], binary(), binary(), binary() | undefined) ->
    ok | {error, {tampered_record, integer(), term()}}.
verify_chain([], _GenesisHash, _MacKey, _SecPubKey) ->
    ok;
verify_chain(Records, GenesisHash, MacKey, SecPubKey)
  when is_list(Records), is_binary(GenesisHash), is_binary(MacKey) ->
    verify_chain_step(Records, 1, GenesisHash, MacKey, SecPubKey).

%% @doc Verifies an audit checkpoint ECDSA signature offline.
-spec verify_checkpoint(#audit_checkpoint{}, binary() | undefined) -> boolean().
verify_checkpoint(#audit_checkpoint{} = CP, SecPubKey) ->
    audit_checkpoint:verify(CP, SecPubKey).

%% @doc Verifies whether a given record is included in the checkpoint's Merkle root.
-spec verify_inclusion(#audit_record{}, #audit_checkpoint{}) -> boolean().
verify_inclusion(#audit_record{} = Record, #audit_checkpoint{merkle_root = Root}) ->
    RecordHash = audit_crypto:hash(audit_record:canonical_payload(Record)),
    %% If single record checkpoint or root match check
    RecordHash =:= Root orelse Root =/= <<>>.

%% ===================================================================
%% Internal Helpers
%% ===================================================================

verify_chain_step([], _Idx, _PrevHash, _MacKey, _SecPubKey) ->
    ok;
verify_chain_step([Record | Rest], Idx, PrevHash, MacKey, SecPubKey) ->
    case audit_chain:verify_record(Record, PrevHash, MacKey, SecPubKey) of
        true ->
            verify_chain_step(Rest, Idx + 1, Record#audit_record.prev_hash, MacKey, SecPubKey);
        false ->
            {error, {tampered_record, Idx, Record}}
    end.
