-module(audit_record).
-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Generates a unique monotonic record ID.
-spec new_id() -> binary().
new_id() ->
    TS = erlang:system_time(millisecond),
    Rand = crypto:strong_rand_bytes(8),
    <<TS:64/big, Rand/binary>>.

%% @doc Returns current timestamp in UTC milliseconds.
-spec now_ms() -> integer().
now_ms() ->
    erlang:system_time(millisecond).

%% @doc Creates a new #audit_record{} with default parameters and validation.
-spec new(Plane, Subject, Event, Resource, Action, Outcome, Meta) -> #audit_record{} when
    Plane :: security | system | application,
    Subject :: binary(),
    Event :: atom(),
    Resource :: binary(),
    Action :: atom(),
    Outcome :: success | failure,
    Meta :: map().
new(Plane, Subject, Event, Resource, Action, Outcome, Meta) ->
    Record = #audit_record{
        id          = new_id(),
        ts          = now_ms(),
        plane       = Plane,
        subject     = ensure_binary(Subject),
        event       = Event,
        resource    = ensure_binary(Resource),
        action      = Action,
        outcome     = Outcome,
        meta        = Meta,
        prev_hash   = <<>>,
        hmac        = <<>>,
        sig         = undefined,
        tsp         = undefined
    },
    case validate(Record) of
        ok -> Record;
        {error, Reason} -> error({invalid_audit_record, Reason})
    end.

%% @doc Validates NIST AU-3 mandatory record fields.
-spec validate(term()) -> ok | {error, term()}.
validate({audit_record, Id, TS, Plane, Subj, Ev, Res, Act, Out, _Meta, _PrevHash, _Hmac, _Sig, _Tsp}) ->
    ValidPlane = Plane =:= security orelse Plane =:= system orelse Plane =:= application,
    ValidOutcome = Out =:= success orelse Out =:= failure,
    if
        not is_binary(Id) orelse byte_size(Id) =:= 0 -> {error, invalid_id};
        not is_integer(TS) orelse TS =< 0 -> {error, invalid_timestamp};
        not ValidPlane -> {error, invalid_plane};
        not is_binary(Subj) -> {error, invalid_subject};
        not is_atom(Ev) -> {error, invalid_event};
        not is_binary(Res) -> {error, invalid_resource};
        not is_atom(Act) -> {error, invalid_action};
        not ValidOutcome -> {error, invalid_outcome};
        true -> ok
    end;
validate(_) ->
    {error, not_a_record}.

%% @doc Deterministic canonical binary encoding of payload for hashing &amp; HMAC.
%% Excludes prev_hash, hmac, sig, and tsp to allow stable hash calculation.
-spec canonical_payload(#audit_record{}) -> binary().
canonical_payload(#audit_record{id = Id, ts = TS, plane = Plane, subject = Subj,
                                event = Ev, resource = Res, action = Act,
                                outcome = Out, meta = Meta}) ->
    PlaneBin = atom_to_binary(Plane, utf8),
    EvBin = atom_to_binary(Ev, utf8),
    ActBin = atom_to_binary(Act, utf8),
    OutBin = atom_to_binary(Out, utf8),
    MetaBin = canonical_meta(Meta),
    <<
        Id/binary,
        TS:64/big,
        PlaneBin/binary,
        Subj/binary,
        EvBin/binary,
        Res/binary,
        ActBin/binary,
        OutBin/binary,
        MetaBin/binary
    >>.

%% @doc Encodes complete record into binary representation for persistence/export.
-spec encode(#audit_record{}) -> binary().
encode(#audit_record{} = R) ->
    term_to_binary(R, [deterministic]).

%% @doc Decodes binary back to #audit_record{}.
-spec decode(binary()) -> {ok, #audit_record{}} | {error, term()}.
decode(Bin) when is_binary(Bin) ->
    try
        Record = binary_to_term(Bin, [safe]),
        case validate(Record) of
            ok -> {ok, Record};
            {error, Reason} -> {error, Reason}
        end
    catch
        _:_ -> {error, invalid_binary}
    end.

%% ===================================================================
%% Internal Helpers
%% ===================================================================

ensure_binary(B) when is_binary(B) -> B;
ensure_binary(L) when is_list(L) -> list_to_binary(L);
ensure_binary(A) when is_atom(A) -> atom_to_binary(A, utf8).

canonical_meta(Meta) when is_map(Meta) ->
    Keys = lists:sort(maps:keys(Meta)),
    Items = [ <<(ensure_binary(K))/binary, ":", (ensure_binary(maps:get(K, Meta)))/binary>> || K <- Keys ],
    iolist_to_binary(Items);
canonical_meta(_) ->
    <<>>.
