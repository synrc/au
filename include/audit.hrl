-ifndef(AUDIT_HRL).
-define(AUDIT_HRL, true).

-record(audit_record, {
    id          :: binary(),
    ts          :: integer(),
    plane       :: security | system | application,
    subject     :: binary(),
    event       :: atom(),
    resource    :: binary(),
    action      :: atom(),
    outcome     :: success | failure,
    meta = #{}  :: map(),
    prev_hash   :: binary(),
    hmac        :: binary(),
    sig         :: binary() | undefined,
    tsp         :: binary() | undefined
}).

-record(audit_checkpoint, {
    node_id      :: binary(),
    from_id      :: binary(),
    to_id        :: binary(),
    head_hash    :: binary(),
    record_count :: non_neg_integer(),
    merkle_root  :: binary(),
    sig          :: binary() | undefined,
    tsp          :: binary() | undefined
}).

-type audit_record() :: #audit_record{}.
-type audit_checkpoint() :: #audit_checkpoint{}.

-endif.
