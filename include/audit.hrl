-ifndef(AUDIT_HRL).
-define(AUDIT_HRL, true).

-type audit_event() ::
    %% Security Plane Events
    auth_login | auth_logout | auth_failure |
    cert_issue | cert_revoke | key_gen | key_rotate | key_unseal |
    policy_change | privilege_escalation |
    %% System Plane Events
    sys_boot | sys_shutdown | process_spawn | process_exit |
    fs_mount | device_grant | net_bind | config_update |
    %% Application Plane Events
    user_action | data_access | data_mutation |
    session_start | session_stop | api_call |
    atom().

-type audit_action() ::
    create | read | update | delete | execute |
    authenticate | authorize | grant | revoke |
    sign | verify | encrypt | decrypt | unseal | rotate |
    mount | unmount | start | stop |
    atom().

-record(audit_record, {
    id          :: binary(),
    ts          :: integer(),
    plane       :: security | system | application,
    subject     :: binary(),
    event       :: audit_event(),
    resource    :: binary(),
    action      :: audit_action(),
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
