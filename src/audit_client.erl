-module(audit_client).
-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Submits a standard audit event from Application plane.
-spec log(binary(), atom(), binary(), atom(), success | failure, map()) -> ok | {error, term()}.
log(Subject, Event, Resource, Action, Outcome, Meta) ->
    log(application, Subject, Event, Resource, Action, Outcome, Meta).

%% @doc Submits an audit event for a specified plane.
-spec log(Plane, Subject, Event, Resource, Action, Outcome, Meta) -> ok | {error, term()} when
    Plane :: security | system | application,
    Subject :: binary(),
    Event :: atom(),
    Resource :: binary(),
    Action :: atom(),
    Outcome :: success | failure,
    Meta :: map().
log(Plane, Subject, Event, Resource, Action, Outcome, Meta) ->
    Record = audit_record:new(Plane, Subject, Event, Resource, Action, Outcome, Meta),
    audit_core:log_event(Record).

%% @doc Submits a critical audit event requiring Security Admin signature.
-spec log_critical(Plane, Subject, Event, Resource, Action, Outcome, Meta) -> ok | {error, term()} when
    Plane :: security | system | application,
    Subject :: binary(),
    Event :: atom(),
    Resource :: binary(),
    Action :: atom(),
    Outcome :: success | failure,
    Meta :: map().
log_critical(Plane, Subject, Event, Resource, Action, Outcome, Meta) ->
    Record = audit_record:new(Plane, Subject, Event, Resource, Action, Outcome, Meta),
    audit_core:log_critical_event(Record).
