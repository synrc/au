-module(audit_test_lib).
-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

fresh_keypair() ->
    audit_crypto:generate_keypair().

fresh_mac_key() ->
    audit_crypto:generate_mac_key().

sample_record(Plane, Subject, Event) ->
    audit_record:new(Plane, Subject, Event, <<"res-1">>, action_test, success, #{<<"seat">> => <<"s1">>}).
