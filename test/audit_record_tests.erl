-module(audit_record_tests).
-include_lib("eunit/include/eunit.hrl").
-include("audit.hrl").

new_record_validation_test() ->
    R = audit_record:new(security, <<"user1">>, cert_issue, <<"cert-42">>, issue, success, #{<<"ip">> => <<"10.0.0.1">>}),
    ?assertEqual(security, R#audit_record.plane),
    ?assertEqual(<<"user1">>, R#audit_record.subject),
    ?assertEqual(cert_issue, R#audit_record.event),
    ?assertEqual(ok, audit_record:validate(R)).

invalid_record_plane_test() ->
    ?assertError({invalid_audit_record, invalid_plane},
                 audit_record:new(invalid_plane, <<"u">>, ev, <<"r">>, act, success, #{})).

encode_decode_test() ->
    R = audit_record:new(application, <<"app-sec">>, login, <<"session-1">>, create, success, #{}),
    Encoded = audit_record:encode(R),
    ?assert(is_binary(Encoded)),
    {ok, Decoded} = audit_record:decode(Encoded),
    ?assertEqual(R, Decoded).

canonical_payload_determinism_test() ->
    R1 = audit_record:new(system, <<"sys">>, mount, <<"/dev/sda">>, mount, success, #{<<"a">> => <<"1">>, <<"b">> => <<"2">>}),
    R2 = R1#audit_record{meta = #{<<"b">> => <<"2">>, <<"a">> => <<"1">>}},
    Payload1 = audit_record:canonical_payload(R1),
    Payload2 = audit_record:canonical_payload(R2),
    ?assertEqual(Payload1, Payload2).
