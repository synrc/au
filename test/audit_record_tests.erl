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

validation_error_cases_test() ->
    R = audit_record:new(security, <<"user">>, ev, <<"res">>, act, success, #{}),
    ?assertEqual({error, invalid_id}, audit_record:validate(R#audit_record{id = <<>>})),
    ?assertEqual({error, invalid_timestamp}, audit_record:validate(R#audit_record{ts = 0})),
    ?assertEqual({error, invalid_plane}, audit_record:validate(R#audit_record{plane = bad_plane})),
    ?assertEqual({error, invalid_subject}, audit_record:validate(R#audit_record{subject = 123})),
    ?assertEqual({error, invalid_event}, audit_record:validate(R#audit_record{event = <<"not_an_atom">>})),
    ?assertEqual({error, invalid_resource}, audit_record:validate(R#audit_record{resource = 123})),
    ?assertEqual({error, invalid_action}, audit_record:validate(R#audit_record{action = <<"not_an_atom">>})),
    ?assertEqual({error, invalid_outcome}, audit_record:validate(R#audit_record{outcome = unknown})),
    ?assertEqual({error, not_a_record}, audit_record:validate(not_a_record)),
    ?assertEqual({error, invalid_binary}, audit_record:decode(<<"corrupt">>)),

    R2 = audit_record:new(security, "string_subject", ev, atom_resource, act, success, not_a_map),
    ?assertEqual(<<"string_subject">>, R2#audit_record.subject),
    ?assertEqual(<<"atom_resource">>, R2#audit_record.resource),

    PayloadNonMap = audit_record:canonical_payload(R2#audit_record{meta = undefined}),
    ?assert(is_binary(PayloadNonMap)).
