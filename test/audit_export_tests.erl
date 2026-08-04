-module(audit_export_tests).
-include_lib("eunit/include/eunit.hrl").
-include("audit.hrl").

export_test() ->
    MacKey = audit_crypto:generate_mac_key(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 0),

    R1 = audit_chain:append_record(audit_record:new(system, <<"subj1">>, ev1, <<"res1">>, act1, success, #{}), Genesis, MacKey),
    CP = audit_checkpoint:create(<<"node-1">>, [R1], R1#audit_record.prev_hash, undefined),

    JSONSingle = audit_export:to_json(R1),
    ?assert(is_binary(JSONSingle)),

    JSONList = audit_export:to_json([R1]),
    ?assert(is_binary(JSONList)),

    SIEM = audit_export:to_siem(R1),
    ?assert(is_binary(SIEM)),

    Oscal = audit_export:to_oscal(CP, [R1]),
    ?assert(is_map(Oscal)),

    RNoSig = R1#audit_record{sig = undefined},
    JSONNoSig = audit_export:to_json(RNoSig),
    ?assert(is_binary(JSONNoSig)),

    ?assertEqual(<<"">>, audit_export:binary_to_hex(undefined)),
    ?assertEqual(<<"">>, audit_export:binary_to_hex(<<>>)).

secure_stream_test() ->
    EncKey = audit_crypto:generate_enc_key(),
    MacKey = audit_crypto:generate_mac_key(),
    Genesis = audit_chain:genesis_hash(<<"node-1">>, 0),
    R1 = audit_chain:append_record(audit_record:new(system, <<"subj1">>, ev1, <<"res1">>, act1, success, #{}), Genesis, MacKey),

    Stream = audit_export:to_secure_stream([R1], EncKey),
    ?assert(is_binary(Stream)),

    {ok, JsonText} = audit_export:from_secure_stream(Stream, EncKey),
    ?assert(is_binary(JsonText)),

    WrongKey = audit_crypto:generate_enc_key(),
    ?assertEqual({error, invalid_tag}, audit_export:from_secure_stream(Stream, WrongKey)),
    ?assertEqual({error, invalid_stream_format}, audit_export:from_secure_stream(term_to_binary({bad_stream}), EncKey)),
    ?assertEqual({error, corrupt_stream_binary}, audit_export:from_secure_stream(<<"invalid_bin">>, EncKey)).
