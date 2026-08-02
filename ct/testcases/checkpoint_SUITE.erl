-module(checkpoint_SUITE).
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include("audit.hrl").

all() ->
    [
        test_checkpoint_generation_and_export
    ].

init_per_suite(Config) ->
    {PubKey, PrivKey} = audit_crypto:generate_keypair(),
    [{sec_pub, PubKey}, {sec_priv, PrivKey} | Config].

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    PubKey = ?config(sec_pub, Config),
    PrivKey = ?config(sec_priv, Config),
    {ok, _Pid} = audit_core:start_link(#{
        node_id => <<"ct-checkpoint-node">>,
        sec_keypair => {PubKey, PrivKey}
    }),
    Config.

end_per_testcase(_TC, _Config) ->
    catch audit_core:stop(),
    ok.

test_checkpoint_generation_and_export(Config) ->
    PubKey = ?config(sec_pub, Config),
    ok = audit_client:log(application, <<"u1">>, op1, <<"r1">>, act1, success, #{}),
    ok = audit_client:log(system, <<"u2">>, op2, <<"r2">>, act2, success, #{}),

    CP = audit_core:get_checkpoint(),
    2 = CP#audit_checkpoint.record_count,
    true = audit_checkpoint:verify(CP, PubKey),

    Records = audit_core:get_records(),
    ArchiveBin = audit_archive:serialize_archive(Records, CP),
    {ok, DeserializedCP, DeserializedRecs} = audit_archive:deserialize_archive(ArchiveBin),
    CP = DeserializedCP,
    Records = DeserializedRecs,

    JSON = audit_export:to_json(Records),
    true = (is_binary(JSON) andalso byte_size(JSON) > 0),

    SIEM = audit_export:to_siem(hd(Records)),
    true = (is_binary(SIEM) andalso byte_size(SIEM) > 0).
