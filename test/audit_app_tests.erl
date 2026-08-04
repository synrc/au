-module(audit_app_tests).
-include_lib("eunit/include/eunit.hrl").

app_lifecycle_test() ->
    _ = application:start(crypto),
    _ = application:stop(au),
    ?assertEqual(ok, application:start(au)),
    ?assertEqual(ok, application:stop(au)).
