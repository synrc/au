-module(audit_sup_tests).
-include_lib("eunit/include/eunit.hrl").

sup_init_test() ->
    {ok, {SupFlags, ChildSpecs}} = audit_sup:init([]),
    ?assertMatch(#{strategy := one_for_one}, SupFlags),
    ?assertEqual(1, length(ChildSpecs)).
