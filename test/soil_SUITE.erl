-module(soil_SUITE).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

begin_test() ->
  norm_app:ensure_started(soil).
