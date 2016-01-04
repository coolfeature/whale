-module(soil_log).

-export([
  log/1
]).

log(Msg) ->
  io:fwrite("~p ~n",[Msg]).

