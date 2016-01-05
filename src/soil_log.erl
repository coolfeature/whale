-module(soil_log).

-export([
  log/1
  ,log/2
]).

log(Msg) ->
  io:fwrite("~p ~n",[Msg]).

log(Msg,Args) ->
  io:fwrite(Msg,Args).

