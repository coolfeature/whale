-module(soil_bullet_handler).

-export([init/4]).
-export([stream/3]).
-export([info/3]).
-export([terminate/2]).

-define(GPROC_KEY(Sid),{p,l,Sid}).

%% ------------------------------------------------------------------
%% The process running this code executes effectively the business
%% logic via the norm.erl module. Keep this in mind as the process 
%% is transient and may terminate any time.
%% ------------------------------------------------------------------
%%

init(_Transport, Req, _Opts, Active) ->
  io:fwrite("WEBSOCKET INIT ~p~n",[Active]),
  {Peer,Req1} = cowboy_req:peer(Req),
  {[Sid],Req2} = cowboy_req:path_info(Req1),
  case soil_session:allow_peer(Peer) of
    ok ->
      State = #{ sid => Sid, peer => Peer, active => Active },
      gproc:reg(?GPROC_KEY(Sid),[{map,#{ active => Active }}]),
      {ok, Req2, State};
    stop ->
      {shutdown, Req2, #{}}
  end.
    

stream(Data, Req, #{sid := Sid} = State) ->  
  JsonMap = jsx:decode(Data,[return_maps]),
  HeaderMap = maps:get(<<"header">>,JsonMap,#{}),
  Action = maps:get(<<"action">>,HeaderMap,undefined), 
  soil:handle(Action,JsonMap,?GPROC_KEY(Sid)),
  {ok, Req, State}.

info(Map, Req, State) ->
  Json = jsx:encode(Map),
  {reply, Json, Req, State}.

terminate(_Req, #{ sid := Sid } = _State) ->
  %% ensure unregistered
  gproc:unreg(?GPROC_KEY(Sid)),
  ok.


