-module(soil_session).

-export([ 
  get_cookie/2
  ,set_cookie/3
  ,drop_session/1
  ,allow_peer/1
  ,is_authorized/1
]).

get_cookie(Req,Name) ->
  {Path, Req1} = cowboy_req:path(Req),
  {Cookie, Req2} = cowboy_req:cookie(Name, Req1),
  {Cookie, Path, Req2}.
 
set_cookie(Req,Name,Value) ->
  cowboy_req:set_resp_cookie(Name,Value,[{path, <<"/">>}],Req).
 
drop_session(Req) ->
  cowboy_req:set_resp_header(<<"Set-Cookie">>,<<"COOKIE=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/">>, Req).

allow_peer(_Peer) -> 
  ok.
%%
%% @doc Checks the integrity of the session
%%
is_authorized(JsonMap) ->
  BodyMap = maps:get(<<"body">>,JsonMap,<<"">>),
  Token = maps:get(<<"token">>,BodyMap,<<"">>),
  case Token of
    <<"">> -> {error,<<"Token missing">>};
    T when is_binary(T) -> 
      Key = soil_utls:get_env(jwt), 
      case jwt:decode(Token,Key) of 
        error -> {error, <<"Tampered Token">>};
        Payload -> 
	  %% @TODO: Expire on timestamp
	  {ok,Payload}
      end;
    _ ->
      {error,<<"Unexpected value">>}
  end.

