-module(soil).

-export([
  handle/3
  ,reply/4
  ,sessions/0
  ,get_qid/1
]).

%% ------------------------------------------------------------------

handle(Action,JsonMap,Key) when Action =:= <<"login">> ->
  io:fwrite("Login: ~p ~p ~n",[JsonMap,Key]),
  timer:sleep(5000),
  User = maps:get(<<"body">>,JsonMap),
  Email = maps:get(<<"email">>,User),
  Find = norm:find(<<"user">>,#{ <<"where">> => [{ <<"email">>,'=',Email}] }),
  io:fwrite("~p ~n",[Find]),
  R = #{ <<"authenticated">> => false },
  Reply = if Find =:= [] -> R;
    true ->
      [Entry] = Find,
      JsonPass = maps:get(<<"password">>,User), 
      DbPass = maps:get(<<"password">>,Entry),
      if JsonPass =:= DbPass ->
        R2 = maps:update(<<"authenticated">>,true,R),
	UserId = maps:get(<<"id">>,Entry),
	[Customer] = norm:find(<<"customer">>,#{ <<"where">> => [{ <<"user_id">>,'=',UserId}] }),
	Fname = maps:get(<<"fname">>,Customer),
	Lname = maps:get(<<"lname">>,Customer),
	Name = #{ <<"fname">> => Fname, <<"lname">> => Lname },
	R3 = maps:put(<<"customer">>,Name,R2),
	R4 = maps:put(<<"email">>,Email,R3), 
	Cid = maps:get(<<"id">>,Customer),
	JwtPayload = #{ <<"cid">> => Cid },
	Jwt = soil_utls:get_env(jwt),
        Token = jwt:encode(JwtPayload,Jwt),
	maps:put(<<"token">>,Token,R4);
      true -> R end
    end,
  reply(Action,Reply,JsonMap,Key);
  
handle(Action,JsonMap,Key) when Action =:= <<"register">> ->
  io:fwrite("Register: ~p ~p ~n",[JsonMap,Key]),
  timer:sleep(5000),
  Body = maps:get(<<"body">>,JsonMap),
  User = maps:get(<<"user">>,Body),
  Customer = maps:get(<<"customer">>,Body),
  R = #{ <<"registered">> => false },
  Reply = try
    {ok,start} = norm_pgsql:transaction(),
    {ok,UserId} = norm:save(User),
    CustomerAddUserId = maps:put(<<"user_id">>,UserId,Customer),
    {ok,CustomerId} = norm:save(CustomerAddUserId), 
    {ok,commit} = norm_pgsql:commit(),
    io:fwrite("Norm save: ~p ~p ~n",[UserId,CustomerId]),
    maps:update(<<"registered">>,true,R)
  catch _Error:Reason ->
    norm_pgsql:rollback(),
    io:fwrite("Rolling back: ~p ~n",[Reason]),R
  end,
  reply(Action,Reply,JsonMap,Key);
 
handle(undefined,JsonMap,_Sid) ->
  io:fwrite("UNDEFINED ACTION: ~p~n",[JsonMap]),
  ok.

reply(Action,Body,JsonMap,Key) ->
  Reply = #{ 
    <<"header">> => #{ <<"type">> => Action, <<"qid">> => get_qid(JsonMap) }
    , <<"body">> => Body 
  },
  gproc:send(Key,Reply).
 
%% ------------------------------------------------------------------

sessions() ->
  List = gproc:select([{{'_', '_', '_'},[],['$$']}]),
  lists:foldl(fun(Elem,Acc) ->
    [Key,_Pid1,_Pid2] = Elem,
    {_,_,Sid} = Key,
    Acc ++ [[{sid,Sid},{properties,gproc:get_attribute(Key,map)}]]
  end,[],List).

get_qid(JsonMap) ->
  HeaderMap = maps:get(<<"header">>,JsonMap,#{}),
  maps:get(<<"qid">>,HeaderMap,0). 


