-module(soil).

-export([
  handle/3
  ,reply/4
  ,sessions/0
  ,get_qid/1
]).

%% ------------------------------------------------------------------
%%
%%  Signs user in
%%
handle(Action,JsonMap,Key) when Action =:= <<"login">> ->
  soil_log:log("Login: ~p ~p ~n",[JsonMap,Key]),
  timer:sleep(2000),
  User = maps:get(<<"body">>,JsonMap),
  Email = maps:get(<<"email">>,User),
  Find = norm:find(<<"user">>,#{ <<"where">> => [{ <<"email">>,'=',Email}] }),
  soil_log:log("~p ~n",[Find]),
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
        HomeKey = maps:get(<<"home_key">>,Customer),
	R5 = maps:put(<<"key">>,HomeKey,R4), 
	Cid = maps:get(<<"id">>,Customer),
	JwtPayload = #{ 
          <<"customer_id">> => Cid
          , <<"timestamp">> => soil_utls:timestamp() 
        },
	Jwt = soil_utls:get_env(jwt),
        Token = jwt:encode(JwtPayload,Jwt),
	maps:put(<<"token">>,Token,R5);
      true -> R end
    end,
  reply(Action,Reply,JsonMap,Key);

%%
%% Registers new users
%%
 
handle(Action,JsonMap,Key) when Action =:= <<"register">> ->
  soil_log:log("Register: ~p ~p ~n",[JsonMap,Key]),
  timer:sleep(2000),
  Body = maps:get(<<"body">>,JsonMap),
  User = maps:get(<<"user">>,Body),
  Customer = maps:get(<<"customer">>,Body),
  R = #{ <<"registered">> => false },
  Reply = try
    {ok,start} = norm_pgsql:transaction(),
    {ok,UserId} = norm:save(User),
    Email = maps:get(<<"email">>,User),
    CustomerAddEmail = maps:put(<<"email">>,Email,Customer),
    CustomerAddUserId = maps:put(<<"user_id">>,UserId,CustomerAddEmail),
    HomeKey = soil_utls:home_key_hash(UserId),
    CustomerAddHomeKey = maps:put(<<"home_key">>,HomeKey,CustomerAddUserId),
    {ok,_CustomerId} = norm:save(CustomerAddHomeKey), 
    {ok,commit} = norm_pgsql:commit(),
    maps:update(<<"registered">>,true,R)
  catch _Error:Reason ->
    norm_pgsql:rollback(),
    soil_log:log("Rolling back: ~p ~n",[Reason]),R
  end,
  reply(Action,Reply,JsonMap,Key);
 
%%
%% Hands out s3 authorizations
%%
handle(Action,JsonMap,Key) when Action =:= <<"s3">> ->
  Reply = case soil_session:is_authorized(JsonMap) of
    {ok,_Decoded} -> 
      Body = maps:get(<<"body">>,JsonMap),
      Type = maps:get(<<"type">>,Body),
      case soil_s3:s3(Type,JsonMap) of
	{ok,Response} -> Response;
	{error,Msg} -> Msg
      end;
    {error,Msg} -> 
      #{ <<"unauthorised">> => Msg }  
  end,
  reply(Action,Reply,JsonMap,Key);

handle(undefined,JsonMap,_Sid) ->
  io:fwrite("UNDEFINED ACTION: ~p~n",[JsonMap]),
  ok.

%% ============================================================================
%%
%%

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


