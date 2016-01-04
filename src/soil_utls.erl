-module(soil_utls).

-export([
  root_dir/0
  ,priv_dir/0
  ,etc_dir/0

  ,get_value/3
  
  ,get_env/1
  ,get_env/2
  
  ,random/0

  ,format_with_padding/2
  ,datetime_to_timestamp/1
  ,datetime_to_timestamp/2
]).

random() ->
  {N1,N2,N3} = os:timestamp(),
  N1b = integer_to_binary(N1),
  N2b = integer_to_binary(N2),
  N3b = integer_to_binary(N3),
  <<N1b/binary,N2b/binary,N3b/binary>>.

root_dir() ->
  {ok,Path} = file:get_cwd(),
  Path.

priv_dir() ->
  filename:join(?MODULE:root_dir(), "priv").

etc_dir() ->
  filename:join(?MODULE:root_dir(), "etc").

get_value(Key, Opts, Default) ->
  case lists:keyfind(Key, 1, Opts) of
    {_, Value} -> Value;
    _ -> Default
  end.

get_env(aws_s3) ->
  S3AKID = list_to_binary(os:getenv("DROOK_S3_ACCESS_KEY_ID")),
  S3SK = list_to_binary(os:getenv("DROOK_S3_SECRET_KEY")),
  if S3AKID /= false andalso S3SK /= false ->
    {ok,#{ <<"access">> => S3AKID, <<"secret">> => S3SK }};
  true -> undefined end;
get_env(Key) ->
  case application:get_env(soil, Key) of
    {ok,Val} -> Val;
    _ -> undefined
  end.
  
get_env(Section,Key) ->
  SectionConf = get_env(Section),
  get_value(Key,SectionConf,undefined).

%%------------------------------------------------------------------------------
%% @doc Format an integer with a padding of zeroes
%% @end
%%------------------------------------------------------------------------------
-spec format_with_padding(Number :: integer(),Padding :: integer()) -> iodata().

format_with_padding(Number, Padding) when Number < 0 ->
  [$- | format_with_padding(-Number, Padding - 1)];
format_with_padding(Number, Padding) ->
  NumberStr = integer_to_list(Number),
  ZeroesNeeded = max(Padding - length(NumberStr), 0),
  String = [lists:duplicate(ZeroesNeeded, $0), NumberStr],
  iolist_to_binary(String).

datetime_to_timestamp(DateTime) ->
  Seconds = calendar:datetime_to_gregorian_seconds(DateTime) - 62167219200,
  {Seconds div 1000000, Seconds rem 1000000, 0}.
datetime_to_timestamp(DateTime,return_integer) ->
  {S,SS,_O} = datetime_to_timestamp(DateTime),
  S + SS;
datetime_to_timestamp(DateTime,return_binary) ->
  {S,SS,_O} = datetime_to_timestamp(DateTime),
  list_to_binary(integer_to_list(S) ++ integer_to_list(SS)).

