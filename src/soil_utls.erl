-module(soil_utls).

-export([
  root_dir/0
  ,priv_dir/0
  ,etc_dir/0

  ,get_value/3
  
  ,get_env/1
  ,get_env/2
  
  ,random/0

  ,timestamp/0
  ,datetime_to_timestamp/1
  ,datetime_to_timestamp/2
  ,format_date/1
  ,format_datetime/1

  ,pad/3
  ,home_key_hash/1

  ,trim_bin/1
  ,to_hex/1
  ,hex/1
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

get_env(s3_secret) ->
  list_to_binary(os:getenv("DROOK_S3_SECRET_KEY"));
get_env(s3_access) ->
  list_to_binary(os:getenv("DROOK_S3_ACCESS_KEY_ID"));
get_env(Key) ->
  case application:get_env(soil, Key) of
    {ok,Val} -> Val;
    _ -> undefined
  end.
  
get_env(Section,Key) ->
  SectionConf = get_env(Section),
  get_value(Key,SectionConf,undefined).


timestamp() ->
  datetime_to_timestamp(calendar:universal_time(),return_integer).

datetime_to_timestamp(DateTime) ->
  Seconds = calendar:datetime_to_gregorian_seconds(DateTime) - 62167219200,
  {Seconds div 1000000, Seconds rem 1000000, 0}.
datetime_to_timestamp(DateTime,return_integer) ->
  {S,SS,_O} = datetime_to_timestamp(DateTime),
  S + SS;
datetime_to_timestamp(DateTime,return_binary) ->
  {S,SS,_O} = datetime_to_timestamp(DateTime),
  list_to_binary(integer_to_list(S) ++ integer_to_list(SS)).

format_date(DateTime) ->
  format_date(DateTime,'iso8601').

format_date(DateTime,Format) ->
  norm_utls:format_date(DateTime,Format).

format_datetime(DateTime) ->
  format_datetime(DateTime,'iso8601').

format_datetime(DateTime,Format) ->
  ExpiryTime = norm_utls:format_time(DateTime,Format),
  ExpiryDate = format_date(DateTime,Format),
  iolist_to_binary([ExpiryDate,<<"T">>,ExpiryTime,<<"Z">>]).

%%------------------------------------------------------------------------------
%% @doc Format an integer with a padding of zeroes
%% @end
%%------------------------------------------------------------------------------
-spec pad(Number :: integer(),Padding :: integer(),Char :: integer()) -> iodata().

pad(Number, Padding, Char) when Number < 0 ->
  [$- | pad(-Number, Padding - 1, Char)];
pad(Number, Padding, Char) ->
  NumberStr = integer_to_list(Number),
  ZeroesNeeded = max(Padding - length(NumberStr), 0),
  String = [lists:duplicate(ZeroesNeeded, Char), NumberStr],
  iolist_to_binary(String).

home_key_hash(UserId) ->
  base64url:encode(crypto:hash(sha256,pad(UserId,10,$0))).

trim_bin(Bin) ->
  re:replace(Bin, "^\\s+|\\s+$", "", [{return, binary}, global]).

%% ============================================================================
%% ============================== HEX UTLS ====================================
%% ============================================================================

%% @type iolist() = [char() | binary() | iolist()]
%% @type iodata() = iolist() | binary()

%% @spec to_hex(integer | iolist()) -> string()
%% @doc Convert an iolist to a hexadecimal string.
to_hex(0) ->
    "0";
to_hex(I) when is_integer(I), I > 0 ->
    to_hex_int(I, []).

%% @spec hexdigit(integer()) -> char()
%% @doc Convert an integer less than 16 to a hex digit.
hexdigit(C) when C >= 0, C =< 9 ->
    C + $0;
hexdigit(C) when C =< 15 ->
    C + $a - 10.

%% Internal API

to_hex_int(0, Acc) ->
    Acc;
to_hex_int(I, Acc) ->
    to_hex_int(I bsr 4, [hexdigit(I band 15) | Acc]).


%% ============================================================================
%%
%%
hex(Binary) when is_binary(Binary) ->
  String = lists:flatten(lists:map(
    fun(X) -> io_lib:format("~2.16.0b", [X]) end, 
  binary_to_list(Binary))),
  list_to_binary(String).

