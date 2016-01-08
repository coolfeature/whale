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

  ,pad/3
  ,hash/1
  ,setup_s3/0
  ,home_key_hash/1

  ,trim_bin/1
  ,to_hex/1
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

setup_s3() ->
  S3AKID = get_env(s3_access),
  S3SK = get_env(s3_secret),
  Host = get_env(s3_hostname),
  Hostname = re:replace(Host,<<"{{ph1}}">>,<<"">>,[{return,binary}]),
  erlcloud_s3:configure(S3AKID, S3SK, Hostname).

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

hash(Msg) ->
  <<X:256/big-unsigned-integer>> = crypto:hash(sha256,Msg),
  list_to_binary(integer_to_list(X, 16)).

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
    <<"0">>;
to_hex(I) when is_integer(I), I > 0 ->
    to_hex_int(I, []);
to_hex(B) ->
    to_hex(iolist_to_binary(B), []).

%% @spec to_bin(string()) -> binary()
%% @doc Convert a hexadecimal string to a binary.
to_bin(L) ->
    to_bin(L, []).

%% @spec to_int(string()) -> integer()
%% @doc Convert a hexadecimal string to an integer.
to_int(L) ->
    erlang:list_to_integer(L, 16).

%% @spec dehex(char()) -> integer()
%% @doc Convert a hex digit to its integer value.
dehex(C) when C >= $0, C =< $9 ->
    C - $0;
dehex(C) when C >= $a, C =< $f ->
    C - $a + 10;
dehex(C) when C >= $A, C =< $F ->
    C - $A + 10.

%% @spec hexdigit(integer()) -> char()
%% @doc Convert an integer less than 16 to a hex digit.
hexdigit(C) when C >= 0, C =< 9 ->
    C + $0;
hexdigit(C) when C =< 15 ->
    C + $a - 10.

%% Internal API

to_hex(<<>>, Acc) ->
    lists:reverse(Acc);
to_hex(<<C1:4, C2:4, Rest/binary>>, Acc) ->
    to_hex(Rest, [hexdigit(C2), hexdigit(C1) | Acc]).

to_hex_int(0, Acc) ->
    Acc;
to_hex_int(I, Acc) ->
    to_hex_int(I bsr 4, [hexdigit(I band 15) | Acc]).
to_bin([], Acc) ->
    iolist_to_binary(lists:reverse(Acc));
to_bin([C1, C2 | Rest], Acc) ->
    to_bin(Rest, [(dehex(C1) bsl 4) bor dehex(C2) | Acc]).


