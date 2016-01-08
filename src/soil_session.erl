-module(soil_session).

-export([ 
  get_cookie/2
  ,set_cookie/3
  ,drop_session/1
  ,allow_peer/1
  ,is_authorized/1
  ,s3/2
  ,s3_encode_uri/1
  ,s3_encode_headers/1
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

%%
%% @doc Hands out s3 tickets.
%%
%% -- GET
s3(Type,JsonMap) when Type =:= <<"list">> ->

  %% HTTPMethod
  HTTPMethod = <<"GET">>,

  %% CanonicalURI
  CanonicalURI = s3_encode_uri(<<"/">>),

  %% CanonicalQueryString
  Body = maps:get(<<"body">>,JsonMap),
  Key = maps:get(<<"key">>,Body),
  Prefix = iolist_to_binary([ Key ,<<"/content/">> ]), 
  CanonicalQueryString = iolist_to_binary([
    s3_encode_uri(<<"prefix">>),<<"=">>,s3_encode_uri(Prefix)
    ,s3_encode_uri(<<"delimeter">>),<<"=">>,s3_encode_uri(<<"/">>)
  ]),

  %% CanonicalHeaders & SignedHeaders
  Hostname = soil_utls:get_env(s3_hostname),
  Host = re:replace(Hostname,<<"{{ph1}}">>,<<"drook-users.">>,[{return,binary}]),
  Headers = [
    {<<"host">>,Host}
    ,{<<"x-amz-content-sha256">>,<<"the hash">>}
    ,{<<"x-amz-date">>,<<"20130708T220855Z">>}
  ],
  {SignedHeaders,CanonicalHeaders} = s3_encode_headers(Headers), 

  %% HashedPayload 
  HashedPayload = soil_utls:hash(<<"">>),

  CanonicalRequest = iolist_to_binary([
    HTTPMethod,<<"\n">>
    ,CanonicalURI,<<"\n">>
    ,CanonicalQueryString,<<"\n">>
    ,CanonicalHeaders,<<"\n">>
    ,SignedHeaders,<<"\n">>
    ,HashedPayload
  ]),

  Response = CanonicalRequest,
  {ok,Response};
%% -- POST  
s3(Type,JsonMap) when Type =:= <<"upload">> ->
  Body = maps:get(<<"body">>,JsonMap),
  Key = maps:get(<<"key">>,Body),
  BuketKey = iolist_to_binary([ Key,<<"/content/">> ]),
  % 1) Create Policy map
  NowSecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
  Add15Mins = NowSecs + (15 * 60),
  DateTimeExpires = calendar:gregorian_seconds_to_datetime(Add15Mins),
  ExpiryTime = norm_utls:format_time(DateTimeExpires,'iso8601'),
  ExpiryDate = norm_utls:format_date(DateTimeExpires,'iso8601'),
  Expiration = iolist_to_binary([ExpiryDate,<<"T">>,ExpiryTime,<<"Z">>]),
  Acl = <<"public-read">>,
  PolicyMap = #{
    <<"expiration">> => Expiration
    ,<<"conditions">> => [
      #{ <<"bucket">> => <<"drook-users">> }
      ,[ <<"starts-with">>, <<"$key">>, BuketKey ]
      ,#{ <<"acl">> => Acl }
      %%,#{ <<"success_action_redirect">> => <<"http://drook.net">> }
      ,[ <<"starts-with">>, <<"$Content-Type">>, <<"">> ]
      ,[ <<"content-length-range">>, 0, 1048576 ]
    ]
  },
  %% 2) Base64 encode Policy and generate signature
  PolicyBin = jsx:encode(PolicyMap),
  PolicyBase64 = base64:encode(PolicyBin),
  Secret = soil_utls:get_env(s3_secret),
  Access = soil_utls:get_env(s3_access),
  SignatureRaw = crypto:hmac(sha, Secret, PolicyBase64),
  SignatureBase64 = base64:encode(SignatureRaw),
  Host = soil_utls:get_env(s3_hostname),
  S3UploadsUrl = re:replace(Host,<<"{{ph1}}">>,<<"drook-users.">>,[{return,binary}]),
  ResultMap = #{  
    <<"url">> => S3UploadsUrl
    ,<<"access">> => Access
    ,<<"policy">> => PolicyBase64
    ,<<"signature">> => SignatureBase64
    ,<<"key">> => BuketKey
    ,<<"acl">> => Acl
  },
  {ok,ResultMap};
s3(_Type,_JsonMap) ->
  {error,#{ <<"unauthorised">> => <<"Invalid">> }}.


s3_encode_uri(Data) ->
  Data.

s3_encode_headers(Headers) -> 
  lists:foldl(fun(Elem,Acc) ->
    {Name,Value} = Elem,
    LowercaseName = Name,
    TrimValue = soil_utls:trim_bin(Value),
    Header = iolist_to_binary([ LowercaseName, <<":">>, TrimValue, <<"\n">>]),
    {SignedHeaderAcc,CanonicalHeaderAcc} = Acc,
    Semi = if length(Acc) =:= length(Headers) -> <<"">>; true -> <<";">> end,
    SignedHeader = iolist_to_binary([ SignedHeaderAcc,LowercaseName,Semi ]),
    CanonicalHeader = iolist_to_binary([ CanonicalHeaderAcc,Header ]),
    {SignedHeader,CanonicalHeader}
  end,{<<"">>,<<"">>},Headers).






