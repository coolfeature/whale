-module(soil_session).

-export([ 
  get_cookie/2
  ,set_cookie/3
  ,drop_session/1
  ,allow_peer/1
  ,is_authorized/1
  ,s3_policy/2
  ,s3/2
  ,s3_canonical_uri/1
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
        Payload -> {ok,Payload}
      end;
    _ ->
      {error,<<"Unexpected value">>}
  end.

%%
%% @doc Hands out s3 tickets.
%%
s3(Verb,BodyMap) when Verb =:= <<"GET">> ->
  ResourcePath = maps:get(<<"path">>,BodyMap),
  Headers = maps:get(<<"headers">>,BodyMap),
  {CanonicalHeaders,SignedHeaders} = s3_canonical_headers(Headers),
  <<X:256/big-unsigned-integer>> = crypto:hash(sha256,<<"">>),
  HashedPayload = list_to_binary(integer_to_list(X, 16)),
  iolist_to_binary([
    Verb,<<"\n">>
    ,s3_canonical_uri(ResourcePath),<<"\n">>
    ,CanonicalHeaders,<<"\n">>
    ,SignedHeaders,<<"\n">>
    ,HashedPayload
  ]);  
s3(Verb,_BodyMap) when Verb =:= <<"POST">> ->
  #{};
s3(_Verb,_BodyMap) ->
  #{ <<"unauthorised">> => <<"Invalid">> }.



s3_canonical_uri(Data) ->
  Data.

s3_canonical_headers(Headers) ->
  
  SignedHeaders = Headers,
  {Headers,SignedHeaders}.

s3_policy(Customer,DateTimeExpires) ->
  case soil_utls:get_env(aws_s3) of
    {ok,AwsMap} ->
      case maps:get(<<"user_id">>,Customer) of
        UserId when is_integer(UserId) ->
	  PaddedUserId = soil_utls:format_with_padding(UserId,10),
	  BuketKey = iolist_to_binary([ PaddedUserId,<<"/">> ]),
          % 1) Create Policy map
          ExpirationTime = norm_utls:format_time(DateTimeExpires,'iso8601'),
          ExpirationDate = norm_utls:format_date(DateTimeExpires,'iso8601'),
          Expiration = iolist_to_binary([ExpirationDate,<<"T">>,ExpirationTime,<<"Z">>]),
          PolicyMap = #{
            <<"expiration">> => Expiration
            ,<<"conditions">> => [
              #{ <<"bucket">> => <<"drook-users">> }
              ,[ <<"starts-with">>, <<"$key">>, BuketKey ]
              ,#{ <<"acl">> => <<"private">> }
              %%,#{ <<"success_action_redirect">> => <<"http://drook.net">> }
              ,[ <<"starts-with">>, <<"$Content-Type">>, <<"">> ]
              ,[ <<"content-length-range">>, 0, 1048576 ]
            ]
          },
          % 2) Base64 encode Policy and generate signature
          PolicyBin = jsx:encode(PolicyMap),
          PolicyBase64 = base64:encode(PolicyBin),
          Secret = maps:get(<<"secret">>,AwsMap),
          Access = maps:get(<<"access">>,AwsMap),
          SignatureRaw = crypto:hmac(sha, Secret, PolicyBase64),
          SignatureBase64 = base64:encode(SignatureRaw),
          S3UploadsUrl = soil_utls:get_env(s3_uploads_url),
          ResultMap = #{  
            <<"url">> => S3UploadsUrl
            ,<<"access">> => Access
            ,<<"policy">> => PolicyBase64
            ,<<"signature">> => SignatureBase64
	    ,<<"key">> => BuketKey
          },
          {ok,ResultMap};
        _Error ->
          ErrorMap = #{ <<"unauthorised">> => <<"Unable to progress">> },
          {error,ErrorMap}
      end;
    undefined -> 
      ErrorMap = #{ <<"unauthorised">> => <<"Unable to proceed">> },
      {error,ErrorMap}
  end.

