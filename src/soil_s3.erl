%%
%%
%% @author IONAS SOFTWARE LTD
%%
-module(soil_s3).

-export([ 
  s3/2
  ,s3_host/0
  ,s3_host/1
  ,s3_encode_uri/1
  ,s3_encode_uri/2
  ,s3_encode_headers/1
]).

-define(S3_HOSTNAME,<<"http://{{bucket}}s3-{{region}}amazonaws.com">>).
-define(S3_REGION,<<"eu-west-1">>).
-define(S3_USER_BUCKET,<<"drook-users">>).

-include_lib("eunit/include/eunit.hrl").

%%
%% 
%%
%%

s3_host() ->
  Host = re:replace(?S3_HOSTNAME,<<"{{bucket}}">>,<<"">>,[{return,binary}]),
  re:replace(Host,<<"{{region}}">>,<<"">>,[{return,binary}]). 
s3_host(_Type) ->
  Bucket = iolist_to_binary([ ?S3_USER_BUCKET,<<".">> ]),
  Region = iolist_to_binary([ ?S3_REGION,<<".">> ]),
  Host = re:replace(?S3_HOSTNAME,<<"{{bucket}}">>,Bucket,[{return,binary}]),
  re:replace(Host,<<"{{region}}">>,Region,[{return,binary}]).

%%
%% @doc Hands out s3 tickets.
%%
%% -- GET
s3(Type,JsonMap) when Type =:= <<"list">> -> 
  RequestMap = s3_authorization(Type,JsonMap),
  {ok,RequestMap};
%% -- POST  
s3(Type,JsonMap) when Type =:= <<"upload">> ->
  Body = maps:get(<<"body">>,JsonMap),
  Key = maps:get(<<"key">>,Body),
  BuketKey = iolist_to_binary([ Key,<<"/content/">> ]),
  % 1) Create Policy map
  NowSecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
  Add15Mins = NowSecs + (15 * 60),
  DateTimeExpires = calendar:gregorian_seconds_to_datetime(Add15Mins),
  Expiration = remove_separators(soil_utls:format_datetime(DateTimeExpires)),
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
  S3UploadsUrl = s3_host(Type),
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

%%
%% @private 
%%
%%

s3_authorization(Type,JsonMap) when Type =:= <<"list">> ->
  Body = maps:get(<<"body">>,JsonMap),
  Key = maps:get(<<"key">>,Body),
  Prefix = iolist_to_binary([ Key ,<<"/content/">> ]), 
  Query = [
    { <<"delimeter">>, <<"/">>}
    ,{<<"prefix">>,Prefix }
  ],
  DateTime = calendar:universal_time(),
  Access = soil_utls:get_env(s3_access),
  Secret = soil_utls:get_env(s3_secret),
  ParamMap = #{
    <<"Method">> => <<"GET">>
    ,<<"URI">> => <<"/">>
    ,<<"Host">> => s3_host(Type)
    ,<<"Query">> => Query
    ,<<"Payload">> => <<"">>
    ,<<"Region">> => ?S3_REGION
    ,<<"Service">> => <<"s3">>
    ,<<"DateTime">> => DateTime
    ,<<"Access">> => Access
    ,<<"Secret">> => Secret
  }, 
  s3_authorization(ParamMap).

%%
%% @private 
%% @doc Generates a Signature which is valid for 7 days
%% @see http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
%%

s3_authorization(ParamMap) when is_map(ParamMap) ->

  %% HTTPMethod
  HTTPMethod = maps:get(<<"Method">>,ParamMap),

  %% CanonicalURI
  URI = maps:get(<<"URI">>,ParamMap),
  CanonicalURI = s3_encode_uri(URI),

  %% CanonicalQueryString
  Query = maps:get(<<"Query">>,ParamMap),
  CanonicalQueryString = s3_encode_query_string(Query),
  %% HashedPayload
  Payload = maps:get(<<"Payload">>,ParamMap),
  HashedPayload = hash(Payload),

  %% CanonicalHeaders & SignedHeaders
  Host = maps:get(<<"Host">>,ParamMap),
  DateTime = maps:get(<<"DateTime">>,ParamMap),
  DateTimeISO8601 = soil_utls:format_datetime(DateTime),
  DateTimeS3 = remove_separators(DateTimeISO8601),
  Headers = [
    {<<"Host">>,Host}
    ,{<<"x-amz-content-sha256">>,HashedPayload}
    ,{<<"x-amz-date">>,DateTimeS3}
  ],

  {SignedHeaders,CanonicalHeaders} = s3_encode_headers(Headers), 

  CanonicalRequest = iolist_to_binary([
    HTTPMethod,<<"\n">>
    ,CanonicalURI,<<"\n">>
    ,CanonicalQueryString,<<"\n">>
    ,CanonicalHeaders,<<"\n">>
    ,SignedHeaders,<<"\n">>
    ,HashedPayload
  ]),

  %% String to Sign
  CanonicalRequestHash = hash(CanonicalRequest),

  Aws4Req = <<"aws4_request">>,
  Date = remove_separators(soil_utls:format_date(DateTime)),
  Region = maps:get(<<"Region">>,ParamMap),
  Service = maps:get(<<"Service">>,ParamMap),
  Scope = iolist_to_binary([Date,<<"/">>,Region,<<"/">>,Service,<<"/">>,Aws4Req]), 
  DateTime = maps:get(<<"DateTime">>,ParamMap),
  StringToSign = iolist_to_binary([
    <<"AWS4-HMAC-SHA256">>,<<"\n">>
    ,DateTimeS3,<<"\n">>
    ,Scope,<<"\n">>
    ,CanonicalRequestHash
  ]),

  ParamMap2 = maps:put(<<"StringToSign">>,StringToSign,ParamMap),

  Secret = maps:get(<<"Secret">>,ParamMap),
  DateKey = crypto:hmac(sha256,iolist_to_binary([<<"AWS4">>,Secret]),Date),
  DateRegionKey = crypto:hmac(sha256,DateKey,Region),
  DateRegionService = crypto:hmac(sha256,DateRegionKey,Service),
  SigningKey = crypto:hmac(sha256,DateRegionService,Aws4Req),
  
  %% This is valid for 7 days
  Signature = soil_utls:hex(crypto:hmac(sha256,SigningKey,StringToSign)),

  ParamMap3 =maps:put(<<"Signature">>,Signature,ParamMap2),

  Access = maps:get(<<"Access">>,ParamMap),
  Authorization = iolist_to_binary([
    <<"AWS4-HMAC-SHA256">>,<<" ">>
    ,<<"Credential">>,<<"=">>,Access
    ,<<"/">>,Scope
    ,<<",">>,<<"SignedHeaders">>,<<"=">>,SignedHeaders
    ,<<",">>,<<"Signature">>,<<"=">>,Signature
  ]),
  maps:put(<<"Authorization">>,Authorization,ParamMap3).

%%
%% @private Encodes URI
%%
%%

s3_encode_uri(Data) ->
  s3_encode_uri(Data,false).
s3_encode_uri(Data,EncodeSlash) ->
  s3_encode_uri(Data,<<"">>,EncodeSlash).
s3_encode_uri(<<Char/utf8, Tail/binary>>,Acc,EncodeSlash) ->
  Encoded = case Char of
    Slash when Slash =:= 47 -> if EncodeSlash =:= true -> <<"%2F">>; true -> Slash end;
    Upper when Upper >= 65 andalso Upper =< 90 -> Upper; 
    Lower when Lower >= 97 andalso Lower =< 122 -> Lower; 
    Digit when Digit >= 48 andalso Digit =< 57 -> Digit; 
    Special when Special =:= 95 %% LOW LINE
      orelse Special =:= 45 %% HYPHEN-MINUS
      orelse Special =:= 126 %% TILDE
      orelse Special =:= 46 %% FULL STOP
        -> Special;
    Other -> list_to_binary("%" ++ soil_utls:to_hex(Other))
  end,
  Result = iolist_to_binary([Acc,Encoded]),
  s3_encode_uri(Tail,Result,EncodeSlash);
s3_encode_uri(_,Acc,_EncodeSlash) -> 
  Acc.

%%
%% @private 
%%
%%

s3_encode_headers(Headers) -> 
  {HeadersBin,CanonicalHeaders} = lists:foldl(fun(Elem,Acc) ->
    {Name,Value} = Elem,
    %% TODO: run to_lower on binary
    LowercaseName = list_to_binary(string:to_lower(binary_to_list(Name))),
    TrimValue = soil_utls:trim_bin(Value),
    Header = iolist_to_binary([ LowercaseName, <<":">>, TrimValue, <<"\n">>]),
    {SignedHeaderAcc,CanonicalHeaderAcc} = Acc,
    SignedHeader = iolist_to_binary([ SignedHeaderAcc,LowercaseName,<<";">> ]),
    CanonicalHeader = iolist_to_binary([ CanonicalHeaderAcc,Header ]),
    {SignedHeader,CanonicalHeader}
  end,{<<"">>,<<"">>},Headers),
  SignedHeaders = re:replace(HeadersBin,<<";(?!.*;)">>,<<"">>,[{return, binary}]),
  {SignedHeaders,CanonicalHeaders}.


%%
%% @private 
%%
%%

s3_encode_query_string([]) ->
  <<"">>;
s3_encode_query_string(QueryString) ->
  QueryStringEncoded = lists:foldl(fun({Key,Val},Acc) ->
    iolist_to_binary([
      Acc,s3_encode_uri(Key),<<"=">>,s3_encode_uri(Val),<<"&">>
    ])
  end,<<"">>,QueryString),
  re:replace(QueryStringEncoded,<<"&(?!.*&)">>,<<"">>,[{return, binary}]).

%%
%% @private Hashing punctions used by s3
%%

hash(Msg) ->
  Binary = crypto:hash(sha256,Msg),
  soil_utls:hex(Binary).
  
%%
%% @private
%%
remove_separators(Bin) ->
  re:replace(Bin,<<"(-)|(:)">>,<<"">>,[global,{return, binary}]).

%% ============================================================================
%% =============================== TEST =======================================
%% ============================================================================

sample_test_data() ->
  s3_authorization(#{
    <<"Method">> => <<"GET">>
    ,<<"URI">> => <<"/">>
    ,<<"Host">> =>  <<"examplebucket.s3.amazonaws.com">>
    ,<<"Query">> => [
      { <<"max-keys">>, <<"2">>}
      ,{<<"prefix">>,<<"J">> }
    ]
    ,<<"Payload">> => <<"">>
    ,<<"Region">> => <<"us-east-1">>
    ,<<"Service">> => <<"s3">>
    ,<<"DateTime">> => {{2013,5,24},{0,0,0}}
    ,<<"Access">> => <<"AKIAIOSFODNN7EXAMPLE">>
    ,<<"Secret">> => <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>
  }).

sign_string_test() ->
  TestData = sample_test_data(),
  Test = iolist_to_binary([<<"AWS4-HMAC-SHA256\n">>,
    <<"20130524T000000Z\n">>,
    <<"20130524/us-east-1/s3/aws4_request\n">>,
    <<"df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7">>]),
  Result = maps:get(<<"StringToSign">>,TestData),
  io:fwrite(user,"======= sign_string_test:~n~p~n~n =:= ~n~n~p~n~n",[Test,Result]),
  ?assert(Test =:= Result).

signature_test() ->
  TestData = sample_test_data(),
  Result = maps:get(<<"Authorization">>,TestData),
  Test = iolist_to_binary([<<"AWS4-HMAC-SHA256">>,<<" ">>
    ,<<"Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request">>
    ,<<",SignedHeaders=host;x-amz-content-sha256;x-amz-date">>
    ,<<",Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7">>]),
  io:fwrite(user,"======= signature_test:~n~p~n~n =:= ~n~n~p~n~n",[Test,Result]),
  ?assert(Test =:= Result).



