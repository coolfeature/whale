%%
%%
%% @copyright IONAS SOFTWARE LTD
%% @author IONAS SOFTWARE LTD
%% @see http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
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

-define(S3_HOSTNAME,<<"http://{{bucket}}s3{{region}}amazonaws.com">>).
-define(S3_REGION,<<"eu-west-1">>).
-define(S3_USER_BUCKET,<<"drook-users">>).

-include_lib("eunit/include/eunit.hrl").
-include_lib("xmerl/include/xmerl.hrl").

%%
%% 
%%
%%

s3_host() ->
  Host = re:replace(?S3_HOSTNAME,<<"{{bucket}}">>,<<"">>,[{return,binary}]),
  re:replace(Host,<<"{{region}}">>,<<".">>,[{return,binary}]). 
s3_host(<<"upload">>) ->
  Bucket = iolist_to_binary([ ?S3_USER_BUCKET,<<".">> ]),
  Host = re:replace(?S3_HOSTNAME,<<"{{bucket}}">>,Bucket,[{return,binary}]), 
  Region = iolist_to_binary([ <<"-">>,?S3_REGION,<<".">> ]),
  re:replace(Host,<<"{{region}}">>,Region,[{return,binary}]);
s3_host(<<"list">>) ->
  Bucket = iolist_to_binary([ ?S3_USER_BUCKET,<<".">> ]),
  Host = re:replace(?S3_HOSTNAME,<<"{{bucket}}">>,Bucket,[{return,binary}]),
  re:replace(Host,<<"{{region}}">>,<<".">>,[{return,binary}]).

%%
%% @doc Hands out s3 tickets.
%%
%% -- GET
s3(Type,JsonMap) when Type =:= <<"list">> -> 
  RequestMap = s3_authorization(Type,JsonMap),
  case s3_req(RequestMap) of 
    {ok,{{200,_Ok},Body}} ->
      {Root, _RemainingText} = xmerl_scan:string(binary_to_list(Body)),
      KeyList = s3_resp_extract(Type,Root),
      {ok,#{ <<"result">> => <<"ok">>, <<"contents">> => KeyList}};
    {error,_Error} ->
      {error,#{ <<"result">> => <<"error">>
        , <<"msg">> => <<"S3 call did not succeed">> }}
  end;
%% -- POST  
s3(Type,JsonMap) when Type =:= <<"upload">> ->
  Body = maps:get(<<"body">>,JsonMap),
  Key = maps:get(<<"key">>,Body),
  BuketKey = iolist_to_binary([ Key,<<"/content/">> ]),
  % 1) Create Policy map
  NowSecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
  Add15Mins = NowSecs + (15 * 60),
  DateTimeExpires = calendar:gregorian_seconds_to_datetime(Add15Mins),
  Expiration = soil_utls:format_datetime(DateTimeExpires),
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
  S3Referer = soil_utls:get_env(s3_referer),
  Headers = [{<<"Referer">>,S3Referer}],
  DateTime = calendar:universal_time(),
  Access = soil_utls:get_env(s3_access),
  Secret = soil_utls:get_env(s3_secret),
  ParamMap = #{
    <<"Method">> => <<"GET">>
    ,<<"URI">> => <<"/">>
    ,<<"Host">> => s3_host(Type)
    ,<<"Query">> => Query
    ,<<"Headers">> => Headers
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
  ParamMap2 = maps:put(<<"QueryString">>,CanonicalQueryString,ParamMap),
  %% HashedPayload
  Payload = maps:get(<<"Payload">>,ParamMap2),
  HashedPayload = hash(Payload),
  ParamMap3 = maps:put(<<"HashedPayload">>,HashedPayload,ParamMap2),
  %% CanonicalHeaders & SignedHeaders
  HostUrl = maps:get(<<"Host">>,ParamMap3),
  Host = re:replace(HostUrl,<<"https?://">>,<<"">>,[{return,binary}]),
  DateTime = maps:get(<<"DateTime">>,ParamMap3),
  DateTimeISO8601 = soil_utls:format_datetime(DateTime),
  DateTimeS3 = remove_separators(DateTimeISO8601),

  Hdrs = maps:get(<<"Headers">>,ParamMap3,[]),
  Headers = [
    {<<"Host">>,Host}
    ,{<<"x-amz-content-sha256">>,HashedPayload}
    ,{<<"x-amz-date">>,DateTimeS3}
  ] ++ Hdrs,

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
  Region = maps:get(<<"Region">>,ParamMap3),
  Service = maps:get(<<"Service">>,ParamMap3),
  Scope = iolist_to_binary([Date,<<"/">>,Region,<<"/">>,Service,<<"/">>,Aws4Req]), 
  DateTime = maps:get(<<"DateTime">>,ParamMap3),
  StringToSign = iolist_to_binary([
    <<"AWS4-HMAC-SHA256">>,<<"\n">>
    ,DateTimeS3,<<"\n">>
    ,Scope,<<"\n">>
    ,CanonicalRequestHash
  ]),

  ParamMap4 = maps:put(<<"StringToSign">>,StringToSign,ParamMap3),

  Secret = maps:get(<<"Secret">>,ParamMap4),
  DateKey = crypto:hmac(sha256,iolist_to_binary([<<"AWS4">>,Secret]),Date),
  DateRegionKey = crypto:hmac(sha256,DateKey,Region),
  DateRegionService = crypto:hmac(sha256,DateRegionKey,Service),
  SigningKey = crypto:hmac(sha256,DateRegionService,Aws4Req),
  
  %% This is valid for 7 days
  Signature = soil_utls:hex(crypto:hmac(sha256,SigningKey,StringToSign)),

  ParamMap5 = maps:put(<<"Signature">>,Signature,ParamMap4),

  Access = maps:get(<<"Access">>,ParamMap5),
  Authorization = iolist_to_binary([
    <<"AWS4-HMAC-SHA256">>,<<" ">>
    ,<<"Credential">>,<<"=">>,Access
    ,<<"/">>,Scope
    ,<<",">>,<<"SignedHeaders">>,<<"=">>,SignedHeaders
    ,<<",">>,<<"Signature">>,<<"=">>,Signature
  ]),
  AuthHeaders = [{<<"Authorization">>,Authorization}] ++ Headers,
  maps:put(<<"Headers">>,AuthHeaders,ParamMap5).

%%
%% @private Encodes URI
%%
%%

s3_encode_uri(Data) ->
  s3_encode_uri(Data,false).
s3_encode_uri(Data,EncSlash) ->
  s3_encode_uri(Data,<<"">>,EncSlash).
s3_encode_uri(<<Char/utf8, Tail/binary>>,Acc,EncSlash) ->
  Encoded = case Char of
    Slash when Slash =:= 47 -> if EncSlash =:= true -> <<"%2F">>; true -> Slash end;
    Upper when Upper >= 65 andalso Upper =< 90 -> Upper; 
    Lower when Lower >= 97 andalso Lower =< 122 -> Lower; 
    Digit when Digit >= 48 andalso Digit =< 57 -> Digit; 
    Special when Special =:= 95 %% LOW LINE
      orelse Special =:= 45 %% HYPHEN-MINUS
      orelse Special =:= 126 %% TILDE
      orelse Special =:= 46 %% FULL STOP
        -> Special;
    Other -> soil_utls:hex(Other,"%")
  end,
  Result = iolist_to_binary([Acc,Encoded]),
  s3_encode_uri(Tail,Result,EncSlash);
s3_encode_uri(_,Acc,_EncSlash) -> 
  Acc.

%%
%% @private Every slash should be encoded except in key name and absolute URI.
%%
%%

s3_encode_headers(Headers) -> 
  HeadersSorted = lists:keysort(1,Headers),
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
  end,{<<"">>,<<"">>},HeadersSorted),
  SignedHeaders = re:replace(HeadersBin,<<";(?!.*;)">>,<<"">>,[{return, binary}]),
  {SignedHeaders,CanonicalHeaders}.


%%
%% @private 
%%
%%

s3_encode_query_string([]) ->
  <<"">>;
s3_encode_query_string(QueryString) ->
  QueryStringSorted = lists:keysort(1,QueryString),
  QueryStringEncoded = lists:foldl(fun({Key,Val},Acc) ->
    iolist_to_binary([
      Acc,s3_encode_uri(Key,true),<<"=">>,s3_encode_uri(Val,true),<<"&">>
    ])
  end,<<"">>,QueryStringSorted),
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

%% =============================================================================
%% ================================ HTTP =======================================
%% =============================================================================

s3_req(DataMap) ->
  Host = maps:get(<<"Host">>,DataMap),
  URI = maps:get(<<"URI">>,DataMap),
  QS = maps:get(<<"QueryString">>,DataMap),
  AddQs = if QS =:= <<"">> -> <<"">>; true -> <<"?">> end,
  Path = iolist_to_binary([ URI,AddQs,QS ]),
  URL = soil_utls:to_string(iolist_to_binary([ Host,Path ])),
  Method = soil_utls:to_string(maps:get(<<"Method">>,DataMap)),
  Headers = maps:get(<<"Headers">>,DataMap),
  Hdrs = soil_utls:to_string(proplists:delete(<<"Host">>,Headers)),
  %Hdrs = [{<<"Host">>,Host}] ++ Headers, 
  %Body = maps:get(<<"HashedPayload">>,DataMap),
  Timeout = 5000,
  Options = [],
  case lhttpc:request(URL,Method,Hdrs,[],Timeout,Options) of
    {ok,{Status,_Headers,Body}} -> {ok,{Status,Body}};
    {error,Error} -> {error,Error}
  end.

%% =============================================================================
%% ================================ XML ========================================
%% =============================================================================

s3_resp_extract(Type,Root) when Type =:= <<"list">> -> 
  KeyList = xmerl_xpath:string("//ListBucketResult/Contents/Key/text()",Root),
  lists:foldl( fun(Elm,Acc) -> 
    {_XmlText,_TreeList,_No,_Empty,Key,_Text} = Elm,
    KeyBin = list_to_binary(Key),
    Url = iolist_to_binary([ s3_host(<<"upload">>),<<"/">>,KeyBin]),
    [ #{<<"src">> => Url }] ++ Acc
  end,[],KeyList ).
 
%% =============================================================================
%% ================================ TEST =======================================
%% =============================================================================

sample_test_data() ->
  s3_authorization(#{
    <<"Method">> => <<"GET">>
    ,<<"URI">> => <<"/">>
    ,<<"Host">> => <<"examplebucket.s3.amazonaws.com">>
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
  io:fwrite(user,"==== sign_string_test:~n~p~n~n =:= ~n~n~p~n~n",[Test,Result]),
  ?assert(Test =:= Result).

signature_test() ->
  TestData = sample_test_data(),
  Headers = maps:get(<<"Headers">>,TestData),
  Result = proplists:get_value(<<"Authorization">>,Headers),
  Test = iolist_to_binary([<<"AWS4-HMAC-SHA256">>,<<" ">>
    ,<<"Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request">>
    ,<<",SignedHeaders=host;x-amz-content-sha256;x-amz-date">>
    ,<<",Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7">>]),
  io:fwrite(user,"==== signature_test:~n~p~n~n =:= ~n~n~p~n~n",[Test,Result]),
  ?assert(Test =:= Result).

s3_req_test() ->
  JsonMap = #{ <<"body">> => 
    #{ <<"key">> => <<"0HPdYgj3YXlCO2A-RP0vXlzYK4UH2sO6LOsrPeMwDP8">> }},
  {IsOk,_ResultMap} = Resp = s3(<<"list">>,JsonMap),
  io:fwrite(user,"==== s3_req_test:~n~p~n~n",[Resp]),
  ?assert(IsOk =:= ok).
 
s3_parse_resp_test() ->
  {Root, _RemainingText} = xmerl_scan:file("test/xml/list.xml"),
  Contents = s3_resp_extract(<<"list">>,Root),
  ?assert(is_list(Contents)).


