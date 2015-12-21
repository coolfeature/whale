-module(soil_rest).

-export([init/3]).
-export([
  rest_init/2
  ,content_types_accepted/2
  ,content_types_provided/2
  ,handle_html/2
  ,handle_json/2
  ,handle_text/2
  ,rest_terminate/2
  
  ,resource_exists/2
  ,allowed_methods/2
  ,to_html/3

  ,route_to_html/2
  ,route_handle_json/2
]).

%% ============================================================================

init(_Transport, _Req, _Opts) ->
  {upgrade, protocol, cowboy_rest}.

rest_init(Req, Opts) ->
  State = if Opts =:= [] -> #{}; true -> hd(Opts) end, 
  {ok, Req, State}.

%% Only POST and GET are allowed as REST
allowed_methods(Req, State) ->
  {[<<"POST">>,<<"GET">>], Req, State}.

%% Types that are POST accepted,
%% %% and it's parsed using handle_post/2
content_types_accepted(Req, State) ->
  {[
    {{<<"application">>, <<"json">>, []},route_handle_json}
  ], Req, State}.

%% Types that are GET and POST provided
content_types_provided(Req, State) ->
  {[
    {<<"text/html">>, route_to_html}
  ], Req, State}.

%% Set to false to stop ptogressing.
resource_exists(Req, State) ->
  {true, Req, State}.

%% ============================================================================

route_to_html(Req,State) ->
  {Path,Req2} = cowboy_req:path(Req),
  {_Peer,Req3} = cowboy_req:peer(Req2),
  to_html(Path,Req3,State).

to_html(IndexFile, Req, #{ index_file := IndexFile } = State) ->
  Sid = soil_utls:random(),
  Req1 = soil_session:set_cookie(Req,<<"TSID">>,Sid),
  Template = soil_utls:priv_dir() ++ binary_to_list(IndexFile),
  {ok,_Module} = erlydtl:compile_file(Template,index_dtl),
  {Peer,Req2} = cowboy_req:peer(Req1),
  case soil_session:allow_peer(Peer) of
    ok ->
      {ok,Body} = index_dtl:render([]);
    stop ->
      {ok,Body} = index_dtl:render([])
  end,
  {Body, Req2, State};

to_html(<<"/">>, Req, State) ->
  {ok, Req2} = cowboy_req:reply(302,
    [{<<"Location">>, <<"/cards/app/index.html">>}],<<>>,Req),
  {halt, Req2, State};

to_html(_, Req, State) ->
  {<<"404">>, Req, State}.

%% ============================================================================

route_handle_json(_Req,_State) ->
  ok.

handle_html(Req, State) ->
  {<<"<html>html</html>">>, Req, State}.

handle_json(Req, State) ->
  Body = <<"{\"rest\": \"Hello World!\"}">>,
  {Body, Req, State}.

handle_text(Req, State) ->
  {<<"REST Hello World as text!">>, Req, State}.

rest_terminate(_Req,_State) ->
  ok.
