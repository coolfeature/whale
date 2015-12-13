-module(soil_js).

-export([
  fabric_js/0
  ,fabric/0
]).

fabric() ->
  {ok,JS} = js_driver:new(),
  js_driver:define_js(JS,<<"fabric.js">>,fabric_js(),5000).

fabric_js() ->
  PrivDir = soil_utls:priv_dir(),
  FileName = filename:join([PrivDir, "cards/static/lib/fabric-js-1.5.0/fabric.min.js.sm"]),
  case js_cache:fetch(FileName) of
    none ->
      {ok, Contents} = file:read_file(FileName),
      js_cache:store(FileName, Contents),
      Contents;
    Contents ->
      Contents
  end.
