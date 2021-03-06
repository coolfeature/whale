-module(soil_models).

-compile(export_all).

pgsql() -> 
  #{
    <<"user">> => #{
      <<"create_rank">> => <<"1">>
      ,<<"fields">> => #{
        <<"id">> => #{  <<"type">> => <<"bigserial">>, <<"null">> => <<"false">> }
        ,<<"email">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"50">>, <<"null">> => <<"false">> }
        ,<<"password">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"50">>, <<"null">> => <<"false">> }
        ,<<"date_registered">> => #{ <<"type">> => <<"timestamp">>, <<"default">> => <<"current_timestamp">> }
      }
      ,<<"constraints">> => #{
	%% There may be only ONE pk
        <<"pk">> => #{ <<"fields">> => [<<"id">>] }
	%% There may be MULTIPLE unique
        ,<<"unique">> => [
		#{ <<"fields">> => [<<"email">>] }
	]
      }
    }
    ,<<"customer">> => #{
      <<"create_rank">> => <<"3">>
      ,<<"fields">> => #{
        <<"id">> => #{ <<"type">> => <<"bigserial">>, <<"null">> => <<"false">> }
        ,<<"email">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"50">>, <<"null">> => <<"false">> }
        ,<<"fname">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"50">>, <<"null">> => <<"false">> }
        ,<<"lname">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"50">>, <<"null">> => <<"false">> }
        ,<<"gender">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"1">>, <<"null">> => <<"false">> }
        ,<<"promo">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"1">>, <<"null">> => <<"false">> }
        ,<<"home_key">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"512">>,  <<"null">> => <<"false">> }
        ,<<"user_id">> => #{ <<"type">> => <<"bigint">>, <<"null">> => <<"false">> }
        ,<<"address_id">> => #{ <<"type">> => <<"bigint">>, <<"null">> => <<"true">> }
      }
      ,<<"constraints">> => #{
        <<"pk">> => #{ <<"name">> => <<"pk_customer">>, <<"fields">> => [<<"id">>] }
        ,<<"fk">> => [ #{ <<"references">> => #{ <<"table">> => <<"user">>, <<"fields">> => [<<"id">>] }, <<"fields">> => [<<"user_id">>] }
          ,#{ <<"references">> => #{ <<"table">> => <<"address">>, <<"fields">> => [<<"id">>] }, <<"fields">> => [<<"address_id">>] }]
      }
    }
    ,<<"address">> => #{
      <<"create_rank">> => <<"2">>
      ,<<"fields">> => #{
        <<"id">> => #{  <<"type">> => <<"bigserial">>, <<"null">> => <<"false">> }
        ,<<"line1">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"50">> }
        ,<<"line2">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"50">> }
        ,<<"postcode">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"50">> }
        ,<<"city">> => #{ <<"type">> => <<"varchar">>, <<"length">> => <<"50">> }
      }
      ,<<"constraints">> => #{
        <<"pk">> => #{ <<"fields">> => [<<"id">>] }
      }
    }

  }.

mnesia() ->
  #{
    <<"views">> => #{
      <<"key">> => <<"id">>
      ,<<"type">> => <<"set">>
      ,<<"fields">> => #{
        <<"id">> => #{ <<"type">> => <<"binary">> }
        ,<<"visits">> => #{ <<"type">> => <<"integer">> }
        ,<<"reviews">> => #{ <<"type">> => <<"map">> }
        ,<<"purchases">> => #{ <<"type">> => <<"map">> }
      }
    }
  }.
