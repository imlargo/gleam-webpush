%% Erlang FFI helpers for Gleam VAPID utilities.
-module(webpush_vapid_ffi).
-export([p256_generate_key/0, jwt_es256_sign/4, now_unix/0]).

%% Current Unix time (seconds).
now_unix() ->
  erlang:system_time(second).

%% Generate P-256 keypair.
%% Returns {ok, {PrivBin, PubUncompressedBin}} where:
%% - PrivBin is 32 bytes (scalar d)
%% - PubUncompressedBin is <<4, X:32, Y:32>>
p256_generate_key() ->
  try
    {Pub, Priv} = crypto:generate_key(ecdh, prime256v1),
    {ok, {Priv, Pub}}
  catch
    C:R ->
      {error, io_lib:format("~p:~p", [C, R])}
  end.

%% Sign a compact JWT (ES256) with given claims using erlang-jose.
%% Aud, ExpUnix, Sub, Priv -> {ok, CompactJWT} | {error, ReasonString}
jwt_es256_sign(Aud, ExpUnix, Sub, Priv) ->
  try
    %% Derive public from private to build a JWK
    {Pub, _} = crypto:generate_key(ecdh, prime256v1, Priv),
    <<4, X:32/binary, Y:32/binary>> = Pub,

    B64 = fun(Bin) -> jose_base64url:encode(Bin) end,

    JWKMap = #{
      <<"kty">> => <<"EC">>,
      <<"crv">> => <<"P-256">>,
      <<"d">>   => B64(Priv),
      <<"x">>   => B64(X),
      <<"y">>   => B64(Y)
    },
    {ok, JWK} = jose_jwk:from_map(JWKMap),

    Header = #{<<"alg">> => <<"ES256">>, <<"typ">> => <<"JWT">>},
    Claims = #{<<"aud">> => Aud, <<"exp">> => ExpUnix, <<"sub">> => Sub},

    JWS     = jose_jwt:sign(JWK, Header, Claims),
    Compact = jose_jws:compact(JWS),
    {ok, Compact}
  catch
    C:R ->
      {error, io_lib:format("~p:~p", [C, R])}
  end.
