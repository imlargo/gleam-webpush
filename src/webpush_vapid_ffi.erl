%% Erlang FFI helpers for Gleam VAPID utilities.
%% File: webpush_vapid_ffi.erl
%% Requires: crypto, erlang-jose
-module(webpush_vapid_ffi).

-export([p256_generate_key/0, jwt_es256_sign/4, now_unix/0]).

%%--------------------------------------------------------------------
%% Types (for dialyzer/help)
%%--------------------------------------------------------------------
%-type priv_key() :: binary().              %% 32 bytes (scalar d)
%-type pub_key_uncompressed() :: binary().  %% <<4, X:32, Y:32>>
%-type reason_bin() :: binary().
%-type jwt_bin() :: binary().

%%--------------------------------------------------------------------
%% Current Unix time (seconds).
%%--------------------------------------------------------------------
%% @doc Return current Unix time in seconds.
-spec now_unix() -> integer().
now_unix() ->
  erlang:system_time(second).

%%--------------------------------------------------------------------
%% Generate P-256 keypair.
%% Returns {ok, {PrivBin, PubUncompressedBin}} where:
%% - PrivBin is 32 bytes (scalar d)
%% - PubUncompressedBin is <<4, X:32, Y:32>>
%%--------------------------------------------------------------------
-spec p256_generate_key() ->
        {ok, {binary(), binary()}} | {error, binary()}.
p256_generate_key() ->
  try
    {Pub, Priv} = crypto:generate_key(ecdh, prime256v1),
    {ok, {Priv, Pub}}
  catch
    C:R ->
      Reason = unicode:characters_to_binary(io_lib:format("~p:~p", [C, R])),
      {error, Reason}
  end.

%%--------------------------------------------------------------------
%% Sign a compact JWT (ES256) with given claims using erlang-jose.
%% Aud (binary), ExpUnix (integer), Sub (binary), Priv (32-byte binary)
%% -> {ok, CompactJWTBinary} | {error, ReasonBinary}
%%--------------------------------------------------------------------
%% Sign a compact JWT (ES256) with given claims using erlang-jose.
-spec jwt_es256_sign(binary(), integer(), binary(), binary()) ->
        {ok, binary()} | {error, binary()}.
jwt_es256_sign(Aud, ExpUnix, Sub, Priv) ->
  try
    %% Derive public from private to build a JWK
    {Pub, _} = crypto:generate_key(ecdh, prime256v1, Priv),
    %% Ensure uncompressed point: <<4, X:32, Y:32>>
    <<4, X:32/binary, Y:32/binary>> = Pub,

    B64 = fun(Bin) -> jose_base64url:encode(Bin) end,

    JWKMap = #{
      <<"kty">> => <<"EC">>,
      <<"crv">> => <<"P-256">>,
      <<"d">>   => B64(Priv),
      <<"x">>   => B64(X),
      <<"y">>   => B64(Y)
    },

    %% OJO: from_map NO devuelve {ok, ...}
    {JWK, _Fields} = jose_jwk:from_map(JWKMap),

    Header = #{<<"alg">> => <<"ES256">>, <<"typ">> => <<"JWT">>},
    Claims = #{<<"aud">> => Aud, <<"exp">> => ExpUnix, <<"sub">> => Sub},

    JWS = jose_jwt:sign(JWK, Header, Claims),

    %% OJO: compact devuelve el binario directamente
    CompactBin = jose_jws:compact(JWS),
    {ok, CompactBin}
  catch
    C:R ->
      Reason = unicode:characters_to_binary(io_lib:format("~p:~p", [C, R])),
      {error, Reason}
  end.
