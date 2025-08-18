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
    ensure_runtime(),          %% crypto + jose + json module listos

    %% Derivar pública desde privada (P-256)
    {Pub, _} = crypto:generate_key(ecdh, prime256v1, Priv),
    %% Punto no comprimido <<4, X:32, Y:32>>
    <<4, X:32/binary, Y:32/binary>> = Pub,

    B64 = fun(Bin) -> jose_base64url:encode(Bin) end,

    JWKMap = #{
      <<"kty">> => <<"EC">>,
      <<"crv">> => <<"P-256">>,
      <<"d">>   => B64(Priv),
      <<"x">>   => B64(X),
      <<"y">>   => B64(Y)
    },

    %% from_map puede devolver JWK o {JWK, Fields}
    JWK0 = jose_jwk:from_map(JWKMap),
    JWK = case JWK0 of
            {JW, _Fields} -> JW;
            JW -> JW
          end,

    Header = #{<<"alg">> => <<"ES256">>, <<"typ">> => <<"JWT">>},
    Claims = #{<<"aud">> => Aud, <<"exp">> => ExpUnix, <<"sub">> => Sub},

    JWS = jose_jwt:sign(JWK, Header, Claims),

    %% compact puede ser:
    %%   Bin
    %% | {ok, Bin}
    %% | {Meta, Bin} (p.ej. #{alg => jose_jws_alg_ecdsa}, Bin)
    Compact0 = jose_jws:compact(JWS),
    CompactBin =
      case Compact0 of
        Bin when is_binary(Bin) -> Bin;
        {ok, Bin} when is_binary(Bin) -> Bin;
        {_Meta, Bin} when is_binary(Bin) -> Bin;
        Other ->
          erlang:error({unexpected_compact_return, Other})
      end,

    {ok, CompactBin}
  catch
    C:R ->
      Reason = unicode:characters_to_binary(io_lib:format("~p:~p", [C, R])),
      {error, Reason}
  end.

%% ---- helpers ----

ensure_runtime() ->
  _ = application:ensure_all_started(crypto),
  _ = application:ensure_all_started(public_key),
  _ = application:ensure_all_started(jose),
  %% Intenta arrancar jiffy si existe (no falla si no está)
  _ = case code:which(jiffy) of
        non_existing -> ok;
        _ -> application:ensure_all_started(jiffy)
      end,
  ensure_json_module().

ensure_json_module() ->
  case application:get_env(jose, json_module) of
    {ok, _Mod} -> ok;  %% ya configurado
    undefined ->
      %% preferencia: jiffy -> jsone -> thoas
      case code:which(jose_json_jiffy) of
        non_existing ->
          case code:which(jose_json_jsone) of
            non_existing ->
              case code:which(jose_json_thoas) of
                non_existing -> erlang:error(unsupported_json_module);
                _ -> application:set_env(jose, json_module, jose_json_thoas)
              end;
            _ -> application:set_env(jose, json_module, jose_json_jsone)
          end;
        _ -> application:set_env(jose, json_module, jose_json_jiffy)
      end
  end.
