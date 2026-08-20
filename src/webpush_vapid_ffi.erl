%% Erlang FFI helpers for Gleam VAPID utilities.
%% File: webpush_vapid_ffi.erl
%% Requires: crypto, public_key and the built in json module (OTP 27+)
-module(webpush_vapid_ffi).

-export([p256_generate_key/0, p256_public_key/1, jwt_es256_sign/4, now_unix/0]).

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
%% Derive the public key belonging to a private key, so that a mismatched or
%% otherwise unusable key pair can be rejected before anything is signed.
%%--------------------------------------------------------------------
-spec p256_public_key(binary()) -> {ok, binary()} | {error, binary()}.
p256_public_key(Priv) ->
  try
    {Pub, _} = crypto:generate_key(ecdh, prime256v1, Priv),
    {ok, Pub}
  catch
    C:R ->
      Reason = unicode:characters_to_binary(io_lib:format("~p:~p", [C, R])),
      {error, Reason}
  end.

%%--------------------------------------------------------------------
%% Sign a compact JWT (ES256) with the given claims.
%% Aud (binary), ExpUnix (integer), Sub (binary), Priv (32-byte binary)
%% -> {ok, CompactJWTBinary} | {error, ReasonBinary}
%%--------------------------------------------------------------------
-spec jwt_es256_sign(binary(), integer(), binary(), binary()) ->
        {ok, binary()} | {error, binary()}.
jwt_es256_sign(Aud, ExpUnix, Sub, Priv) ->
  try
    Header = json_encode(#{<<"typ">> => <<"JWT">>, <<"alg">> => <<"ES256">>}),
    Claims = json_encode(#{
      <<"aud">> => Aud,
      <<"exp">> => ExpUnix,
      <<"sub">> => Sub
    }),
    Signed = <<(b64url(Header))/binary, $., (b64url(Claims))/binary>>,
    Signature = es256_sign(Signed, Priv),
    {ok, <<Signed/binary, $., (b64url(Signature))/binary>>}
  catch
    C:R ->
      Reason = unicode:characters_to_binary(io_lib:format("~p:~p", [C, R])),
      {error, Reason}
  end.

%% ---- helpers ----

%% crypto:sign/4 returns the DER SEQUENCE {r, s}, but JWS (RFC 7515) wants the
%% two values concatenated and each zero padded to 32 bytes. DER drops leading
%% zero bytes and adds one when the high bit is set, so redo the padding here.
es256_sign(Signed, Priv) ->
  Der = crypto:sign(ecdsa, sha256, Signed, [Priv, prime256v1]),
  {'ECDSA-Sig-Value', R, S} = public_key:der_decode('ECDSA-Sig-Value', Der),
  <<(coordinate(R))/binary, (coordinate(S))/binary>>.

coordinate(Value) ->
  Bin = binary:encode_unsigned(Value, big),
  Pad = 32 - byte_size(Bin),
  <<0:(Pad * 8), Bin/binary>>.

b64url(Data) ->
  base64:encode(Data, #{mode => urlsafe, padding => false}).

json_encode(Term) ->
  iolist_to_binary(json:encode(Term)).
