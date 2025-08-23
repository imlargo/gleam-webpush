%% Erlang FFI for Web Push encryption (RFC8291) + ECDH + AES-GCM.
%% No dependency on crypto:hkdf/5 (HKDF implemented manually).
-module(webpush_push_ffi).
-export([encrypt_payload/4]).

-define(MAX_RECORD_SIZE, 4096).

-spec encrypt_payload(binary(), binary(), binary(), integer())
  -> {ok, binary()} | {error, binary()}.
encrypt_payload(Message, PeerPub, AuthSecret, RecordSize0) ->
  try
    ensure_crypto(),

    %% Parameters
    RecordSize = case RecordSize0 of 0 -> ?MAX_RECORD_SIZE; _ -> RecordSize0 end,
    RecordLen  = RecordSize - 16,

    %% 16-byte salt
    Salt = crypto:strong_rand_bytes(16),

    %% Local ephemeral P-256 key (uncompressed pub <<4,X:32,Y:32>>)
    {LocalPub, LocalPriv} = crypto:generate_key(ecdh, prime256v1),

    %% ECDH with the public key of the user agent (peer)
    %%    PeerPub must be uncompressed point (65 bytes, starts with 4)
    <<4, _/binary>> = PeerPub,
    Secret = crypto:compute_key(ecdh, PeerPub, LocalPriv, prime256v1),

    %% HKDF-Expand to obtain IKM (32 bytes) as in RFC8291
    %%    IKM = HKDF(sha256, ikm=Secret, salt=AuthSecret, info="WebPush: info\0 || dh || pub")
    PRKInfo = << "WebPush: info", 0, PeerPub/binary, LocalPub/binary >>,
    IKM = hkdf_expand(Secret, AuthSecret, PRKInfo, 32),

    %% CEK (16) and Nonce (12) from IKM with salt=Salt
    CEKInfo   = << "Content-Encoding: aes128gcm", 0 >>,
    NonceInfo = << "Content-Encoding: nonce", 0   >>,
    CEK   = hkdf_expand(IKM, Salt, CEKInfo,   16),
    Nonce = hkdf_expand(IKM, Salt, NonceInfo, 12),

    %% Header + padding calculation
    HeaderLen = 16 + 4 + 1 + byte_size(LocalPub),

    %% Data: message + 0x02 + zero padding
    Data0 = << Message/binary, 16#02 >>,
    Required = RecordLen - HeaderLen,
    Data0Len = byte_size(Data0),
    case Data0Len =< Required of
  false -> throw(max_pad_exceeded);
  true ->
    PadLen = Required - Data0Len,
    Padding = case PadLen of 0 -> <<>>; _ -> binary:copy(<<0>>, PadLen) end,
    Data = << Data0/binary, Padding/binary >>,

    %% AES-GCM without AAD (uses 'aes_gcm', 16-byte key => AES-128-GCM)
    {Cipher, Tag} =
      crypto:crypto_one_time_aead(aes_gcm, CEK, Nonce, Data, <<>>, 16, true),
    Ciphertext = << Cipher/binary, Tag/binary >>,

    %% Body: Salt | RS | id_len | LocalPub | Ciphertext
    Body = <<
      Salt/binary,
      RecordSize:32/big-unsigned-integer,
      (byte_size(LocalPub)):8,
      LocalPub/binary,
      Ciphertext/binary
    >>,
    {ok, Body}
    end
  catch
    throw:max_pad_exceeded ->
  {error, <<"payload has exceeded the maximum length">>};
    C:R ->
  Reason = unicode:characters_to_binary(io_lib:format("~p:~p", [C, R])),
  {error, Reason}
  end.

%% -------------------------------------------------------------------
%% Helpers
%% -------------------------------------------------------------------

ensure_crypto() ->
  _ = application:ensure_all_started(crypto),
  ok.

%% HKDF (RFC5869) with SHA-256:
%% PRK = HMAC(Salt, IKM)
%% T(0)=<<>>, T(i)=HMAC(PRK, T(i-1) || Info || <<i>>), concat until Length
-spec hkdf_expand(binary(), binary(), binary(), non_neg_integer()) -> binary().
hkdf_expand(IKM, Salt, Info, Length) ->
  PRK = crypto:mac(hmac, sha256, Salt, IKM),
  hkdf_expand_loop(PRK, Info, Length, 1, <<>>, <<>>).

hkdf_expand_loop(_PRK, _Info, Length, _I, _Tprev, Acc) when byte_size(Acc) >= Length ->
  binary:part(Acc, 0, Length);
hkdf_expand_loop(PRK, Info, Length, I, Tprev, Acc) ->
  T = crypto:mac(hmac, sha256, PRK, <<Tprev/binary, Info/binary, I:8/integer>>),
  hkdf_expand_loop(PRK, Info, Length, I+1, T, <<Acc/binary, T/binary>>).

