%% Erlang FFI para cifrado Web Push (RFC8291) + HKDF + AES-128-GCM.
%% Depende de: crypto (OTP 24+).
-module(webpush_push_ffi).
-export([encrypt_payload/4]).

-define(MAX_RECORD_SIZE, 4096).

-spec encrypt_payload(binary(), binary(), binary(), integer())
      -> {ok, binary()} | {error, binary()}.
encrypt_payload(Message, PeerPub, AuthSecret, RecordSize0) ->
  try
    %% 0) Parámetros
    RecordSize = case RecordSize0 of 0 -> ?MAX_RECORD_SIZE; _ -> RecordSize0 end,
    RecordLen  = RecordSize - 16,

    %% 1) Salt de 16 bytes
    Salt = crypto:strong_rand_bytes(16),

    %% 2) Clave local efímera P-256 (pub no comprimida <<4,X:32,Y:32>>)
    {LocalPub, LocalPriv} = crypto:generate_key(ecdh, prime256v1),

    %% 3) ECDH con la clave pública del agente de usuario (peer)
    %%    PeerPub debe ser punto no comprimido (65 bytes, empieza en 4)
    <<4, _/binary>> = PeerPub,
    Secret = crypto:compute_key(ecdh, PeerPub, LocalPriv, prime256v1),

    %% 4) HKDF (PRK/IKM) según RFC8291
    PRKInfo = << "WebPush: info", 0, PeerPub/binary, LocalPub/binary >>,
    IKM = crypto:hkdf(sha256, Secret, AuthSecret, PRKInfo, 32),

    %% 5) Derivar CEK y Nonce
    CEKInfo   = << "Content-Encoding: aes128gcm", 0 >>,
    NonceInfo = << "Content-Encoding: nonce", 0   >>,
    CEK   = crypto:hkdf(sha256, IKM, Salt, CEKInfo,   16),
    Nonce = crypto:hkdf(sha256, IKM, Salt, NonceInfo, 12),

    %% 6) Construir cabecera de registro (sin ciphertext)
    %%    header = Salt(16) + RS(4) + id_len(1) + LocalPub(65)
    HeaderLen = 16 + 4 + 1 + byte_size(LocalPub),

    %% 7) Datos: mensaje + 0x02 + padding con ceros
    Data0 = << Message/binary, 16#02 >>,
    Required = RecordLen - HeaderLen,
    Data0Len = byte_size(Data0),
    case Data0Len =< Required of
      false -> throw(max_pad_exceeded);
      true ->
        PadLen = Required - Data0Len,
        Padding = case PadLen of 0 -> <<>>; _ -> <<0:8*PadLen>> end,
        Data = << Data0/binary, Padding/binary >>,

        %% 8) AES-128-GCM sin AAD, concatenando Tag (16) al final
        {Cipher, Tag} =
          crypto:crypto_one_time_aead(aes_128_gcm, CEK, Nonce, Data, <<>>, 16, true),
        Ciphertext = << Cipher/binary, Tag/binary >>,

        %% 9) Ensamblar registro completo para HTTP body
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
