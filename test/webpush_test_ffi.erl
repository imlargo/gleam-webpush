%% Test only helpers, so the library is checked against an independent
%% implementation rather than against itself.
-module(webpush_test_ffi).

-export([verify_es256/3, decrypt/4]).

%% A JWS signature is `R || S'; crypto:verify/5 wants it DER encoded.
-spec verify_es256(binary(), binary(), binary()) -> boolean().
verify_es256(Signed, <<R:32/binary, S:32/binary>>, PublicKey) ->
    Der = public_key:der_encode('ECDSA-Sig-Value', {'ECDSA-Sig-Value',
        binary:decode_unsigned(R, big),
        binary:decode_unsigned(S, big)
    }),
    crypto:verify(ecdsa, sha256, Signed, Der, [PublicKey, prime256v1]);
verify_es256(_Signed, _Signature, _PublicKey) ->
    false.

%% Decrypt an aes128gcm body the way a browser does (RFC 8291 section 3.4).
-spec decrypt(binary(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, binary()}.
decrypt(Body, RecipientPrivate, RecipientPublic, AuthSecret) ->
    try
        <<Salt:16/binary, _RecordSize:32, KeyLength:8, Rest/binary>> = Body,
        <<SenderPublic:KeyLength/binary, Ciphertext/binary>> = Rest,

        Shared = crypto:compute_key(ecdh, SenderPublic, RecipientPrivate, prime256v1),
        Info = <<"WebPush: info", 0, RecipientPublic/binary, SenderPublic/binary>>,
        Ikm = hkdf(Shared, AuthSecret, Info, 32),
        Key = hkdf(Ikm, Salt, <<"Content-Encoding: aes128gcm", 0>>, 16),
        Nonce = hkdf(Ikm, Salt, <<"Content-Encoding: nonce", 0>>, 12),

        Length = byte_size(Ciphertext) - 16,
        <<Encrypted:Length/binary, Tag:16/binary>> = Ciphertext,

        case crypto:crypto_one_time_aead(aes_gcm, Key, Nonce, Encrypted, <<>>, Tag, false) of
            error -> {error, <<"authentication failed">>};
            Padded -> {ok, strip_padding(Padded, byte_size(Padded))}
        end
    catch
        Class:Reason ->
            {error, unicode:characters_to_binary(io_lib:format("~p:~p", [Class, Reason]))}
    end.

%% The plaintext is the message, a `0x02\' delimiter, then zero padding.
strip_padding(Padded, 0) ->
    Padded;
strip_padding(Padded, Size) ->
    case binary:at(Padded, Size - 1) of
        0 -> strip_padding(Padded, Size - 1);
        2 -> binary:part(Padded, 0, Size - 1);
        _ -> erlang:error(missing_delimiter)
    end.

hkdf(Ikm, Salt, Info, Length) ->
    expand(crypto:mac(hmac, sha256, Salt, Ikm), Info, Length, 1, <<>>, <<>>).

expand(_Key, _Info, Length, _N, _Previous, Acc) when byte_size(Acc) >= Length ->
    binary:part(Acc, 0, Length);
expand(Key, Info, Length, N, Previous, Acc) ->
    Block = crypto:mac(hmac, sha256, Key, <<Previous/binary, Info/binary, N:8>>),
    expand(Key, Info, Length, N + 1, Block, <<Acc/binary, Block/binary>>).
