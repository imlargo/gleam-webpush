%% Test only helpers, so the library is checked against an independent
%% implementation rather than against itself.
-module(webpush_test_ffi).

-export([verify_es256/3]).

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
