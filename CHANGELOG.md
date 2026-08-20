# Changelog

## v2.0.0

Requires Erlang/OTP 27 or later.

### Changed

- VAPID JWTs are signed with Erlang/OTP's own `crypto` and `public_key` instead
  of `erlang-jose`. The library now has no external dependencies, and `jiffy`,
  a C NIF that needed a working compiler to install, is gone. `erlang-jose`
  does not build on OTP 28 or 29, so version 1.0.0 could not be compiled at all
  on a current Erlang.
- The `webpush` root module has been removed. It contained only a demo `main`
  with placeholder keys. Import `webpush/push`, `webpush/vapid` and
  `webpush/urgency`, which is how the library was already used.

### Fixed

- A subscriber that already carried its URI scheme was prefixed again, so
  `"mailto:you@example.com"` became `sub: "mailto:mailto:you@example.com"` and
  was rejected by push services. The README and the example both told users to
  pass an address in that form.
- `p256dh` keys longer than 65 bytes passed validation and failed later inside
  OpenSSL, surfacing as `CryptoError("error:{error,{\"ecdh.c\",80},...")`
  instead of `InvalidPeerPublicKey`.
- The package declared the Apache-2.0 licence to Hex while the project is MIT.
- `MaxPadExceeded` was declared and documented but nothing ever returned it. A
  message too large for the record surfaced as
  `CryptoError("payload has exceeded the maximum length")` instead.

### Removed

- `VapidError.UnknownError`, which was never constructed.

### Added

- `push.max_payload_size`, the largest message that fits in a record of a given
  size. With the default record size the limit is 3993 bytes.
- A test suite covering VAPID key generation, JWT signing and payload
  encryption. Signatures are verified with OTP's ECDSA and payloads are
  decrypted with an independent implementation of the receiving side, rather
  than by re-running the code under test.
- CI running the suite against OTP 27, 28 and 29.

### Migrating from v1.0.0

No function signatures changed. If you imported the `webpush` module itself,
import the submodules instead. Make sure you are on OTP 27 or later.

Two error values moved: an oversized payload now returns `MaxPadExceeded`
rather than `CryptoError`, and `VapidError.UnknownError` no longer exists, so
a `case` over `VapidError` that matched it needs that branch removed.

## v1.0.0

Initial release.
