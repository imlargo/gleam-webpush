//// VAPID helpers for Web Push (P-256 + ES256 JWT) using Erlang FFI.

import gleam/bit_array
import gleam/option
import gleam/result
import gleam/string
import gleam/uri

// ---------- Public types ----------

/// Errors you might encounter when working with VAPID.
pub type VapidError {
  InvalidEndpoint(String)
  DecodeKeyError
  UnknownError(String)
  CryptoError(String)
}

/// VAPID key pair in Base64URL (unpadded), as required by Web Push.
pub type VapidKeys {
  VapidKeys(private_key_b64url: String, public_key_b64url: String)
}

// ---------- Externals (FFI) ----------

@external(erlang, "webpush_vapid_ffi", "p256_generate_key")
fn p256_generate_key() -> Result(#(BitArray, BitArray), String)

@external(erlang, "webpush_vapid_ffi", "jwt_es256_sign")
fn jwt_es256_sign(
  aud: String,
  exp_unix: Int,
  sub: String,
  priv_key: BitArray,
) -> Result(String, String)

@external(erlang, "webpush_vapid_ffi", "now_unix")
pub fn now_unix() -> Int

// ---------- Public API ----------

/// Generate a new P-256 VAPID key pair (Base64URL, no padding).
pub fn generate_vapid_keys() -> Result(VapidKeys, VapidError) {
  case p256_generate_key() {
    Ok(#(priv, pub_bytes)) -> {
      let priv_b64 = bit_array.base64_url_encode(priv, False)
      let pub_b64 = bit_array.base64_url_encode(pub_bytes, False)
      Ok(VapidKeys(priv_b64, pub_b64))
    }
    Error(msg) -> Error(CryptoError("failed to generate P-256 key: " <> msg))
  }
}

/// Produce the `Authorization` header value for Web Push (VAPID).
/// Returns: `vapid t=<jwt>, k=<base64url(pub)>`.
pub fn vapid_authorization_header(
  endpoint: String,
  subscriber: String,
  vapid_public_key_b64url: String,
  vapid_private_key_b64url: String,
  expiration_unix: Int,
) -> Result(String, VapidError) {
  use url <- result.try(
    uri.parse(endpoint) |> result.map_error(fn(_) { InvalidEndpoint(endpoint) }),
  )

  use aud <- result.try(extract_audience(url.scheme, url.host, endpoint))

  // 3) Normalize subscriber
  let sub = case string.starts_with(subscriber, "https:") {
    True -> subscriber
    False -> "mailto:" <> subscriber
  }

  use priv <- result.try(
    decode_vapid_key(vapid_private_key_b64url)
    |> result.map_error(fn(_) { DecodeKeyError }),
  )

  use pub_bytes <- result.try(
    decode_vapid_key(vapid_public_key_b64url)
    |> result.map_error(fn(_) { DecodeKeyError }),
  )

  use jwt <- result.try(
    jwt_es256_sign(aud, expiration_unix, sub, priv)
    |> result.map_error(CryptoError),
  )

  let pub_b64 = bit_array.base64_url_encode(pub_bytes, False)
  Ok("vapid t=" <> jwt <> ", k=" <> pub_b64)
}

fn extract_audience(
  scheme: option.Option(String),
  host: option.Option(String),
  endpoint: String,
) -> Result(String, VapidError) {
  case scheme, host {
    option.Some(s), option.Some(h) -> Ok(string.concat([s, "://", h]))
    _, _ -> Error(InvalidEndpoint(endpoint))
  }
}

// ---------- Internal helpers ----------

/// Decode VAPID key: try Base64URL first, then standard Base64.
pub fn decode_vapid_key(b64: String) -> Result(BitArray, Nil) {
  case bit_array.base64_url_decode(b64) {
    Ok(b) -> Ok(b)
    Error(_) -> bit_array.base64_decode(b64)
  }
}
