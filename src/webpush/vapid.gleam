import gleam/bit_array
import gleam/int
import gleam/option
import gleam/result
import gleam/string
import gleam/uri

/// Represents possible errors that can occur during VAPID operations.
///
/// - `InvalidEndpoint(String)`: The endpoint has no scheme and host to derive
///   the JWT audience from.
/// - `InvalidSubscriber(String)`: The contact is empty. RFC 8292 requires a
///   `mailto:` or `https:` URI the push service operator can reach.
/// - `DecodeKeyError`: Occurs when decoding a cryptographic key fails.
/// - `InvalidPrivateKey(Int)`: The private key is not the 32 byte P-256 scalar.
/// - `InvalidPublicKey(Int)`: The public key is not a 65 byte uncompressed point.
/// - `CryptoError(String)`: Represents an error related to cryptographic operations.
pub type VapidError {
  InvalidEndpoint(String)
  InvalidSubscriber(String)
  DecodeKeyError
  InvalidPrivateKey(Int)
  InvalidPublicKey(Int)
  CryptoError(String)
}

/// Converts a `VapidError` into a human-readable string message.
/// 
/// # Arguments
/// - `error`: The `VapidError` to be converted.
///
/// # Returns
/// A descriptive string representing the error type and details.
///
/// # Error Variants
pub fn vapid_error_to_string(error: VapidError) -> String {
  case error {
    InvalidEndpoint(endpoint) -> "Invalid endpoint: " <> endpoint
    InvalidSubscriber(subscriber) ->
      "Invalid subscriber, expected an email or a mailto:/https: URI, got: "
      <> subscriber
    DecodeKeyError -> "Failed to decode VAPID key"
    InvalidPrivateKey(size) ->
      "Invalid VAPID private key: expected 32 bytes, got "
      <> int.to_string(size)
    InvalidPublicKey(size) ->
      "Invalid VAPID public key: expected 65 bytes, got " <> int.to_string(size)
    CryptoError(msg) -> "VAPID crypto error: " <> msg
  }
}

/// Represents a pair of VAPID (Voluntary Application Server Identification) keys used for Web Push authentication.
/// Contains the private and public keys encoded in base64url format.
pub type VapidKeys {
  VapidKeys(private_key_b64url: String, public_key_b64url: String)
}

/// Generates a new P-256 elliptic curve key pair for VAPID authentication.
/// 
/// This function calls an external Erlang FFI to generate the key pair.
/// 
/// Returns:
///   - `Ok((private_key, public_key))` on success, where both keys are represented as `BitArray`.
///   - `Error(message)` if key generation fails, with an error message.
/// 
/// # Example
/// ```gleam
/// let result = p256_generate_key()
/// ```
@external(erlang, "webpush_vapid_ffi", "p256_generate_key")
fn p256_generate_key() -> Result(#(BitArray, BitArray), String)

/// Signs a JWT using the ES256 algorithm for VAPID authentication.
///
/// # Parameters
/// - `aud`: The audience claim, typically the origin of the push service.
/// - `exp_unix`: The expiration time as a Unix timestamp.
/// - `sub`: The subject claim, usually an email or URL identifying the sender.
/// - `priv_key`: The private key as a BitArray used for signing.
///
/// # Returns
/// - `Result(String, String)`: On success, returns the signed JWT as a string.
///   On failure, returns an error message.
@external(erlang, "webpush_vapid_ffi", "jwt_es256_sign")
fn jwt_es256_sign(
  aud: String,
  exp_unix: Int,
  sub: String,
  priv_key: BitArray,
) -> Result(String, String)

/// Returns the current Unix timestamp as an integer.
/// This function is implemented externally in Erlang via the `webpush_vapid_ffi` module.
/// Useful for generating time-based values, such as VAPID token expiration.
@external(erlang, "webpush_vapid_ffi", "now_unix")
pub fn now_unix() -> Int

/// Generates a new pair of VAPID (Voluntary Application Server Identification) keys
/// using the P-256 elliptic curve. The private and public keys are encoded in
/// base64 URL-safe format. Returns a `Result` containing the generated `VapidKeys`
/// on success, or a `VapidError` if key generation fails.
///
/// # Returns
/// - `Ok(VapidKeys)`: Contains the base64 URL-encoded private and public keys.
/// - `Error(VapidError)`: Contains an error message if key generation fails.
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

/// Generates the `Authorization` header value required for Web Push (VAPID).
/// 
/// This function constructs a header in the format: `vapid t=<jwt>, k=<base64url(pub)>`,
/// where `<jwt>` is a JSON Web Token signed with the provided VAPID private key,
/// and `<base64url(pub)>` is the base64url-encoded VAPID public key.
/// 
/// Parameters:
/// - `endpoint`: The push service endpoint URL.
/// - `subscriber`: The subscriber's contact information (e.g., mailto address).
/// - `vapid_public_key_b64url`: The base64url-encoded VAPID public key.
/// - `vapid_private_key_b64url`: The base64url-encoded VAPID private key.
/// - `expiration_unix`: The expiration time for the JWT, as a Unix timestamp.
/// 
/// Returns:
/// - `Result(String, VapidError)`: On success, returns the header value as a string.
///   On failure, returns a `VapidError` describing the error.
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

  use sub <- result.try(normalize_subscriber(subscriber))
  use priv <- result.try(decode_private_key(vapid_private_key_b64url))
  use pub_bytes <- result.try(decode_public_key(vapid_public_key_b64url))

  use jwt <- result.try(
    jwt_es256_sign(aud, expiration_unix, sub, priv)
    |> result.map_error(CryptoError),
  )

  let pub_b64 = bit_array.base64_url_encode(pub_bytes, False)
  Ok("vapid t=" <> jwt <> ", k=" <> pub_b64)
}

/// RFC 8292 requires the `sub` claim to be a URI, but a bare email address is
/// the natural thing to pass, so the scheme is only added when absent.
fn normalize_subscriber(subscriber: String) -> Result(String, VapidError) {
  case string.trim(subscriber) {
    "" -> Error(InvalidSubscriber(subscriber))
    trimmed ->
      case has_scheme(trimmed) {
        True -> Ok(trimmed)
        False -> Ok("mailto:" <> trimmed)
      }
  }
}

/// Erlang's crypto signs with a private key of any length, producing a token no
/// push service can verify, so the size is checked rather than trusted.
fn decode_private_key(b64: String) -> Result(BitArray, VapidError) {
  use key <- result.try(
    decode_vapid_key(b64) |> result.map_error(fn(_) { DecodeKeyError }),
  )

  case key {
    <<_:bytes-size(32)>> -> Ok(key)
    _ -> Error(InvalidPrivateKey(bit_array.byte_size(key)))
  }
}

fn decode_public_key(b64: String) -> Result(BitArray, VapidError) {
  use key <- result.try(
    decode_vapid_key(b64) |> result.map_error(fn(_) { DecodeKeyError }),
  )

  case key {
    <<4, _:bytes-size(64)>> -> Ok(key)
    _ -> Error(InvalidPublicKey(bit_array.byte_size(key)))
  }
}

fn has_scheme(subscriber: String) -> Bool {
  string.starts_with(subscriber, "mailto:")
  || string.starts_with(subscriber, "https:")
  || string.starts_with(subscriber, "http:")
}

/// Extracts the audience (origin) from the given scheme and host options.
/// 
/// # Arguments
/// - `scheme`: An optional string representing the URL scheme (e.g., "https").
/// - `host`: An optional string representing the host (e.g., "example.com").
/// - `endpoint`: The endpoint string, used for error reporting.
/// 
/// # Returns
/// - `Ok(String)`: The concatenated audience string in the format "scheme://host" if both scheme and host are present.
/// - `Error(VapidError)`: An error if either scheme or host is missing, containing the invalid endpoint.
/// 
/// # Example
/// ```gleam
/// extract_audience(Some("https"), Some("example.com"), "https://example.com/endpoint")
/// // Ok("https://example.com")
/// ```
fn extract_audience(
  scheme: option.Option(String),
  host: option.Option(String),
  endpoint: String,
) -> Result(String, VapidError) {
  case scheme, host {
    option.Some(s), option.Some(h) if h != "" -> Ok(string.concat([s, "://", h]))
    _, _ -> Error(InvalidEndpoint(endpoint))
  }
}

/// Decodes a VAPID key from a base64 string.
///
/// Accepts either alphabet, padded or not: `base64_url_decode` maps the URL
/// safe characters onto the standard ones and restores any missing padding.
pub fn decode_vapid_key(b64: String) -> Result(BitArray, Nil) {
  bit_array.base64_url_decode(b64)
}
