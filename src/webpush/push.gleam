import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/httpc
import gleam/int
import gleam/option
import gleam/result
import gleam/string
import webpush/urgency
import webpush/vapid

/// The maximum allowed size for a record in bytes.
pub const max_record_size: Int = 4096

/// Represents the cryptographic keys used for authentication and encryption in a push subscription.
/// - `auth`: The authentication secret as a base64url-encoded string.
/// - `p256dh`: The user's public key as a base64url-encoded string.
pub type Keys {
  Keys(auth: String, p256dh: String)
}

/// Represents a push subscription, including the endpoint and associated keys.
/// - `endpoint`: The URL to which push messages are sent.
/// - `keys`: The cryptographic keys for the subscription.
pub type Subscription {
  Subscription(endpoint: String, keys: Keys)
}

/// Options for sending a push notification.
/// - `ttl`: Time to live for the push message in seconds.
/// - `subscriber`: The subscriber's contact information (e.g., email).
/// - `vapid_public_key_b64url`: VAPID public key as a base64url-encoded string.
/// - `vapid_private_key_b64url`: VAPID private key as a base64url-encoded string.
/// - `topic`: Optional topic for the push message.
/// - `urgency`: Optional urgency level for the push message.
/// - `record_size`: Optional maximum record size for the push message.
/// - `vapid_expiration_unix`: Optional VAPID token expiration time as a Unix timestamp.
pub type Options {
  Options(
    ttl: Int,
    subscriber: String,
    vapid_public_key_b64url: String,
    vapid_private_key_b64url: String,
    topic: option.Option(String),
    urgency: option.Option(urgency.Urgency),
    record_size: option.Option(Int),
    vapid_expiration_unix: option.Option(Int),
  )
}

/// Represents the possible errors that can occur during the push notification process.
/// 
/// - `DecodeKeyError`: Indicates a failure to decode a cryptographic key.
/// - `InvalidPeerPublicKey`: The provided peer public key is in an invalid format.
/// - `CryptoError(String)`: A cryptographic operation failed, with an associated error message.
/// - `HttpError(String)`: An HTTP request or response error, with an associated error message.
/// - `VapidHeaderError(vapid.VapidError)`: An error occurred while handling the VAPID header.
/// - `MaxPadExceeded`: The payload size has exceeded the allowed maximum length.
pub type PushError {
  DecodeKeyError
  InvalidPeerPublicKey
  CryptoError(String)
  HttpError(String)
  VapidHeaderError(vapid.VapidError)
  MaxPadExceeded
}

/// Converts a `PushError` value into a human-readable string description.
/// 
/// This function matches on the provided `PushError` and returns a descriptive
/// error message for each variant, including decoding errors, cryptographic errors,
/// HTTP errors, VAPID header errors, and payload length issues.
/// 
/// - `DecodeKeyError`: Indicates a failure to decode a key.
/// - `InvalidPeerPublicKey`: Indicates an invalid peer public key format.
/// - `CryptoError(msg)`: Indicates a cryptographic error with a message.
/// - `HttpError(msg)`: Indicates an HTTP error with a message.
/// - `VapidHeaderError(vapid_err)`: Indicates a VAPID header error, with details from `vapid_error_to_string`.
/// - `MaxPadExceeded`: Indicates the payload has exceeded the maximum allowed length.
/// 
/// Returns: A string describing the error.
pub fn push_error_to_string(error: PushError) -> String {
  case error {
    DecodeKeyError -> "Failed to decode key"
    InvalidPeerPublicKey -> "Invalid peer public key format"
    CryptoError(msg) -> "Crypto error: " <> msg
    HttpError(msg) -> "HTTP error: " <> msg
    VapidHeaderError(vapid_err) ->
      "VAPID header error: " <> vapid.vapid_error_to_string(vapid_err)
    MaxPadExceeded -> "Payload has exceeded the maximum length"
  }
}

/// Encrypts a payload for Web Push using the provided message, peer's public key,
/// authentication secret, and record size. This function uses Erlang FFI for cryptographic
/// operations. Returns either the encrypted payload as a `BitArray` or an error message.
///
/// - `message`: The payload to be encrypted.
/// - `peer_pub_uncompressed`: The uncompressed public key of the peer.
/// - `auth_secret`: The authentication secret used for encryption.
/// - `record_size`: The size of each record in the encrypted payload.
///
/// Returns: `Result(BitArray, String)` containing the encrypted payload or an error.
@external(erlang, "webpush_push_ffi", "encrypt_payload")
fn encrypt_payload(
  message: BitArray,
  peer_pub_uncompressed: BitArray,
  auth_secret: BitArray,
  record_size: Int,
) -> Result(BitArray, String)

/// Sends a web push notification to a subscriber.
///
/// This function performs the following steps:
/// 1. Decodes the authentication and peer public keys from the subscription.
/// 2. Validates the peer public key format (must be uncompressed).
/// 3. Encrypts the payload using the provided keys and record size.
/// 4. Generates a VAPID authorization header for authentication.
/// 5. Constructs an HTTP request with the appropriate headers and binary body.
/// 6. Sends the request and returns the response or an error.
///
/// # Arguments
/// - `message`: The payload to send as a `BitArray`.
/// - `sub`: The subscription information containing endpoint and keys.
/// - `opts`: Options for the push notification, such as TTL, topic, urgency, and VAPID keys.
///
/// # Returns
/// - `Ok(response.Response(BitArray))`: The HTTP response on success.
/// - `Error(PushError)`: An error if any step fails (e.g., invalid keys, encryption, HTTP).
///
pub fn send_notification(
  message: BitArray,
  sub: Subscription,
  opts: Options,
) -> Result(response.Response(BitArray), PushError) {
  // Decode keys
  use auth_secret <- result.try(decode_subscription_key(sub.keys.auth))
  use peer_pub <- result.try(decode_subscription_key(sub.keys.p256dh))

  // Verify uncompressed point (0x04 | X | Y)
  let valid_pub =
    bit_array.byte_size(peer_pub) >= 65
    && bit_array.slice(peer_pub, 0, 1) == Ok(bit_array.from_string("\u{04}"))

  case valid_pub {
    False -> Error(InvalidPeerPublicKey)
    True -> {
      // Encrypt payload
      let record_size = case opts.record_size {
        option.Some(n) -> n
        option.None -> max_record_size
      }

      use body <- result.try(
        encrypt_payload(message, peer_pub, auth_secret, record_size)
        |> result.map_error(CryptoError),
      )

      // VAPID
      let exp = case opts.vapid_expiration_unix {
        option.Some(e) -> e
        option.None -> vapid.now_unix() + 60 * 60 * 12
      }

      use auth_header <- result.try(
        vapid.vapid_authorization_header(
          sub.endpoint,
          opts.subscriber,
          opts.vapid_public_key_b64url,
          opts.vapid_private_key_b64url,
          exp,
        )
        |> result.map_error(VapidHeaderError),
      )

      // Build Request from the full URL
      use req0 <- result.try(
        request.to(sub.endpoint)
        |> result.map_error(fn(_) { HttpError("invalid endpoint url") }),
      )

      let req =
        req0
        |> request.set_method(http.Post)
        |> request.set_header("content-encoding", "aes128gcm")
        |> request.set_header("content-type", "application/octet-stream")
        |> request.set_header("ttl", int.to_string(opts.ttl))
        |> set_topic(opts.topic)
        |> set_urgency(opts.urgency)
        |> request.set_header("authorization", auth_header)
        |> request.set_body(body)

      case httpc.send_bits(req) {
        Ok(resp) -> Ok(resp)
        Error(_) -> Error(HttpError("http error"))
      }
    }
  }
}

fn set_topic(
  req: request.Request(a),
  topic: option.Option(String),
) -> request.Request(a) {
  case topic {
    option.Some(t) -> request.set_header(req, "topic", t)
    option.None -> req
  }
}

fn set_urgency(
  req: request.Request(a),
  u: option.Option(urgency.Urgency),
) -> request.Request(a) {
  case u {
    option.Some(val) ->
      request.set_header(req, "urgency", urgency.to_string(val))
    option.None -> req
  }
}

/// Decodes a base64 or base64url-encoded subscription key string into a `BitArray`.
/// The function first attempts standard base64 decoding, and if that fails,
/// it tries base64url decoding. Padding is added if necessary to ensure the input
/// length is a multiple of 4. Returns `Ok(BitArray)` on success, or `Error(PushError)`
/// if decoding fails.
fn decode_subscription_key(b64: String) -> Result(BitArray, PushError) {
  let padded = case string.length(b64) % 4 {
    0 -> b64
    rem -> b64 <> string.repeat("=", 4 - rem)
  }

  case bit_array.base64_decode(padded) {
    Ok(b) -> Ok(b)
    Error(_) -> {
      case bit_array.base64_url_decode(padded) {
        Ok(b) -> Ok(b)
        Error(_) -> Error(DecodeKeyError)
      }
    }
  }
}
