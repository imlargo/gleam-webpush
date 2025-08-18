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

pub const max_record_size: Int = 4096

pub type Keys {
  Keys(auth: String, p256dh: String)
}

pub type Subscription {
  Subscription(endpoint: String, keys: Keys)
}

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

pub type PushError {
  DecodeKeyError
  InvalidPeerPublicKey
  CryptoError(String)
  HttpError(String)
  VapidHeaderError(vapid.VapidError)
  MaxPadExceeded
}

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

// ---------- FFI cripto (Erlang) ----------
@external(erlang, "webpush_push_ffi", "encrypt_payload")
fn encrypt_payload(
  message: BitArray,
  peer_pub_uncompressed: BitArray,
  auth_secret: BitArray,
  record_size: Int,
) -> Result(BitArray, String)

// from your existing module:
// pub fn vapid_authorization_header(...) -> Result(String, vapid.VapidError)

// ---------- API principal ----------

/// Envía una notificación Web Push cifrada (aes128gcm) con VAPID.
/// Devuelve la respuesta HTTP del endpoint push.
pub fn send_notification(
  message: BitArray,
  sub: Subscription,
  opts: Options,
) -> Result(response.Response(BitArray), PushError) {
  // 1) Decodificar claves
  use auth_secret <- result.try(decode_subscription_key(sub.keys.auth))
  use peer_pub <- result.try(decode_subscription_key(sub.keys.p256dh))

  // Verificar punto no comprimido (0x04 | X | Y)
  let valid_pub =
    bit_array.byte_size(peer_pub) >= 65
    && bit_array.slice(peer_pub, 0, 1) == Ok(bit_array.from_string("\u{04}"))

  case valid_pub {
    False -> Error(InvalidPeerPublicKey)
    True -> {
      // 2) Cifrar payload
      let record_size = case opts.record_size {
        option.Some(n) -> n
        option.None -> max_record_size
      }

      use body <- result.try(
        encrypt_payload(message, peer_pub, auth_secret, record_size)
        |> result.map_error(CryptoError),
      )

      // 3) VAPID
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

      // 4) Construir Request a partir de la URL completa
      use req0 <- result.try(
        request.to(sub.endpoint)
        |> result.map_error(fn(_) { HttpError("invalid endpoint url") }),
      )

      let req =
        req0
        |> request.set_method(http.Post)
        // IMPORTANTES: headers en minúsculas
        |> request.set_header("content-encoding", "aes128gcm")
        |> request.set_header("content-type", "application/octet-stream")
        |> request.set_header("ttl", int.to_string(opts.ttl))
        |> set_topic(opts.topic)
        |> set_urgency(opts.urgency)
        |> request.set_header("authorization", auth_header)
        // Body binario => cambia el tipo del Request a Request(BitArray)
        |> request.set_body(body)

      // Enviar binario
      case httpc.send_bits(req) {
        Ok(resp) -> Ok(resp)
        Error(_) -> Error(HttpError("http error"))
      }
    }
  }
}

// Helpers genéricos sobre el tipo del body
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

// ---------- Utilidades internas ----------

/// Decodifica base64 o base64url con relleno '=' si falta.
fn decode_subscription_key(b64: String) -> Result(BitArray, PushError) {
  let padded = case string.length(b64) % 4 {
    0 -> b64
    rem -> b64 <> string.repeat("=", 4 - rem)
  }

  // Intento Base64 estándar primero
  case bit_array.base64_decode(padded) {
    Ok(b) -> Ok(b)
    Error(_) -> {
      // Luego Base64URL
      case bit_array.base64_url_decode(padded) {
        Ok(b) -> Ok(b)
        Error(_) -> Error(DecodeKeyError)
      }
    }
  }
}
