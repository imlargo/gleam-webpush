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
) -> Result(response.Response(String), PushError) {
  // 1) Decodificar claves de suscripción
  use auth_secret <- result.try(decode_subscription_key(sub.keys.auth))
  use peer_pub <- result.try(decode_subscription_key(sub.keys.p256dh))

  // Comprobar que sea punto no comprimido (65 bytes, empieza en 0x04)
  let valid_pub =
    bit_array.byte_size(peer_pub) >= 65
    && bit_array.slice(peer_pub, 0, 1) == Ok(bit_array.from_string("\u{04}"))

  case valid_pub {
    False -> Error(InvalidPeerPublicKey)
    True -> {
      // 2) Cifrar payload y construir cuerpo (salt + rs + pub + ciphertext)
      let record_size = case opts.record_size {
        option.Some(n) -> n
        option.None -> max_record_size
      }

      use body <- result.try(
        encrypt_payload(message, peer_pub, auth_secret, record_size)
        |> result.map_error(CryptoError),
      )

      // 3) Header de autorización VAPID
      let exp = case opts.vapid_expiration_unix {
        option.Some(e) -> e
        option.None -> vapid.now_unix() + 60 * 60 * 12
        // 12h por defecto
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

      use body_string <- result.try(
        bit_array.to_string(body) |> result.map_error(fn(_) { HttpError("") }),
      )

      // 4) Construir y enviar la petición HTTP POST
      let req =
        request.new()
        |> request.set_method(http.Post)
        |> request.set_host(sub.endpoint)
        |> request.set_header("Content-Encoding", "aes128gcm")
        |> request.set_header("Content-Type", "application/octet-stream")
        |> request.set_header("TTL", int.to_string(opts.ttl))
        |> set_topic(opts.topic)
        |> set_urgency(opts.urgency)
        |> request.set_header("Authorization", auth_header)
        |> request.set_body(body_string)

      case httpc.send(req) {
        Ok(resp) -> Ok(resp)
        Error(_) -> Error(HttpError("http error"))
      }
    }
  }
}

fn set_topic(
  req: request.Request(String),
  topic: option.Option(String),
) -> request.Request(String) {
  case topic {
    option.Some(t) -> request.set_header(req, "Topic", t)
    option.None -> req
  }
}

fn set_urgency(
  req: request.Request(String),
  urgency: option.Option(urgency.Urgency),
) -> request.Request(String) {
  case urgency {
    option.Some(u) -> request.set_header(req, "Urgency", urgency.to_string(u))
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
