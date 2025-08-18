import gleam/bit_array
import gleam/io
import gleam/option
import webpush/push
import webpush/urgency

pub fn main() {
  let sub =
    push.Subscription("subhere", push.Keys(auth: "authhere", p256dh: "p2here"))

  let opts =
    push.Options(
      ttl: 30,
      subscriber: "test@gmail.com",
      vapid_public_key_b64url: "key",
      vapid_private_key_b64url: "key",
      topic: option.None,
      urgency: option.Some(urgency.Normal),
      record_size: option.None,
      vapid_expiration_unix: option.None,
    )

  let payload =
    "{\"title\":\"Hi from gleam\",\"message\":\"Hi imlargo!\",\"category\":\"imlargo\"}"
  let message = bit_array.from_string(payload)

  case push.send_notification(message, sub, opts) {
    Ok(resp) -> resp.status
    Error(e) -> {
      io.println(push.push_error_to_string(e))
      1
    }
  }
}
