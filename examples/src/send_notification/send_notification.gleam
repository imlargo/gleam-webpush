import gleam/bit_array
import gleam/int
import gleam/io
import gleam/option
import webpush/push
import webpush/urgency

// Paste the two keys printed by `gleam run -m generate_keys/generate_keys`.
const vapid_public_key = "PASTE_YOUR_VAPID_PUBLIC_KEY"

const vapid_private_key = "PASTE_YOUR_VAPID_PRIVATE_KEY"

// Your own contact address, so the push service operator can reach you.
const subscriber = "you@example.com"

pub fn main() {
  // Paste the block printed by the page in ../browser over this subscription.
  let subscription =
    push.Subscription(
      endpoint: "PASTE_YOUR_ENDPOINT",
      keys: push.Keys(auth: "PASTE_YOUR_AUTH", p256dh: "PASTE_YOUR_P256DH"),
    )

  let options =
    push.Options(
      ttl: 3600,
      subscriber: subscriber,
      vapid_public_key_b64url: vapid_public_key,
      vapid_private_key_b64url: vapid_private_key,
      topic: option.None,
      urgency: option.Some(urgency.Normal),
      record_size: option.None,
      vapid_expiration_unix: option.None,
    )

  let message =
    bit_array.from_string(
      "{\"title\":\"Hello from Gleam!\",\"body\":\"It works.\"}",
    )

  case push.send_notification(message, subscription, options) {
    Ok(response) ->
      case response.status {
        201 -> io.println("201 Created: the push service accepted it.")
        404 | 410 ->
          io.println("Subscription has expired, delete it and resubscribe.")
        status ->
          io.println(
            "Unexpected status "
            <> int.to_string(status)
            <> ": "
            <> body_to_string(response.body),
          )
      }
    Error(error) -> io.println("Failed: " <> push.push_error_to_string(error))
  }
}

fn body_to_string(body: BitArray) -> String {
  case bit_array.to_string(body) {
    Ok(text) -> text
    Error(_) -> "<binary response>"
  }
}
