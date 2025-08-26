import gleam/bit_array
import gleam/io
import gleam/option
import webpush/push
import webpush/urgency

pub fn main() {
  // 2. Create subscription (from your frontend)
  let subscription =
    push.Subscription(
      endpoint: "https://fcm.googleapis.com/fcm/send/...",
      keys: push.Keys(
        auth: "authentication_secret_from_browser",
        p256dh: "user_public_key_from_browser",
      ),
    )

  // 3. Configure push options
  let options =
    push.Options(
      ttl: 3600,
      // 1 hour
      subscriber: "mailto:your-email@example.com",
      // Your contact info
      vapid_public_key_b64url: "YOUR_PUBLIC_KEY",
      vapid_private_key_b64url: "YOUR_PRIVATE_KEY",
      topic: option.Some("updates"),
      urgency: option.Some(urgency.Normal),
      record_size: option.None,
      // Use default (4096)
      vapid_expiration_unix: option.None,
      // Use default (12h)
    )

  // 4. Create your message
  let payload =
    "{\"title\":\"Hello from Gleam!\",\"body\":\"Your notification message\"}"
  let message = bit_array.from_string(payload)

  // 5. Send the notification
  case push.send_notification(message, subscription, options) {
    Ok(_) -> {
      // Success! Check response.status for HTTP status code
      io.println("Notification sent successfully!")
    }
    Error(error) -> {
      // Handle error
      io.println("Failed to send: " <> push.push_error_to_string(error))
    }
  }
}
