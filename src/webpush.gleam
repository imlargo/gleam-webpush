import gleam/io
import webpush/vapid

pub fn main() {
  case vapid.generate_vapid_keys() {
    Ok(keys) -> io.print("Generated VAPID keys: " <> keys.private_key_b64url)
    Error(_) -> io.print("Failed to generate VAPID keys: ")
  }
}
