import gleam/io
import webpush/vapid

pub fn main() {
  // Generate VAPID keys (do this once, store securely)
  let assert Ok(keys) = vapid.generate_vapid_keys()

  io.println("VAPID keys generated successfully!")
  io.println("Public Key: " <> keys.public_key_b64url)
  io.println("Private Key: " <> keys.private_key_b64url)
}
