import gleam/io
import webpush/vapid

pub fn main() {
  let assert Ok(keys) = vapid.generate_vapid_keys()

  io.println("Generated VAPID keys")
  io.println("Private Key: " <> keys.private_key_b64url)
  io.println("Public Key: " <> keys.public_key_b64url)
}
