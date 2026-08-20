# Gleam Web Push

[![Package Version](https://img.shields.io/hexpm/v/webpush)](https://hex.pm/packages/webpush)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/webpush/)
[![License](https://img.shields.io/hexpm/l/webpush.svg)](https://github.com/imlargo/gleam-webpush/blob/main/LICENSE)

The **first** and **complete** Web Push notification library for Gleam! 🎉

Send encrypted push notifications to web browsers using the Web Push Protocol (RFC 8291) with full VAPID (RFC 8292) support.

## Current Status

- Sends encrypted notifications to any Web Push service (RFC 8291)
- VAPID key generation and ES256 JWT signing (RFC 8292)
- No external dependencies: only Erlang/OTP's own `crypto` and `public_key`
- Covered by a test suite that verifies the JWT signature and decrypts the
  payload with an independent implementation of the receiving side, run on CI
  against OTP 27, 28 and 29

> Feedback and contributions are very welcome. If you spot something that could
> be done better, please open an issue or a pull request.

## ✨ Features

- 🔐 **RFC 8291 compliant encryption** with AES-128-GCM
- 🔑 **VAPID authentication** (RFC 8292) with ES256 JWT signing
- 🎯 **Complete Web Push API** support (TTL, urgency, topics)
- 🛡️ **Type-safe error handling** with comprehensive error types
- ⚡ **High performance** with Erlang FFI for cryptographic operations
- 📦 **No Erlang dependencies** (cryptography comes from OTP's own `crypto` and `public_key`)
- 🔧 **Easy to use** with sensible defaults

## 🚀 Quick Start

### Installation

Add `webpush` to your project:

```sh
gleam add webpush@2
```

### Requirements

- Gleam 1.11 or later
- Erlang/OTP 27 or later

### Basic Usage

#### Generate Keys

Using the library to generate VAPID keys:

> Note: Do this once and store the keys securely.

```gleam
import gleam/io
import webpush/vapid

pub fn main() {
  // Generate VAPID keys (do this once, store securely)
  let assert Ok(keys) = vapid.generate_vapid_keys()

  io.println("VAPID keys generated successfully!")
  io.println("Public Key: " <> keys.public_key_b64url)
  io.println("Private Key: " <> keys.private_key_b64url)
}
```

#### Send Notification

Using the library to send a push notification:

```gleam
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
```

## 📖 API Documentation

### Key Functions

#### `push.send_notification`
Send a push notification:

```gleam
pub fn send_notification(
  message: BitArray,
  subscription: Subscription, 
  options: Options
) -> Result(response.Response(BitArray), PushError)
```

#### `vapid.generate_vapid_keys`
Generate new VAPID key pair:

```gleam
pub fn generate_vapid_keys() -> Result(VapidKeys, VapidError)
```

## 🏗️ Architecture

This library uses Erlang FFI for performance-critical cryptographic operations:

- **P-256 ECDH** for key agreement
- **HKDF** for key derivation (RFC 5869)
- **AES-128-GCM** for payload encryption
- **ES256 JWT** signing for VAPID authentication

The Gleam layer provides type safety and ergonomic APIs while leveraging Erlang's battle-tested crypto implementations.

## Development

```sh
gleam test        # Run the tests
gleam docs build  # Build the documentation
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built following [RFC 8291](https://tools.ietf.org/html/rfc8291) (Web Push Encryption)
- VAPID implementation per [RFC 8292](https://tools.ietf.org/html/rfc8292)
- Inspired by web push libraries in other languages

---

**Made with ✨ by the Gleam community**

*This is the first Web Push library for Gleam - help us make it even better!*

Further documentation can be found at <https://hexdocs.pm/webpush>.

