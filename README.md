# Gleam Web Push

[![Package Version](https://img.shields.io/hexpm/v/webpush)](https://hex.pm/packages/webpush)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/webpush/)
[![License](https://img.shields.io/hexpm/l/webpush.svg)](https://github.com/your-username/gleam_webpush/blob/main/LICENSE)

The **first** and **complete** Web Push notification library for Gleam! 🎉

Send encrypted push notifications to web browsers using the Web Push Protocol (RFC 8291) with full VAPID (RFC 8292) support.

```sh
gleam add webpush@1
```

## ✨ Features

- 🔐 **RFC 8291 compliant encryption** with AES-128-GCM
- 🔑 **VAPID authentication** (RFC 8292) with ES256 JWT signing
- 🎯 **Complete Web Push API** support (TTL, urgency, topics)
- 🛡️ **Type-safe error handling** with comprehensive error types
- ⚡ **High performance** with Erlang FFI for cryptographic operations
- 📦 **Zero external dependencies** (uses built-in Erlang crypto)
- 🔧 **Easy to use** with sensible defaults

## 🚀 Quick Start

### Installation

Add `webpush` to your `gleam.toml`:

```toml
[dependencies]
webpush = "~> 1.0"
```

### Basic Usage

```gleam
import gleam/bit_array
import gleam/option
import webpush/push
import webpush/urgency
import webpush/vapid

pub fn main() {
  // 1. Generate VAPID keys (do this once, store securely)
  let assert Ok(keys) = vapid.generate_vapid_keys()
  
  // 2. Create subscription (from your frontend)
  let subscription = push.Subscription(
    endpoint: "https://fcm.googleapis.com/fcm/send/...",
    keys: push.Keys(
      auth: "authentication_secret_from_browser",
      p256dh: "user_public_key_from_browser"
    )
  )
  
  // 3. Configure push options
  let options = push.Options(
    ttl: 3600,                                    // 1 hour
    subscriber: "mailto:your-email@example.com",   // Your contact info
    vapid_public_key_b64url: keys.public_key_b64url,
    vapid_private_key_b64url: keys.private_key_b64url,
    topic: option.Some("updates"),
    urgency: option.Some(urgency.Normal),
    record_size: option.None,                     // Use default (4096)
    vapid_expiration_unix: option.None            // Use default (12h)
  )
  
  // 4. Create your message
  let payload = "{\"title\":\"Hello from Gleam!\",\"body\":\"Your notification message\"}"
  let message = bit_array.from_string(payload)
  
  // 5. Send the notification
  case push.send_notification(message, subscription, options) {
    Ok(response) -> {
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

#### `push.send_notification/3`
Send a push notification:

```gleam
pub fn send_notification(
  message: BitArray,
  subscription: Subscription, 
  options: Options
) -> Result(response.Response(BitArray), PushError)
```

#### `vapid.generate_vapid_keys/0`
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
gleam run   # Run the project
gleam test  # Run the tests
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

