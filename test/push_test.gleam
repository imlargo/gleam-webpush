import gleam/bit_array
import gleam/option
import gleam/string
import webpush/push
import webpush/urgency
import webpush/vapid

const endpoint = "https://fcm.googleapis.com/fcm/send/abc123"

/// The auth secret a browser derives, 16 bytes.
const auth_secret = <<
  0x9c, 0x2f, 0x41, 0xdb, 0x7a, 0x03, 0xe8, 0x55, 0x11, 0x6e, 0x4f, 0x2a, 0xb0,
  0xcd, 0x18, 0x37,
>>

@external(erlang, "webpush_push_ffi", "encrypt_payload")
fn encrypt_payload(
  message: BitArray,
  peer_public_key: BitArray,
  auth_secret: BitArray,
  record_size: Int,
) -> Result(BitArray, String)

@external(erlang, "webpush_test_ffi", "decrypt")
fn decrypt(
  body: BitArray,
  private_key: BitArray,
  public_key: BitArray,
  auth_secret: BitArray,
) -> Result(BitArray, String)

/// A stand in for a browser: a P-256 key pair and the auth secret.
type Recipient {
  Recipient(private_key: BitArray, public_key: BitArray)
}

fn recipient() -> Recipient {
  let assert Ok(keys) = vapid.generate_vapid_keys()
  let assert Ok(private_key) =
    bit_array.base64_url_decode(keys.private_key_b64url)
  let assert Ok(public_key) =
    bit_array.base64_url_decode(keys.public_key_b64url)

  Recipient(private_key:, public_key:)
}

fn round_trip(
  recipient: Recipient,
  message: BitArray,
  record_size: Int,
) -> Result(BitArray, String) {
  case
    encrypt_payload(message, recipient.public_key, auth_secret, record_size)
  {
    Error(error) -> Error(error)
    Ok(body) ->
      decrypt(body, recipient.private_key, recipient.public_key, auth_secret)
  }
}

pub fn payload_round_trips_test() {
  let recipient = recipient()
  let message = <<"{\"title\":\"Hello from Gleam!\"}":utf8>>

  assert round_trip(recipient, message, push.max_record_size) == Ok(message)
}

pub fn empty_payload_round_trips_test() {
  assert round_trip(recipient(), <<>>, push.max_record_size) == Ok(<<>>)
}

pub fn largest_payload_round_trips_test() {
  // 4096 minus the 86 byte header, the 0x02 delimiter and the 16 byte tag.
  let message = bit_array.from_string(string.repeat("a", 3993))

  assert round_trip(recipient(), message, push.max_record_size) == Ok(message)
}

pub fn payload_beyond_the_record_is_rejected_test() {
  let message = bit_array.from_string(string.repeat("a", 3994))

  assert round_trip(recipient(), message, push.max_record_size)
    == Error("payload has exceeded the maximum length")
}

pub fn payload_round_trips_at_a_smaller_record_size_test() {
  let message = <<"small record">>

  assert round_trip(recipient(), message, 512) == Ok(message)
}

pub fn each_message_uses_a_fresh_salt_and_ephemeral_key_test() {
  let recipient = recipient()
  let assert Ok(first) =
    encrypt_payload(<<"hi">>, recipient.public_key, auth_secret, 4096)
  let assert Ok(second) =
    encrypt_payload(<<"hi">>, recipient.public_key, auth_secret, 4096)

  assert first != second
}

pub fn another_recipient_cannot_decrypt_test() {
  let subscriber = recipient()
  let eavesdropper = recipient()
  let assert Ok(body) =
    encrypt_payload(<<"secret">>, subscriber.public_key, auth_secret, 4096)

  let assert Error(_) =
    decrypt(
      body,
      eavesdropper.private_key,
      eavesdropper.public_key,
      auth_secret,
    )
}

fn options() -> push.Options {
  let assert Ok(keys) = vapid.generate_vapid_keys()

  push.Options(
    ttl: 0,
    subscriber: "test@example.com",
    vapid_public_key_b64url: keys.public_key_b64url,
    vapid_private_key_b64url: keys.private_key_b64url,
    topic: option.None,
    urgency: option.Some(urgency.Normal),
    record_size: option.None,
    vapid_expiration_unix: option.Some(1_760_000_000),
  )
}

// The following reach `send_notification` but fail validation before any
// request is made, so they never touch the network.

pub fn undecodable_subscription_key_is_rejected_test() {
  let subscription =
    push.Subscription(
      endpoint: endpoint,
      keys: push.Keys(auth: "not base64!", p256dh: "not base64!"),
    )

  assert push.send_notification(<<"hi">>, subscription, options())
    == Error(push.DecodeKeyError)
}

pub fn non_uncompressed_public_key_is_rejected_test() {
  let recipient = recipient()
  let assert Ok(truncated) = bit_array.slice(recipient.public_key, 0, 64)
  let subscription =
    push.Subscription(
      endpoint: endpoint,
      keys: push.Keys(
        auth: bit_array.base64_url_encode(auth_secret, False),
        p256dh: bit_array.base64_url_encode(truncated, False),
      ),
    )

  assert push.send_notification(<<"hi">>, subscription, options())
    == Error(push.InvalidPeerPublicKey)
}

pub fn oversized_public_key_is_rejected_test() {
  let recipient = recipient()
  let padded = bit_array.append(recipient.public_key, <<0>>)
  let subscription =
    push.Subscription(
      endpoint: endpoint,
      keys: push.Keys(
        auth: bit_array.base64_url_encode(auth_secret, False),
        p256dh: bit_array.base64_url_encode(padded, False),
      ),
    )

  assert push.send_notification(<<"hi">>, subscription, options())
    == Error(push.InvalidPeerPublicKey)
}

pub fn invalid_endpoint_is_rejected_test() {
  let recipient = recipient()
  let subscription =
    push.Subscription(
      endpoint: "not-a-url",
      keys: push.Keys(
        auth: bit_array.base64_url_encode(auth_secret, False),
        p256dh: bit_array.base64_url_encode(recipient.public_key, False),
      ),
    )

  assert push.send_notification(<<"hi">>, subscription, options())
    == Error(push.VapidHeaderError(vapid.InvalidEndpoint("not-a-url")))
}

pub fn errors_describe_themselves_test() {
  assert push.push_error_to_string(push.DecodeKeyError)
    == "Failed to decode key"
  assert push.push_error_to_string(push.InvalidPeerPublicKey)
    == "Invalid peer public key format"
  assert push.push_error_to_string(
      push.VapidHeaderError(vapid.InvalidEndpoint("nope")),
    )
    == "VAPID header error: Invalid endpoint: nope"
}
