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

pub fn oversized_payload_reports_max_pad_exceeded_test() {
  let recipient = recipient()
  let subscription =
    push.Subscription(
      endpoint: endpoint,
      keys: push.Keys(
        auth: bit_array.base64_url_encode(auth_secret, False),
        p256dh: bit_array.base64_url_encode(recipient.public_key, False),
      ),
    )
  let message = bit_array.from_string(string.repeat("a", 3994))

  assert push.send_notification(message, subscription, options())
    == Error(push.MaxPadExceeded)
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

pub fn subscription_keys_decode_in_either_alphabet_test() {
  // Reaching the VAPID stage proves both keys decoded and the public key
  // passed validation; a decoding failure would report DecodeKeyError.
  let recipient = recipient()
  let standard =
    push.Subscription(
      endpoint: "not-a-url",
      keys: push.Keys(
        auth: bit_array.base64_encode(auth_secret, True),
        p256dh: bit_array.base64_encode(recipient.public_key, True),
      ),
    )
  let url_safe =
    push.Subscription(
      endpoint: "not-a-url",
      keys: push.Keys(
        auth: bit_array.base64_url_encode(auth_secret, False),
        p256dh: bit_array.base64_url_encode(recipient.public_key, False),
      ),
    )
  let expected =
    Error(push.VapidHeaderError(vapid.InvalidEndpoint("not-a-url")))

  assert push.send_notification(<<"hi">>, standard, options()) == expected
  assert push.send_notification(<<"hi">>, url_safe, options()) == expected
}

pub fn max_payload_size_matches_the_encryption_limit_test() {
  // Ties the exported limit to what the encryption actually accepts, so the
  // two cannot drift apart.
  let recipient = recipient()
  let max = push.max_payload_size(push.max_record_size)
  let fill = fn(size) { bit_array.from_string(string.repeat("a", size)) }

  assert max == 3993
  let assert Ok(_) =
    encrypt_payload(fill(max), recipient.public_key, auth_secret, 4096)
  let assert Error(_) =
    encrypt_payload(fill(max + 1), recipient.public_key, auth_secret, 4096)
}

pub fn public_key_off_the_curve_is_a_crypto_error_test() {
  // 65 bytes with the right prefix, so it passes the shape check, but not a
  // point on P-256.
  let subscription =
    push.Subscription(
      endpoint: endpoint,
      keys: push.Keys(
        auth: bit_array.base64_url_encode(auth_secret, False),
        p256dh: bit_array.base64_url_encode(<<4, 0:size(512)>>, False),
      ),
    )

  let assert Error(push.CryptoError(_)) =
    push.send_notification(<<"hi">>, subscription, options())
}

/// The worked example from RFC 8291 section 5, verbatim.
const rfc8291_receiver_public = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"

const rfc8291_receiver_private = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"

const rfc8291_auth_secret = "BTBZMqHH6r4Tts7J_aSIgg"

const rfc8291_body = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"

const rfc8291_plaintext = "When I grow up, I want to be a watermelon"

/// Decrypting the payload published in the RFC proves the key derivation
/// matches the specification, rather than merely being self consistent.
pub fn rfc8291_test_vector_decrypts_test() {
  let assert Ok(body) = bit_array.base64_url_decode(rfc8291_body)
  let assert Ok(private_key) =
    bit_array.base64_url_decode(rfc8291_receiver_private)
  let assert Ok(public_key) =
    bit_array.base64_url_decode(rfc8291_receiver_public)
  let assert Ok(auth) = bit_array.base64_url_decode(rfc8291_auth_secret)

  assert decrypt(body, private_key, public_key, auth)
    == Ok(bit_array.from_string(rfc8291_plaintext))
}

/// With the decryption above pinned to the RFC, encrypting and reading the
/// result back shows this library produces what the specification describes.
pub fn payload_encrypted_for_the_rfc_receiver_round_trips_test() {
  let assert Ok(private_key) =
    bit_array.base64_url_decode(rfc8291_receiver_private)
  let assert Ok(public_key) =
    bit_array.base64_url_decode(rfc8291_receiver_public)
  let assert Ok(auth) = bit_array.base64_url_decode(rfc8291_auth_secret)
  let message = bit_array.from_string(rfc8291_plaintext)

  let assert Ok(body) = encrypt_payload(message, public_key, auth, 4096)

  assert decrypt(body, private_key, public_key, auth) == Ok(message)
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
