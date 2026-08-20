import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import webpush/vapid

const endpoint = "https://fcm.googleapis.com/fcm/send/abc123"

const expiration = 1_760_000_000

@external(erlang, "webpush_test_ffi", "verify_es256")
fn verify_es256(signed: BitArray, signature: BitArray, key: BitArray) -> Bool

fn keys() -> vapid.VapidKeys {
  let assert Ok(keys) = vapid.generate_vapid_keys()
  keys
}

fn header_for(subscriber: String) -> String {
  let keys = keys()
  let assert Ok(header) =
    vapid.vapid_authorization_header(
      endpoint,
      subscriber,
      keys.public_key_b64url,
      keys.private_key_b64url,
      expiration,
    )
  header
}

pub fn generate_vapid_keys_produces_a_p256_pair_test() {
  let keys = keys()
  let assert Ok(private_key) =
    bit_array.base64_url_decode(keys.private_key_b64url)
  let assert Ok(public_key) =
    bit_array.base64_url_decode(keys.public_key_b64url)

  assert bit_array.byte_size(private_key) == 32
  assert bit_array.byte_size(public_key) == 65
  assert bit_array.slice(public_key, 0, 1) == Ok(<<4>>)
}

pub fn generate_vapid_keys_is_not_deterministic_test() {
  assert keys() != keys()
}

pub fn generated_keys_are_url_safe_and_unpadded_test() {
  let keys = keys()

  assert !string.contains(keys.public_key_b64url, "+")
  assert !string.contains(keys.public_key_b64url, "/")
  assert !string.contains(keys.public_key_b64url, "=")
}

pub fn header_uses_the_vapid_scheme_test() {
  let keys = keys()
  let assert Ok(header) =
    vapid.vapid_authorization_header(
      endpoint,
      "test@example.com",
      keys.public_key_b64url,
      keys.private_key_b64url,
      expiration,
    )

  assert string.starts_with(header, "vapid t=")
  assert string.ends_with(header, ", k=" <> keys.public_key_b64url)
  assert list.length(string.split(jwt(header), ".")) == 3
}

pub fn jwt_header_declares_es256_test() {
  let assert Ok(header) = part(header_for("test@example.com"), 0)

  assert field(header, "alg", decode.string) == Ok("ES256")
  assert field(header, "typ", decode.string) == Ok("JWT")
}

pub fn audience_is_the_endpoint_origin_test() {
  let assert Ok(claims) = part(header_for("test@example.com"), 1)

  assert field(claims, "aud", decode.string) == Ok("https://fcm.googleapis.com")
  assert field(claims, "exp", decode.int) == Ok(expiration)
}

pub fn bare_email_gains_a_mailto_scheme_test() {
  let assert Ok(claims) = part(header_for("test@example.com"), 1)

  assert field(claims, "sub", decode.string) == Ok("mailto:test@example.com")
}

pub fn existing_mailto_scheme_is_not_repeated_test() {
  let assert Ok(claims) = part(header_for("mailto:test@example.com"), 1)

  assert field(claims, "sub", decode.string) == Ok("mailto:test@example.com")
}

pub fn https_subscriber_is_left_alone_test() {
  let assert Ok(claims) = part(header_for("https://example.com/contact"), 1)

  assert field(claims, "sub", decode.string)
    == Ok("https://example.com/contact")
}

pub fn signature_verifies_against_the_public_key_test() {
  let keys = keys()
  let assert Ok(header) =
    vapid.vapid_authorization_header(
      endpoint,
      "test@example.com",
      keys.public_key_b64url,
      keys.private_key_b64url,
      expiration,
    )
  let assert Ok(#(signed, signature)) = split_signature(jwt(header))
  let assert Ok(public_key) =
    bit_array.base64_url_decode(keys.public_key_b64url)

  assert bit_array.byte_size(signature) == 64
  assert verify_es256(signed, signature, public_key)
  assert !verify_es256(bit_array.append(signed, <<"x">>), signature, public_key)
}

pub fn signature_does_not_verify_against_another_key_test() {
  let assert Ok(#(signed, signature)) =
    split_signature(jwt(header_for("test@example.com")))
  let assert Ok(other) = bit_array.base64_url_decode(keys().public_key_b64url)

  assert !verify_es256(signed, signature, other)
}

pub fn endpoint_without_a_host_is_rejected_test() {
  let keys = keys()

  assert vapid.vapid_authorization_header(
      "not-a-url",
      "test@example.com",
      keys.public_key_b64url,
      keys.private_key_b64url,
      expiration,
    )
    == Error(vapid.InvalidEndpoint("not-a-url"))
}

pub fn undecodable_key_is_rejected_test() {
  assert vapid.vapid_authorization_header(
      endpoint,
      "test@example.com",
      "not base64!",
      "not base64!",
      expiration,
    )
    == Error(vapid.DecodeKeyError)
}

pub fn keys_decode_in_either_alphabet_padded_or_not_test() {
  // A value whose standard encoding uses both `+` and `/`, so the two
  // alphabets genuinely differ.
  let raw = <<4, 251, 255, 62, 63, 190, 0:size(472)>>

  assert vapid.decode_vapid_key(bit_array.base64_encode(raw, True)) == Ok(raw)
  assert vapid.decode_vapid_key(bit_array.base64_encode(raw, False)) == Ok(raw)
  assert vapid.decode_vapid_key(bit_array.base64_url_encode(raw, True))
    == Ok(raw)
  assert vapid.decode_vapid_key(bit_array.base64_url_encode(raw, False))
    == Ok(raw)
}

pub fn undecodable_vapid_key_is_an_error_test() {
  assert vapid.decode_vapid_key("not base64!") == Error(Nil)
}

pub fn wrong_sized_private_key_is_rejected_test() {
  // Erlang's crypto signs with a key of any length, so without this check the
  // library hands back a token that no push service can verify.
  let keys = keys()

  assert vapid.vapid_authorization_header(
      endpoint,
      "test@example.com",
      keys.public_key_b64url,
      bit_array.base64_url_encode(<<1, 2, 3>>, False),
      expiration,
    )
    == Error(vapid.InvalidPrivateKey(3))
}

pub fn wrong_sized_public_key_is_rejected_test() {
  let keys = keys()

  assert vapid.vapid_authorization_header(
      endpoint,
      "test@example.com",
      bit_array.base64_url_encode(<<1, 2, 3>>, False),
      keys.private_key_b64url,
      expiration,
    )
    == Error(vapid.InvalidPublicKey(3))
}

pub fn empty_subscriber_is_rejected_test() {
  let keys = keys()

  assert vapid.vapid_authorization_header(
      endpoint,
      "   ",
      keys.public_key_b64url,
      keys.private_key_b64url,
      expiration,
    )
    == Error(vapid.InvalidSubscriber("   "))
}

pub fn endpoint_without_a_host_is_rejected_even_with_a_scheme_test() {
  // uri.parse("https://") yields Some("") for the host, which would produce an
  // audience of "https://".
  let keys = keys()

  assert vapid.vapid_authorization_header(
      "https://",
      "test@example.com",
      keys.public_key_b64url,
      keys.private_key_b64url,
      expiration,
    )
    == Error(vapid.InvalidEndpoint("https://"))
}

pub fn subscriber_is_trimmed_test() {
  let assert Ok(claims) = part(header_for("  test@example.com  "), 1)

  assert field(claims, "sub", decode.string) == Ok("mailto:test@example.com")
}

pub fn mismatched_key_pair_is_rejected_test() {
  // Erlang's crypto signs with any 32 byte value, so a private key from a
  // different pair still produces a header; the push service then rejects it
  // with an opaque 401. Both orderings of the mix up are caught.
  let one = keys()
  let other = keys()

  assert vapid.vapid_authorization_header(
      endpoint,
      "test@example.com",
      one.public_key_b64url,
      other.private_key_b64url,
      expiration,
    )
    == Error(vapid.MismatchedKeyPair)

  assert vapid.vapid_authorization_header(
      endpoint,
      "test@example.com",
      other.public_key_b64url,
      one.private_key_b64url,
      expiration,
    )
    == Error(vapid.MismatchedKeyPair)
}

pub fn structurally_valid_but_unusable_private_key_is_rejected_test() {
  // 32 bytes, so the size check passes, but not a usable scalar.
  let keys = keys()

  let assert Error(_) =
    vapid.vapid_authorization_header(
      endpoint,
      "test@example.com",
      keys.public_key_b64url,
      bit_array.base64_url_encode(<<0:size(256)>>, False),
      expiration,
    )
}

pub fn now_unix_is_in_seconds_test() {
  let now = vapid.now_unix()

  assert now > 1_577_836_800
  assert now < 4_102_444_800
}

fn jwt(header: String) -> String {
  let assert Ok(#(_, rest)) = string.split_once(header, "vapid t=")
  let assert Ok(#(jwt, _)) = string.split_once(rest, ", k=")
  jwt
}

/// The decoded JSON of the header (0) or claims (1) part of the JWT.
fn part(header: String, index: Int) -> Result(String, Nil) {
  use part <- result.try(at(string.split(jwt(header), "."), index))
  use decoded <- result.try(bit_array.base64_url_decode(part))
  bit_array.to_string(decoded)
}

fn at(items: List(a), index: Int) -> Result(a, Nil) {
  case items, index {
    [item, ..], 0 -> Ok(item)
    [_, ..rest], _ -> at(rest, index - 1)
    [], _ -> Error(Nil)
  }
}

fn split_signature(jwt: String) -> Result(#(BitArray, BitArray), Nil) {
  case string.split(jwt, ".") {
    [header, claims, signature] -> {
      use signature <- result.try(bit_array.base64_url_decode(signature))
      Ok(#(bit_array.from_string(header <> "." <> claims), signature))
    }
    _ -> Error(Nil)
  }
}

fn field(
  document: String,
  name: String,
  decoder: decode.Decoder(a),
) -> Result(a, Nil) {
  json.parse(document, decode.at([name], decoder)) |> result.replace_error(Nil)
}
