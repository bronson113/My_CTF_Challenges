import dot_env/env
import gleam/bit_array
import gleam/crypto
import gleam/http
import gleam/http/cookie
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option
import gleam/result
import glen.{type Request, type Response}

fn load_application_secret() -> String {
  env.get_or("APPLICATION_SECRET", "27434b28994f498182d459335258fb6e")
}

pub fn load_authorization_key() -> Int {
  env.get_or("AUTHORIZATION_KEY", "100000009")
  |> int.parse
  |> result.unwrap(100_000_009)
}

/// The body of a HTTP response, to be sent to the client.
///
pub fn set_cookie(
  response response: Response,
  request request: Request,
  name name: String,
  value value: String,
  security security: Security,
  max_age max_age: Int,
) -> Response {
  let attributes =
    cookie.Attributes(
      ..cookie.defaults(http.Http),
      max_age: option.Some(max_age),
    )
  let value = case security {
    PlainText -> bit_array.base64_encode(<<value:utf8>>, False)
    Signed -> sign_message(request, <<value:utf8>>, crypto.Sha512)
  }
  response
  |> response.set_cookie(name, value, attributes)
}

pub type Security {
  PlainText
  Signed
}

pub fn get_cookie(
  request: Request,
  name: String,
  security: Security,
) -> Result(String, Nil) {
  use value <- result.try(
    request
    |> request.get_cookies
    |> list.key_find(name),
  )
  use value <- result.try(case security {
    PlainText -> bit_array.base64_decode(value)
    Signed -> verify_signed_message(request, value)
  })
  bit_array.to_string(value)
}

pub fn sign_message(
  _request: Request,
  message: BitArray,
  algorithm: crypto.HashAlgorithm,
) -> String {
  crypto.sign_message(message, <<load_application_secret():utf8>>, algorithm)
}

/// Verify a signed message which was signed using the `sign_message` function.
///
/// Returns the content of the message if the signature is valid, otherwise
/// returns an error.
///
/// This function uses the secret key base from the request. If the secret
/// changes then the signature will no longer be verifiable.
///
pub fn verify_signed_message(
  _request: Request,
  message: String,
) -> Result(BitArray, Nil) {
  crypto.verify_signed_message(message, <<load_application_secret():utf8>>)
}
