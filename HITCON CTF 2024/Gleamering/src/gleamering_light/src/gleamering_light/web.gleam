//// Various helper functions for use in the web interface of the application.
////

import gleam/http.{Http}
import gleam/http/cookie
import gleam/http/response
import gleam/int
import gleam/javascript/promise.{type Promise}
import gleam/list
import gleam/option
import gleam/result
import gleamering_hope/database
import gleamering_hope/error.{type AppError}
import gleamering_light/my_cookie.{Signed, get_cookie}
import glen.{type Request, type Response}
import glen/status

pub type Context {
  Context(db: database.Connection, user_id: Int, static_path: String)
}

pub const uid_cookie = "uid"

/// Load the user from the `uid` cookie if set, otherwise create a new user row
/// and assign that in the response cookies.
///
/// The `uid` cookie is signed to prevent tampering.
///
pub fn authenticate(
  req: Request,
  ctx: Context,
  next: fn(Context, Bool) -> Promise(Response),
) -> Promise(Response) {
  let id =
    get_cookie(req, uid_cookie, Signed)
    |> result.try(int.base_parse(_, 16))
    |> option.from_result

  let #(id, authed) = case id {
    option.None -> {
      #(0, False)
    }
    option.Some(id) -> #(id, True)
  }
  let context = Context(..ctx, user_id: id)
  let resp = next(context, authed)
  resp
}

pub type AppResult =
  Result(Response, AppError)

/// Return an appropriate HTTP response for a given error.
///
pub fn error_to_response(error: AppError) -> Promise(Response) {
  case error {
    error.UserNotFound -> user_not_found()
    error.NotFound -> not_found()
    error.MethodNotAllowed -> glen.method_not_allowed([])
    error.BadRequest -> bad_request()
    error.UnprocessableEntity | error.ContentRequired -> unprocessible_entry()
    error.SqlightError(_) -> internal_server_error()
  }
  |> promise.resolve()
}

pub fn user_not_found() -> Response {
  let attributes =
    cookie.Attributes(..cookie.defaults(Http), max_age: option.Some(0))
  not_found()
  |> response.set_cookie("uid", "", attributes)
}

pub fn key_find(list: List(#(k, v)), key: k) -> Result(v, AppError) {
  list
  |> list.key_find(key)
  |> result.replace_error(error.UnprocessableEntity)
}

pub fn parse_int(string: String) -> Result(Int, AppError) {
  string
  |> int.parse
  |> result.replace_error(error.BadRequest)
}

pub fn require_ok(
  t: Result(t, AppError),
  next: fn(t) -> Promise(Response),
) -> Promise(Response) {
  case t {
    Ok(t) -> next(t)
    Error(error) -> error_to_response(error)
  }
}

pub fn not_found() -> Response {
  "<h1>Oops, are you lost?</h1>
  <p>This page doesn't exist.</p>"
  |> glen.html(status.not_found)
}

pub fn bad_request() -> Response {
  "<h1>Oops, something went wrong</h1>
  <p>This request is malformed</p>"
  |> glen.html(status.bad_request)
}

pub fn unprocessible_entry() -> Response {
  "<h1>Oops, something went wrong</h1>
  <p>Some bad request is send</p>"
  |> glen.html(status.unprocessable_entity)
}

pub fn internal_server_error() -> Response {
  "<h1>Oops, something went wrong</h1>
  <p>Something went wrong</p>"
  |> glen.html(status.internal_server_error)
}
