import gleam/dynamic
import gleam/fetch
import gleam/http
import gleam/http/request
import gleam/int
import gleam/javascript/promise.{type Promise}
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import gleamering_hope/error.{UnprocessableEntity}
import gleamering_hope/item.{type Category}
import gleamering_hope/user.{User, get_user, insert_user}
import gleamering_light/my_cookie.{Signed, set_cookie}
import gleamering_light/templates/home as home_template
import gleamering_light/templates/item as item_template
import gleamering_light/templates/item_changed as item_changed_template
import gleamering_light/templates/item_created as item_created_template
import gleamering_light/templates/login as login_template
import gleamering_light/web.{type Context, authenticate, not_found, uid_cookie}
import glen.{type Request, type Response}
import glen/status

pub fn handle_request(req: Request, ctx: Context) -> Promise(Response) {
  // Log all requests and responses
  use <- glen.log(req)
  // Handle potential crashes gracefully
  use <- glen.rescue_crashes

  use ctx, authed <- authenticate(req, ctx)
  // Serve static files from ./test/static on the path /static
  use <- glen.static(req, "static", ctx.static_path)

  case glen.path_segments(req), authed {
    [], _ -> login_home()
    ["home"], True -> get_items(ctx, item.All)
    ["login"], _ -> post_only(req, ctx, login)
    ["signup"], _ -> post_only(req, ctx, signup)
    ["logout"], True -> logout(req, ctx)
    ["plain"], True -> get_items(ctx, item.Plain)
    ["encrypted"], True -> encrypted(req, ctx)
    ["posts"], True -> posts(req, ctx)
    ["posts", id], True -> post_item(req, ctx, id)
    ["posts", id, "encrypt"], True -> encrypted_item(req, ctx, id)
    _, False ->
      glen.redirect("/", 301)
      |> promise.resolve()
    _, _ -> not_found() |> promise.resolve()
  }
}

fn login_home() -> Promise(Response) {
  login_template.render(err: "")
  |> glen.html(status.ok)
  |> promise.resolve
}

fn get_items(ctx: Context, category: Category) -> Promise(Response) {
  let endpoint = case category {
    item.All -> "all"
    item.Plain -> "plain"
    item.Encrypted -> "encrypted"
  }
  let res = {
    let path =
      "/api/"
      |> string.append(int.to_string(ctx.user_id))
      |> string.append("/")
      |> string.append(endpoint)
    let req =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(3000)
      |> request.set_scheme(http.Http)
      |> request.set_path(path)
      |> request.set_method(http.Get)

    use resp <- promise.try_await(fetch.send(req))
    use resp <- promise.try_await(fetch.read_text_body(resp))
    let items =
      json.decode(resp.body, dynamic.list(of: item.item_json_decoder()))
      |> result.replace_error(UnprocessableEntity)
    promise.resolve(Ok(items))
  }
  use status <- promise.await(res)
  use status <- web.require_ok(
    status |> result.replace_error(UnprocessableEntity),
  )
  use items <- web.require_ok(status)

  home_template.render(items, category)
  |> glen.html(status.ok)
  |> promise.resolve()
}

fn encrypted(request: Request, ctx: Context) -> Promise(Response) {
  use <- glen.require_method(request, http.Get)
  get_items(ctx, item.Encrypted)
}

fn posts(request: Request, ctx: Context) -> Promise(Response) {
  use <- glen.require_method(request, http.Post)
  create_post(request, ctx)
}

fn post_only(
  request: Request,
  ctx: Context,
  handler: fn(Request, Context) -> Promise(Response),
) -> Promise(Response) {
  use <- glen.require_method(request, http.Post)
  handler(request, ctx)
}

fn login(request: Request, ctx: Context) -> Promise(Response) {
  use params <- glen.require_form(request)

  let result = {
    use user_ <- result.try(web.key_find(params.values, "user"))
    use pass <- result.try(web.key_find(params.values, "pass"))
    get_user(ctx.db, user_, pass)
  }
  case result {
    Error(_) ->
      login_template.render(err: "<p>Invalid Login</p>")
      |> glen.html(status.ok)
    Ok(id) -> {
      let id_str = int.to_base16(id)
      let year = 60 * 60 * 24 * 365

      let resp = glen.redirect("/home", 301)
      set_cookie(resp, request, uid_cookie, id_str, Signed, year)
    }
  }
  |> promise.resolve
}

fn signup(request: Request, ctx: Context) -> Promise(Response) {
  use params <- glen.require_form(request)

  let assert Ok(user_) = {
    use user_ <- result.try(web.key_find(params.values, "user"))
    use pass <- result.try(web.key_find(params.values, "pass"))
    use id <- result.try(web.key_find(params.values, "id"))
    use id_int <- result.try(web.parse_int(id))
    Ok(User(id: id_int, name: user_, password: pass))
  }
  //  use user_ <- web.require_ok(result)
  let id = insert_user(ctx.db, user_)
  let id_str = int.to_base16(id)
  let year = 60 * 60 * 24 * 365

  let resp = glen.redirect("/home", 301)
  let ret = set_cookie(resp, request, uid_cookie, id_str, Signed, year)
  promise.resolve(ret)
}

fn logout(request: Request, _ctx: Context) -> Promise(Response) {
  let resp = glen.redirect("/", 301)
  set_cookie(resp, request, uid_cookie, "", Signed, 0)
  |> promise.resolve()
}

fn create_post(request: Request, ctx: Context) -> Promise(Response) {
  use params <- glen.require_form(request)

  let content = {
    use content <- result.try(web.key_find(params.values, "content"))
    Ok(string.append("content=", content))
  }
  use content <- web.require_ok(content)
  let result = {
    let path =
      "/api/"
      |> string.append(int.to_string(ctx.user_id))
      |> string.append("/posts")
    let req =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(3000)
      |> request.set_scheme(http.Http)
      |> request.set_path(path)
      |> request.set_method(http.Post)
      |> request.set_body(content)
      |> request.set_header("content-type", "application/x-www-form-urlencoded")

    use resp <- promise.try_await(fetch.send(req))
    use resp <- promise.try_await(fetch.read_text_body(resp))
    let item = item.from_json(resp.body)
    promise.resolve(Ok(item))
  }

  use status <- promise.await(result)
  use status <- web.require_ok(
    status |> result.replace_error(UnprocessableEntity),
  )
  use item <- web.require_ok(status)

  let display = item.is_member(item, current_category(request))

  item_created_template.render(item, display)
  |> glen.html(status.ok)
  |> promise.resolve
}

fn post_item(request: Request, ctx: Context, id: String) -> Promise(Response) {
  case request.method {
    http.Get -> get_post(ctx, id, False)
    http.Delete -> delete_item(ctx, id)
    http.Patch -> item_encrypt(request, ctx, id, False)
    _ ->
      glen.method_not_allowed([http.Get, http.Delete, http.Patch])
      |> promise.resolve()
  }
}

fn encrypted_item(
  request: Request,
  ctx: Context,
  id: String,
) -> Promise(Response) {
  case request.method {
    http.Get -> get_post(ctx, id, True)
    http.Patch -> item_encrypt(request, ctx, id, True)
    _ ->
      glen.method_not_allowed([http.Get, http.Delete, http.Patch])
      |> promise.resolve()
  }
}

fn get_post(ctx: Context, id: String, encrypted: Bool) -> Promise(Response) {
  let assert Ok(id) = web.parse_int(id)
  let result = {
    let assert Ok(user_real_id) = user.get_user_id(ctx.db, ctx.user_id)
    let real_id = case encrypted {
      True -> id + user_real_id + my_cookie.load_authorization_key()
      False -> id
    }
    let path =
      "/api/"
      |> string.append(int.to_string(ctx.user_id))
      |> string.append("/posts/")
      |> string.append(int.to_string(real_id))
    let req =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(3000)
      |> request.set_scheme(http.Http)
      |> request.set_path(path)
      |> request.set_method(http.Get)

    use resp <- promise.try_await(fetch.send(req))
    use resp <- promise.try_await(fetch.read_text_body(resp))
    let item = item.from_json(resp.body)
    promise.resolve(Ok(item))
  }
  use status <- promise.await(result)
  use status <- web.require_ok(
    status |> result.replace_error(UnprocessableEntity),
  )
  use item <- web.require_ok(status)

  item_template.render(item, True)
  |> glen.html(status.ok)
  |> promise.resolve
}

fn delete_item(ctx: Context, id: String) -> Promise(Response) {
  let assert Ok(_id) = web.parse_int(id)
  let res = {
    let path =
      "/api/"
      |> string.append(int.to_string(ctx.user_id))
      |> string.append("/posts/")
      |> string.append(id)
    let req =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(3000)
      |> request.set_scheme(http.Http)
      |> request.set_path(path)
      |> request.set_method(http.Delete)

    use resp <- promise.try_await(fetch.send(req))
    use resp <- promise.try_await(fetch.read_text_body(resp))
    promise.resolve(Ok(resp.status))
  }

  use status <- promise.await(res)
  //  let items = item_deleted_template.render()
  case status {
    Ok(status_code) -> {
      glen.html("", status_code)
    }
    _ -> {
      glen.html("", status.internal_server_error)
    }
  }
  |> promise.resolve
}

fn item_encrypt(
  request: Request,
  ctx: Context,
  id: String,
  encrypted: Bool,
) -> Promise(Response) {
  let assert Ok(id) = web.parse_int(id)
  let res = {
    let assert Ok(user_real_id) = user.get_user_id(ctx.db, ctx.user_id)
    let real_id = case encrypted {
      True -> id + user_real_id + my_cookie.load_authorization_key()
      False -> id
    }
    let path =
      "/api/"
      |> string.append(int.to_string(ctx.user_id))
      |> string.append("/posts/")
      |> string.append(int.to_string(real_id))
      |> string.append("/encrypt")
    let req =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(3000)
      |> request.set_scheme(http.Http)
      |> request.set_path(path)
      |> request.set_method(http.Patch)

    use resp <- promise.try_await(fetch.send(req))
    use resp <- promise.try_await(fetch.read_text_body(resp))
    let item = item.from_json(resp.body)
    promise.resolve(Ok(item))
  }

  use status <- promise.await(res)
  use status <- web.require_ok(
    status |> result.replace_error(UnprocessableEntity),
  )
  use item <- web.require_ok(status)

  let display = item.is_member(item, current_category(request))

  item_changed_template.render(item, display)
  |> glen.html(status.ok)
  |> promise.resolve
}

fn current_category(request: Request) -> Category {
  let current_url =
    request.headers
    |> list.key_find("hx-current-url")
    |> result.unwrap("")
  case string.contains(current_url, "/encrypted") {
    True -> item.Encrypted
    False ->
      case string.contains(current_url, "/plain") {
        True -> item.Plain
        False -> item.All
      }
  }
}
