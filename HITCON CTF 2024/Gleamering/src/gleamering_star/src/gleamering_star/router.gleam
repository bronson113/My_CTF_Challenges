import gleam/http
import gleam/json
import gleam/list
import gleam/result
import gleamering_hope/item.{type Category, Item}
import gleamering_star/encrypt_post.{load_authorization_key}
import gleamering_star/web.{type Context, Context}
import wisp.{type Request, type Response}

pub fn handle_request(req: Request, ctx: Context) -> Response {
  let req = wisp.method_override(req)
  use <- wisp.log_request(req)
  use <- wisp.rescue_crashes
  use req <- wisp.handle_head(req)

  case wisp.path_segments(req) {
    ["api", user_id, ..rest] -> {
      case web.parse_int(user_id) {
        Ok(user_id) -> {
          let ctx = Context(..ctx, user_id: user_id)
          case rest {
            ["all"] -> home(ctx, item.All)
            ["plain"] -> home(ctx, item.Plain)
            ["encrypted"] -> home(ctx, item.Encrypted)
            ["posts"] -> posts(req, ctx)
            ["posts", id] -> post_item(req, ctx, id)
            ["posts", id, "encrypt"] -> item_encrypt(ctx, id)
            _ -> wisp.not_found()
          }
        }
        _ -> wisp.bad_request()
      }
    }
    _ -> wisp.not_found()
  }
}

fn home(ctx: Context, category: Category) -> Response {
  let items = case category {
    item.All -> item.list_items(ctx.user_id, ctx.db)
    item.Plain -> item.filtered_items(ctx.user_id, False, ctx.db)
    item.Encrypted -> item.filtered_items(ctx.user_id, True, ctx.db)
  }
  items
  |> list.map(item.to_json)
  |> json.preprocessed_array()
  |> json.to_string_builder
  |> wisp.html_response(200)
}

fn posts(request: Request, ctx: Context) -> Response {
  case request.method {
    http.Post -> create_post(request, ctx)
    _ -> wisp.method_not_allowed([http.Post])
  }
}

fn create_post(request: Request, ctx: Context) -> Response {
  use params <- wisp.require_form(request)

  let result = {
    use content <- result.try(web.key_find(params.values, "content"))
    use id <- result.try(item.insert_item(content, ctx.user_id, ctx.db))
    Ok(Item(id: id, encrypted: False, content: content))
  }
  use item <- web.require_ok(result)
  item
  |> item.to_json
  |> json.to_string_builder
  |> wisp.json_response(200)
}

fn post_item(request: Request, ctx: Context, id: String) -> Response {
  case request.method {
    http.Get -> get_post(ctx, id)
    http.Delete -> delete_item(ctx, id)
    _ -> wisp.method_not_allowed([http.Get, http.Delete, http.Patch])
  }
}

fn get_post(ctx: Context, id: String) -> Response {
  let result = {
    use id <- result.try(web.parse_int(id))
    item.get_item(id, ctx.db)
  }
  use item <- web.require_ok(result)
  item
  |> item.to_json
  |> json.to_string_builder
  |> wisp.json_response(200)
}

fn delete_item(ctx: Context, id: String) -> Response {
  use id <- web.require_ok(web.parse_int(id))
  item.delete_item(id, ctx.user_id, ctx.db)

  [#("id", json.int(id))]
  |> json.object
  |> json.to_string_builder
  |> wisp.json_response(200)
}

fn item_encrypt(ctx: Context, id: String) -> Response {
  let result = {
    use id <- result.try(web.parse_int(id))
    item.encrypt_item(id, ctx.user_id, load_authorization_key(), ctx.db)
  }
  use item <- web.require_ok(result)

  item
  |> item.to_json
  |> json.to_string_builder
  |> wisp.json_response(200)
}
