import dot_env as dot
import dot_env/env
import gleam/erlang/process
import gleam/int
import gleam/result
import gleamering_hope/database
import gleamering_hope/item
import gleamering_hope/user.{User}
import gleamering_star/router
import gleamering_star/web.{Context}
import mist
import wisp

pub fn main() {
  dot.new()
  |> dot.set_path("./.env")
  |> dot.set_debug(False)
  |> dot.load

  wisp.configure_logger()

  let port = load_port()
  let secret_key_base = load_application_secret()

  let db_name = env.get_or("APPLICATION_DB", "gleamering.sqlite3")

  let assert Ok(_) = database.with_connection(db_name, database.migrate_schema)
  database.with_connection(db_name, fn(db) {
    case user.get_user(db, "admin", env.get_or("ADMIN_PASSWORD", "DEADBEEF")) {
      Ok(1) -> 1
      _ ->
        user.insert_user(
          db,
          User(
            id: 1,
            name: "admin",
            password: env.get_or("ADMIN_PASSWORD", "DEADBEEF"),
          ),
        )
    }
  })
  let _ =
    database.with_connection(db_name, fn(db) {
      case item.list_items(1, db) {
        [] -> {
          item.insert_item(env.get_or("FLAG", "hitcon{temp}"), 1, db)
          |> result.then(item.encrypt_item(_, 1, load_authorization_key(), db))
          |> result.replace(Nil)
        }
        _ -> {
          Ok(Nil)
        }
      }
    })

  let handle_request = fn(req) {
    use db <- database.with_connection(db_name)
    let ctx = Context(user_id: 0, db: db)
    router.handle_request(req, ctx)
  }

  let assert Ok(_) =
    wisp.mist_handler(handle_request, secret_key_base)
    |> mist.new
    |> mist.port(port)
    |> mist.start_http

  process.sleep_forever()
}

fn load_application_secret() -> String {
  env.get_or("APPLICATION_SECRET", "27434b28994f498182d459335258fb6e")
}

fn load_authorization_key() -> Int {
  env.get_or("AUTHORIZATION_KEY", "100000009")
  |> int.parse
  |> result.unwrap(100_000_009)
}

fn load_port() -> Int {
  env.get_or("PORT", "3000")
  |> int.parse
  |> result.unwrap(3000)
}
