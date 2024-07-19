import dot_env as dot
import dot_env/env
import gleam/javascript/promise
import gleamering_hope/database
import gleamering_light/router
import gleamering_light/web.{Context}
import glen
import sqlight

pub fn main() {
  dot.new()
  |> dot.set_path("./.env")
  |> dot.set_debug(False)
  |> dot.load

  let db_name = env.get_or("APPLICATION_DB", "gleamering.sqlite3")

  let assert Ok(_) = database.with_connection(db_name, database.migrate_schema)
  let handle_request = fn(req) {
    let assert Ok(db) = sqlight.open(db_name)
    let assert Ok(_) = sqlight.exec("pragma foreign_keys = on;", db)
    let ctx =
      Context(
        user_id: 0,
        db: db,
        static_path: env.get_or("STATIC_PATH", "/var/www/static"),
      )
    use result <- promise.await(router.handle_request(req, ctx))
    let _ = sqlight.close(db)
    result |> promise.resolve()
  }
  glen.serve(8000, handle_request)
}
