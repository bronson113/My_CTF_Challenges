import gleam/result
import gleamering_hope/error.{type AppError}
import sqlight

pub type Connection =
  sqlight.Connection

pub fn with_connection(name: String, f: fn(sqlight.Connection) -> a) -> a {
  use db <- sqlight.with_connection(name)
  let assert Ok(_) = sqlight.exec("pragma foreign_keys = on;", db)
  f(db)
}

/// Run some idempotent DDL to ensure we have the PostgreSQL database schema
/// that we want. This should be run when the application starts.
pub fn migrate_schema(db: sqlight.Connection) -> Result(Nil, AppError) {
  let sql =
    "
    create table if not exists users (
      id integer primary key autoincrement not null,
      user_id text not null,
      user_name text not null,
      user_password text not null
    );

    create table if not exists items (
     id integer primary key autoincrement not null,

     item_id text
       not null
       default 0,

     inserted_at text not null
       default current_timestamp,

     encrypted integer 
       not null
       default 0,

     content text
       not null,

     user_id integer not null,
     foreign key (user_id)
       references users (id)
    );

    create index if not exists items_user_id_encrytped 
    on items (
      user_id, 
      encrypted
    );
    "

  sqlight.exec(sql, db)
  |> result.map_error(error.SqlightError)
}
