import gleam/dynamic
import gleam/int
import gleam/result
import gleamering_hope/error.{type AppError}
import sqlight

pub type User {
  User(id: Int, name: String, password: String)
}

/// Insert a new user, returning their id.
///
pub fn insert_user(db: sqlight.Connection, user: User) -> Int {
  let sql =
    "
insert into users
  (user_id, user_name, user_password) 
values 
  (?1, ?2, ?3)
returning
  id
"
  let serialized_id = int.to_base16(user.id)
  let assert Ok([id]) =
    sqlight.query(
      sql,
      on: db,
      with: [
        sqlight.text(serialized_id),
        sqlight.text(user.name),
        sqlight.text(user.password),
      ],
      expecting: dynamic.element(0, dynamic.int),
    )
  id
}

pub fn get_user_id(db: sqlight.Connection, id: Int) -> Result(Int, AppError) {
  let sql =
    "
select
  user_id
from
  users
where
  id = ?1
"

  let assert Ok(result) =
    sqlight.query(
      sql,
      on: db,
      with: [sqlight.int(id)],
      expecting: dynamic.element(0, dynamic.string),
    )

  case result {
    [id] | [id, ..] -> {
      id
      |> int.base_parse(16)
      |> result.replace_error(error.UnprocessableEntity)
    }
    _ -> Error(error.NotFound)
  }
}

pub fn get_user(
  db: sqlight.Connection,
  name: String,
  pass: String,
) -> Result(Int, AppError) {
  let sql =
    "
select
  id
from
  users
where
  user_name = ?1
and
  user_password = ?2
"

  let assert Ok(result) =
    sqlight.query(
      sql,
      on: db,
      with: [sqlight.text(name), sqlight.text(pass)],
      expecting: dynamic.element(0, dynamic.int),
    )

  case result {
    [id] -> Ok(id)
    [id, ..] -> Ok(id)
    _ -> Error(error.NotFound)
  }
}
