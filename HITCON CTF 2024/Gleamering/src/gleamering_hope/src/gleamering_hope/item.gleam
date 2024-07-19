import gleam/bit_array
import gleam/bool
import gleam/dynamic
import gleam/int
import gleam/json
import gleam/result
import gleamering_hope.{stream_decrypt, stream_encrypt}
import gleamering_hope/error.{type AppError}
import gleamering_hope/user
import sqlight

pub type Item {
  Item(id: Int, encrypted: Bool, content: String)
}

pub type Category {
  All
  Plain
  Encrypted
}

pub fn to_json(item: Item) -> json.Json {
  let id = #("id", json.int(item.id))
  let encrypted = #("encrypted", json.bool(item.encrypted))
  let content = #("content", json.string(item.content))
  json.object([id, encrypted, content])
}

pub fn item_json_decoder() -> dynamic.Decoder(Item) {
  dynamic.decode3(
    Item,
    dynamic.field("id", of: dynamic.int),
    dynamic.field("encrypted", of: dynamic.bool),
    dynamic.field("content", of: dynamic.string),
  )
}

pub fn from_json(json: String) -> Result(Item, AppError) {
  json.decode(json, item_json_decoder())
  |> result.replace_error(error.BadRequest)
}

/// Decode an item from a database row.
///
pub fn item_row_decoder() -> dynamic.Decoder(Item) {
  dynamic.decode3(
    Item,
    dynamic.element(0, dynamic.int),
    dynamic.element(1, sqlight.decode_bool),
    dynamic.element(2, dynamic.string),
  )
}

pub fn item_id_row_decoder() -> dynamic.Decoder(Item) {
  dynamic.decode3(
    fn(item_id, encrypted, content) {
      let assert Ok(item_id) = int.base_parse(item_id, 16)
      Item(id: item_id, encrypted: encrypted, content: content)
    },
    dynamic.element(0, dynamic.string),
    dynamic.element(1, sqlight.decode_bool),
    dynamic.element(2, dynamic.string),
  )
}

pub fn insert_item(
  content: String,
  user_id: Int,
  db: sqlight.Connection,
) -> Result(Int, AppError) {
  let sql =
    "
insert into items
  (content, user_id, encrypted) 
values 
  (?1, ?2, ?3)
returning
  id
"
  use rows <- result.then(
    sqlight.query(
      sql,
      on: db,
      with: [sqlight.text(content), sqlight.int(user_id), sqlight.bool(False)],
      expecting: dynamic.element(0, dynamic.int),
    )
    |> result.map_error(fn(error) {
      case error.code, error.message {
        sqlight.ConstraintCheck, "CHECK constraint failed: empty_content" ->
          error.ContentRequired
        sqlight.Constraint, "FOREIGN KEY constraint failed" ->
          error.UserNotFound
        _, _ -> error.BadRequest
      }
    }),
  )

  let assert [id] = rows
  let assert Ok(item) = set_item_id(id, db)
  Ok(item.id)
}

pub fn set_item_id(
  item_id: Int,
  db: sqlight.Connection,
) -> Result(Item, AppError) {
  let sql =
    "
update
  items
set
  item_id = ?2
where
  id = ?1
returning
  id,
  encrypted,
  content
"
  let assert Ok(row) =
    sqlight.query(
      sql,
      on: db,
      with: [sqlight.int(item_id), sqlight.text(int.to_base16(item_id))],
      expecting: item_row_decoder(),
    )
    |> result.map_error(fn(error) {
      case error.code, error.message {
        sqlight.ConstraintForeignkey, _ -> error.UserNotFound
        _, _ -> error.BadRequest
      }
    })

  case row {
    [item] -> Ok(item)
    _ -> Error(error.NotFound)
  }
}

/// Get a specific item.
///
pub fn get_item(item_id: Int, db: sqlight.Connection) -> Result(Item, AppError) {
  let sql =
    "
select
  id,
  encrypted,
  content
from
  items
where
  item_id = ?1
"

  let assert Ok(rows) =
    sqlight.query(
      sql,
      on: db,
      with: [sqlight.text(int.to_base16(item_id))],
      expecting: item_row_decoder(),
    )

  case rows {
    [item] -> Ok(item)
    _ -> Error(error.NotFound)
  }
}

/// List all the items for a user that have a particular encrypt state.
///
pub fn filtered_items(
  user_id: Int,
  completed: Bool,
  db: sqlight.Connection,
) -> List(Item) {
  let sql =
    "
select
  id,
  encrypted,
  content
from
  items
where
  user_id = ?1
and
  encrypted = ?2
order by
  inserted_at asc
"

  let assert Ok(rows) =
    sqlight.query(
      sql,
      on: db,
      with: [sqlight.int(user_id), sqlight.bool(completed)],
      expecting: item_row_decoder(),
    )

  rows
}

/// List all the items for a user.
///
pub fn list_items(user_id: Int, db: sqlight.Connection) -> List(Item) {
  let sql =
    "
select
  id,
  encrypted,
  content
from
  items
where
  user_id = ?1
order by
  inserted_at asc
"

  let assert Ok(rows) =
    sqlight.query(
      sql,
      on: db,
      with: [sqlight.int(user_id)],
      expecting: item_row_decoder(),
    )

  rows
}

/// Delete a specific item belonging to a user.
///
pub fn delete_item(item_id: Int, user_id: Int, db: sqlight.Connection) -> Nil {
  let sql =
    "
delete from
  items
where
  id = ?1
and
  user_id = ?2
"
  let assert Ok(_) =
    sqlight.query(
      sql,
      on: db,
      with: [sqlight.text(int.to_base16(item_id)), sqlight.int(user_id)],
      expecting: Ok,
    )
  Nil
}

/// Toggle the encryption state for specific item belonging to a user.
///
pub fn encrypt_item(
  item_id: Int,
  user_id: Int,
  key: Int,
  db: sqlight.Connection,
) -> Result(Item, AppError) {
  let assert Ok(item) = get_item(item_id, db)
  let #(new_content, updated_item_id) = case item.encrypted {
    True -> {
      let assert Ok(content) = bit_array.base64_decode(item.content)
      let assert Ok(user_real_id) = user.get_user_id(db, user_id)
      let res = stream_decrypt(content, item.id, user_real_id, key)
      let assert Ok(new_content) = bit_array.to_string(res)
      #(new_content, item.id)
    }
    False -> {
      let assert Ok(user_real_id) = user.get_user_id(db, user_id)
      let new_content =
        stream_encrypt(
          bit_array.from_string(item.content),
          item.id,
          user_real_id,
          key,
        )
        |> bit_array.base64_encode(True)
      #(new_content, item.id + user_real_id + key)
    }
  }
  let sql =
    "
update
  items
set
  encrypted = not encrypted,
  item_id = ?3,
  content = ?4
where
  item_id = ?1
and
  user_id = ?2
"
  let assert Ok(_rows) =
    sqlight.query(
      sql,
      on: db,
      with: [
        sqlight.text(int.to_base16(item_id)),
        sqlight.int(user_id),
        sqlight.text(int.to_base16(updated_item_id)),
        sqlight.text(new_content),
      ],
      expecting: fn(_) { Ok(Nil) },
    )

  get_item(updated_item_id, db)
}

pub fn is_member(item: Item, category: Category) -> Bool {
  case category {
    All -> True
    Encrypted -> item.encrypted
    Plain -> bool.negate(item.encrypted)
  }
}
