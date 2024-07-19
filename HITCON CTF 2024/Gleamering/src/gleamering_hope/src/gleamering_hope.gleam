import gleam/bit_array.{append}
import gleam/crypto.{Sha512, hash}
import gleam/int.{bitwise_exclusive_or}

@external(erlang, "gleamering_hope_ffi", "stream_xor")
pub fn stream_xor(msg: BitArray, key: BitArray, prefix: BitArray) -> BitArray {
  case msg, key {
    <<msg_firstbyte:size(8), rest:bytes>>,
      <<key_firstbyte:size(8), rest_key:bytes>>
    -> {
      let firstbyte = bitwise_exclusive_or(msg_firstbyte, key_firstbyte)
      stream_xor(
        rest,
        append(rest_key, <<key_firstbyte:size(8)>>),
        append(prefix, <<firstbyte:size(8)>>),
      )
    }
    _, _ -> {
      prefix
    }
  }
}

fn calc_key_value(msg_id: Int, user_id: Int, key: Int) {
  let usermult = 0xDEADBEEF
  let msgmult = 0xCAFEBABE
  user_id * usermult + msg_id * msgmult + key * user_id
}

@external(erlang, "gleamering_hope_ffi", "stream_encrypt")
pub fn stream_encrypt(
  msg: BitArray,
  msg_id: Int,
  user_id: Int,
  key: Int,
) -> BitArray {
  let user_key = calc_key_value(msg_id, user_id, key)
  let key_string = hash(Sha512, <<user_key:128>>)
  stream_xor(msg, key_string, <<>>)
}

@external(erlang, "gleamering_hope_ffi", "stream_decrypt")
pub fn stream_decrypt(
  msg: BitArray,
  msg_id: Int,
  user_id: Int,
  key: Int,
) -> BitArray {
  let user_key = calc_key_value(msg_id, user_id, key)
  let key_string = hash(Sha512, <<user_key:128>>)
  stream_xor(msg, key_string, <<>>)
}
