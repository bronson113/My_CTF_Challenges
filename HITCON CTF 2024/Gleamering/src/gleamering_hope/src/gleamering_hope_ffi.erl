-module(gleamering_hope_ffi).
-export([stream_xor/3, stream_encrypt/4, stream_decrypt/4]).
-nifs([stream_xor/3]).
-on_load(init/0).

init() ->
    ok = erlang:load_nif(code:priv_dir(gleamering_hope) ++ "/gleamering_hope_ffi", 0).

-spec stream_xor(bitstring(), bitstring(), bitstring()) -> bitstring().
stream_xor(Msg, Key, Prefix) ->
    case {Msg, Key} of
        {<<Msg_firstbyte:8, Rest/binary>>, <<Key_firstbyte:8, Rest_key/binary>>} ->
            Firstbyte = erlang:'bxor'(Msg_firstbyte, Key_firstbyte),
            stream_xor(
                Rest,
                gleam@bit_array:append(Rest_key, <<Key_firstbyte:8>>),
                gleam@bit_array:append(Prefix, <<Firstbyte:8>>)
            );

        {_, _} ->
            Prefix
    end.
    
-spec stream_encrypt(bitstring(), integer(), integer(), integer()) -> bitstring().
stream_encrypt(Msg, Msg_id, User_id, Key) ->
    Usermult = 16#DEADBEEF,
    Msgmult = 16#CAFEBABE,
    User_key = ((User_id * Usermult) + (Msg_id * Msgmult)) + (Key * User_id),
    Key_string = gleam_crypto_ffi:hash(sha512, <<User_key:128>>),
    stream_xor(Msg, Key_string, <<>>).

-spec stream_decrypt(bitstring(), integer(), integer(), integer()) -> bitstring().
stream_decrypt(Msg, Msg_id, User_id, Key) ->
    Usermult = 16#DEADBEEF,
    Msgmult = 16#CAFEBABE,
    User_key = ((User_id * Usermult) + (Msg_id * Msgmult)) + (Key * User_id),
    Key_string = gleam_crypto_ffi:hash(sha512, <<User_key:128>>),
    stream_xor(Msg, Key_string, <<>>).

