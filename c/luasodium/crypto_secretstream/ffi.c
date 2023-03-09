#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_secretstream_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_keygen),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_init_push),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_push),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_init_pull),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_pull),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_rekey),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_statebytes),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_abytes),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_headerbytes),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_keybytes),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_messagebytes_max),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_tag_message),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_tag_push),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_tag_rekey),
    LS_FUNC(crypto_secretstream_xchacha20poly1305_tag_final),
    { NULL }
};

LS_PUBLIC
int luaopen_luasodium_crypto_secretstream_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_secretstream);
}

