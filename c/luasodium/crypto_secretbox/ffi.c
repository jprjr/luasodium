#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_secretbox_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_secretbox_keygen),
    LS_FUNC(crypto_secretbox),
    LS_FUNC(crypto_secretbox_open),
    LS_FUNC(crypto_secretbox_easy),
    LS_FUNC(crypto_secretbox_open_easy),
    LS_FUNC(crypto_secretbox_detached),
    LS_FUNC(crypto_secretbox_open_detached),
    LS_FUNC(crypto_secretbox_xsalsa20poly1305_keygen),
    LS_FUNC(crypto_secretbox_xsalsa20poly1305),
    LS_FUNC(crypto_secretbox_xsalsa20poly1305_open),
    LS_FUNC(crypto_secretbox_xchacha20poly1305_easy),
    LS_FUNC(crypto_secretbox_xchacha20poly1305_open_easy),
    LS_FUNC(crypto_secretbox_xchacha20poly1305_detached),
    LS_FUNC(crypto_secretbox_xchacha20poly1305_open_detached),
    { NULL, NULL },
};

LS_PUBLIC
int luaopen_luasodium_crypto_secretbox_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_secretbox);
}
