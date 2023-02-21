#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_generichash_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(malloc),
    LS_FUNC(free),
    LS_FUNC(crypto_generichash_keygen),
    LS_FUNC(crypto_generichash_statebytes),
    LS_FUNC(crypto_generichash),
    LS_FUNC(crypto_generichash_init),
    LS_FUNC(crypto_generichash_update),
    LS_FUNC(crypto_generichash_final),
    { NULL }
};

LS_PUBLIC
int luaopen_luasodium_crypto_generichash_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_generichash);
}


