#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_shorthash_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_shorthash_keygen),
    LS_FUNC(crypto_shorthash),
    LS_FUNC(crypto_shorthash_siphashx24),
    { NULL }
};

LS_PUBLIC
int luaopen_luasodium_crypto_shorthash_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_shorthash);
}



