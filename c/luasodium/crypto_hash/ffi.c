#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_hash_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(sodium_malloc),
    LS_FUNC(sodium_free),
    LS_FUNC(crypto_hash),
    LS_FUNC(crypto_hash_sha256),
    LS_FUNC(crypto_hash_sha256_init),
    LS_FUNC(crypto_hash_sha256_update),
    LS_FUNC(crypto_hash_sha256_final),
    LS_FUNC(crypto_hash_sha512),
    LS_FUNC(crypto_hash_sha512_init),
    LS_FUNC(crypto_hash_sha512_update),
    LS_FUNC(crypto_hash_sha512_final),
    LS_FUNC(crypto_hash_sha256_statebytes),
    LS_FUNC(crypto_hash_sha512_statebytes),
    { NULL }
};


LS_PUBLIC
int luaopen_luasodium_crypto_hash_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_hash);
}
