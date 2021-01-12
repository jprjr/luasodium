#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_auth_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_auth),
    LS_FUNC(crypto_auth_verify),
    LS_FUNC(crypto_auth_keygen),
    LS_FUNC(crypto_auth_hmacsha256),
    LS_FUNC(crypto_auth_hmacsha256_verify),
    LS_FUNC(crypto_auth_hmacsha256_keygen),
    LS_FUNC(crypto_auth_hmacsha512256),
    LS_FUNC(crypto_auth_hmacsha512256_verify),
    LS_FUNC(crypto_auth_hmacsha512256_keygen),
    LS_FUNC(crypto_auth_hmacsha512),
    LS_FUNC(crypto_auth_hmacsha512_verify),
    LS_FUNC(crypto_auth_hmacsha512_keygen),
    { NULL }
};

LS_PUBLIC
int
luaopen_luasodium_crypto_auth_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_auth);
}
