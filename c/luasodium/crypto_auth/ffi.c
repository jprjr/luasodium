#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_auth_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_auth),
    LS_FUNC(crypto_auth_verify),
    LS_FUNC(crypto_auth_keygen),
    { NULL }
};

LS_PUBLIC
int
luaopen_luasodium_crypto_auth_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_auth);
}
