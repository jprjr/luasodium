#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_verify_functions[] = {
    LS_FUNC(crypto_verify_16),
    LS_FUNC(crypto_verify_32),
    { NULL }
};

LS_PUBLIC
int luaopen_luasodium_crypto_verify_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_verify);
}
