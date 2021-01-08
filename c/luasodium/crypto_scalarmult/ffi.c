#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_scalarmult_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_scalarmult_base),
    LS_FUNC(crypto_scalarmult),
    { NULL, NULL },
};

LS_PUBLIC
int luaopen_luasodium_crypto_scalarmult_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_scalarmult);
}

