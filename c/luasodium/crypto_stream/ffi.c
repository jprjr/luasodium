#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_stream_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_stream),
    LS_FUNC(crypto_stream_xor),
    LS_FUNC(crypto_stream_keygen),
    { NULL }
};

int luaopen_luasodium_crypto_stream_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_stream);
}
