#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_kx_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_kx_keypair),
    LS_FUNC(crypto_kx_seed_keypair),
    LS_FUNC(crypto_kx_client_session_keys),
    LS_FUNC(crypto_kx_server_session_keys),
    { NULL, NULL },
};

LS_PUBLIC
int luaopen_luasodium_crypto_kx_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_kx);
}

