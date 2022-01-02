#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_onetimeauth_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(sodium_malloc),
    LS_FUNC(sodium_free),
    LS_FUNC(crypto_onetimeauth),
    LS_FUNC(crypto_onetimeauth_verify),
    LS_FUNC(crypto_onetimeauth_keygen),
    LS_FUNC(crypto_onetimeauth_init),
    LS_FUNC(crypto_onetimeauth_update),
    LS_FUNC(crypto_onetimeauth_final),
    LS_FUNC(crypto_onetimeauth_statebytes),
    LS_FUNC(crypto_onetimeauth_poly1305),
    LS_FUNC(crypto_onetimeauth_poly1305_verify),
    LS_FUNC(crypto_onetimeauth_poly1305_keygen),
    LS_FUNC(crypto_onetimeauth_poly1305_init),
    LS_FUNC(crypto_onetimeauth_poly1305_update),
    LS_FUNC(crypto_onetimeauth_poly1305_final),
    LS_FUNC(crypto_onetimeauth_poly1305_statebytes),
    { NULL }
};

LS_PUBLIC
int luaopen_luasodium_crypto_onetimeauth_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_onetimeauth);
}
