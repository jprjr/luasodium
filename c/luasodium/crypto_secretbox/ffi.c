#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

static const luasodium_function_t ls_crypto_secretbox_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_secretbox_keygen),
    LS_FUNC(crypto_secretbox),
    LS_FUNC(crypto_secretbox_open),
    LS_FUNC(crypto_secretbox_easy),
    LS_FUNC(crypto_secretbox_open_easy),
    LS_FUNC(crypto_secretbox_detached),
    LS_FUNC(crypto_secretbox_open_detached),
    LS_FUNC(crypto_secretbox_xsalsa20poly1305_keygen),
    LS_FUNC(crypto_secretbox_xsalsa20poly1305),
    LS_FUNC(crypto_secretbox_xsalsa20poly1305_open),
    LS_FUNC(crypto_secretbox_xchacha20poly1305_easy),
    LS_FUNC(crypto_secretbox_xchacha20poly1305_open_easy),
    LS_FUNC(crypto_secretbox_xchacha20poly1305_detached),
    LS_FUNC(crypto_secretbox_xchacha20poly1305_open_detached),
    { NULL, NULL },
};



int
luaopen_luasodium_crypto_secretbox_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,crypto_secretbox_lua,crypto_secretbox_lua_length - 1,"crypto_secretbox.lua")) {
        return lua_error(L);
    }

    luasodium_push_functions(L,ls_crypto_secretbox_functions);
    luasodium_push_constants(L,ls_crypto_secretbox_constants);

    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }
    return 1;
}
