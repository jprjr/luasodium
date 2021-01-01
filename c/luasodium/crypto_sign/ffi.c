#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

static const luasodium_function_t ls_crypto_sign_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(malloc),
    LS_FUNC(free),
    LS_FUNC(crypto_sign_keypair),
    LS_FUNC(crypto_sign_seed_keypair),
    LS_FUNC(crypto_sign),
    LS_FUNC(crypto_sign_open),
    LS_FUNC(crypto_sign_detached),
    LS_FUNC(crypto_sign_verify_detached),
    LS_FUNC(crypto_sign_init),
    LS_FUNC(crypto_sign_update),
    LS_FUNC(crypto_sign_final_create),
    LS_FUNC(crypto_sign_final_verify),
    LS_FUNC(crypto_sign_ed25519_sk_to_seed),
    LS_FUNC(crypto_sign_ed25519_sk_to_pk),
    LS_FUNC(crypto_sign_statebytes),
    { NULL }
};

int luaopen_luasodium_crypto_sign_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,crypto_sign_lua,crypto_sign_lua_length - 1,"crypto_sign.lua") ) {
        return lua_error(L);
    }

    luasodium_push_functions(L,ls_crypto_sign_functions);
    luasodium_push_constants(L,ls_crypto_sign_constants);
    lua_pushinteger(L,crypto_sign_statebytes());
    lua_setfield(L,-2,"crypto_sign_STATEBYTES");

    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }
    return 1;
}

