#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

static const luasodium_function_t ls_crypto_auth_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_auth),
    LS_FUNC(crypto_auth_verify),
    LS_FUNC(crypto_auth_keygen),
    { NULL }
};

int luaopen_luasodium_crypto_auth_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,crypto_auth_lua,crypto_auth_lua_length - 1,"crypto_auth.lua") ) {
        return lua_error(L);
    }

    luasodium_push_functions(L,ls_crypto_auth_functions);

    luasodium_push_constants(L,ls_crypto_auth_constants);
    /* there's no STATEBYTES constants, we'll add one */
    lua_pushinteger(L,crypto_sign_statebytes());
    lua_setfield(L,-2,"crypto_sign_STATEBYTES");

    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }
    return 1;
}
