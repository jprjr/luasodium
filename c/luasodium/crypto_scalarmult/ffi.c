#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

static const luasodium_function_t ls_crypto_scalarmult_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_scalarmult_base),
    LS_FUNC(crypto_scalarmult),
    { NULL }
};

int luaopen_luasodium_crypto_scalarmult_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,crypto_scalarmult_lua,crypto_scalarmult_lua_length - 1,"crypto_scalarmult.lua") ) {
        return lua_error(L);
    }
    luasodium_push_functions(L,ls_crypto_scalarmult_functions);
    luasodium_push_constants(L,ls_crypto_scalarmult_constants);

    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }
    return 1;
}

