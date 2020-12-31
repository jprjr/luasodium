#include "../luasodium-ffi.h"
#include "constants.h"
#include "functions.h"
#include "core.luah"

static const luasodium_function_t * const ls_crypto_scalarmult_functions[] = {
    (const luasodium_function_t *)&ls_crypto_scalarmult_base_func,
    (const luasodium_function_t *)&ls_crypto_scalarmult_func,
    NULL
};

int luaopen_luasodium_crypto_scalarmult_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,crypto_scalarmult_lua,crypto_scalarmult_lua_length - 1,"crypto_scalarmult.lua") ) {
        return lua_error(L);
    }
    luasodium_push_inittable(L);
    luasodium_push_constants(L,ls_crypto_scalarmult_constants);
    luasodium_push_functions(L,ls_crypto_scalarmult_functions);

    if(lua_pcall(L,3,1,0)) {
        return lua_error(L);
    }
    return 1;
}

