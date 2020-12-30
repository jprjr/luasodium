#include "../luasodium-ffi.h"
#include "constants.h"
#include "functions.h"

#include "core.luah"

static const luasodium_function_t * const ls_crypto_box_functions[] = {
    (const luasodium_function_t *)&ls_crypto_box_keypair_func,
    (const luasodium_function_t *)&ls_crypto_box_seed_keypair_func,
    (const luasodium_function_t *)&ls_crypto_box_func,
    (const luasodium_function_t *)&ls_crypto_box_open_func,
    (const luasodium_function_t *)&ls_crypto_box_easy_func,
    (const luasodium_function_t *)&ls_crypto_box_open_easy_func,
    (const luasodium_function_t *)&ls_crypto_box_detached_func,
    (const luasodium_function_t *)&ls_crypto_box_open_detached_func,
    (const luasodium_function_t *)&ls_crypto_box_beforenm_func,
    (const luasodium_function_t *)&ls_crypto_box_easy_afternm_func,
    (const luasodium_function_t *)&ls_crypto_box_open_easy_afternm_func,
    (const luasodium_function_t *)&ls_crypto_box_detached_afternm_func,
    (const luasodium_function_t *)&ls_crypto_box_open_detached_afternm_func,
    NULL
};

int luaopen_luasodium_crypto_box_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,crypto_box_lua,crypto_box_lua_length - 1,"crypto_box.lua") ) {
        return lua_error(L);
    }

    luasodium_push_inittable(L);
    luasodium_push_constants(L,ls_crypto_box_constants);
    luasodium_push_functions(L,ls_crypto_box_functions);

    if(lua_pcall(L,3,1,0)) {
        return lua_error(L);
    }
    return 1;
}
