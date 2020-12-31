#include "../luasodium-ffi.h"
#include "constants.h"
#include "functions.h"
#include "core.luah"

static const luasodium_function_t * const ls_randombytes_functions[] = {
    (const luasodium_function_t *)&ls_randombytes_random_func,
    (const luasodium_function_t *)&ls_randombytes_uniform_func,
    (const luasodium_function_t *)&ls_randombytes_buf_func,
    (const luasodium_function_t *)&ls_randombytes_buf_deterministic_func,
    (const luasodium_function_t *)&ls_randombytes_close_func,
    (const luasodium_function_t *)&ls_randombytes_stir_func,
    NULL
};

int
luaopen_luasodium_randombytes_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,randombytes_lua,randombytes_lua_length - 1,"randombytes.lua")) {
        return lua_error(L);
    }

    luasodium_push_inittable(L);
    luasodium_push_constants(L,ls_randombytes_constants);
    luasodium_push_functions(L,ls_randombytes_functions);

    if(lua_pcall(L,3,1,0)) {
        return lua_error(L);
    }
    return 1;
}

