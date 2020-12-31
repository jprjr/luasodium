#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

static const luasodium_function_t ls_randombytes_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(randombytes_random),
    LS_FUNC(randombytes_uniform),
    LS_FUNC(randombytes_buf),
    LS_FUNC(randombytes_buf_deterministic),
    LS_FUNC(randombytes_close),
    LS_FUNC(randombytes_stir),
    { NULL, NULL },
};

int
luaopen_luasodium_randombytes_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,randombytes_lua,randombytes_lua_length - 1,"randombytes.lua")) {
        return lua_error(L);
    }

    luasodium_push_functions(L,ls_randombytes_functions);
    luasodium_push_constants(L,ls_randombytes_constants);

    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }
    return 1;
}

