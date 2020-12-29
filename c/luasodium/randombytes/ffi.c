#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

static const ffi_pointer_t ffi_pointers[] = {
    randombytes_random,
    randombytes_uniform,
    randombytes_buf,
    randombytes_seedbytes,
    randombytes_close,
    randombytes_stir,
    randombytes_buf_deterministic,
    NULL
};

int
luaopen_luasodium_randombytes_ffi(lua_State *L) {
    unsigned int i = 0;
    if(luaL_loadbuffer(L,randombytes_lua,randombytes_lua_length - 1,"randombytes.lua")) {
        return lua_error(L);
    }
    i += luasodium_push_init(L);
    i += luasodium_push_constants(L,luasodium_randombytes_constants);
    i += luasodium_push_functions(L,ffi_pointers);
    assert(i == 9);
    if(lua_pcall(L,i,1,0)) {
        return lua_error(L);
    }
    return 1;
}

