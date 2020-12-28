#include "luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

static const ffi_pointer_t ffi_pointers[] = {
    sodium_init,
    sodium_memcmp,
    sodium_bin2hex,
    sodium_hex2bin,
    sodium_bin2base64,
    sodium_base642bin,
    sodium_increment,
    sodium_add,
    sodium_sub,
    sodium_compare,
    sodium_is_zero,
    sodium_pad,
    sodium_unpad,
    sodium_base64_encoded_len,
    NULL
};

int
luaopen_luasodium_ffi(lua_State *L) {
    unsigned int i = 0;
    if(luaL_loadbuffer(L,luasodium_lua,luasodium_lua_length - 1,"luasodium.lua")) {
        return lua_error(L);
    }
    i = luasodium_push_functions(L,ffi_pointers);
    assert(i == 14);
    i += luasodium_push_constants(L,luasodium_constants);
    assert(i == 18);
    if(lua_pcall(L,i,1,0)) {
        return lua_error(L);
    }
    return 1;
}

