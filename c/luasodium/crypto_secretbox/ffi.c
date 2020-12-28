#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

static const ffi_pointer_t ffi_pointers[] = {
    crypto_secretbox_easy,
    crypto_secretbox_open_easy,
    crypto_secretbox_detached,
    crypto_secretbox_open_detached,
    crypto_secretbox_keygen,
    NULL,
};

int
luaopen_luasodium_crypto_secretbox_ffi(lua_State *L) {
    unsigned int i = 0;
    if(luaL_loadbuffer(L,crypto_secretbox_lua,crypto_secretbox_lua_length - 1,"crypto_secretbox.lua")) {
        return lua_error(L);
    }

    i += luasodium_push_constants(L,luasodium_secretbox_constants);
    assert(i==3);
    i += luasodium_push_functions(L,ffi_pointers);
    assert(i==8);
    if(lua_pcall(L,i,1,0)) {
        return lua_error(L);
    }
    return 1;
}
