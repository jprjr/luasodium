#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"


static const ffi_pointer_t ffi_pointers[] = {
    crypto_box_keypair,
    crypto_box_seed_keypair,
    crypto_box_easy,
    crypto_box_open_easy,
    crypto_box_detached,
    crypto_box_open_detached,
    crypto_box_beforenm,
    crypto_box_easy_afternm,
    crypto_box_open_easy_afternm,
    crypto_box_detached_afternm,
    crypto_box_open_detached_afternm,
    NULL,
};

int luaopen_luasodium_crypto_box_ffi(lua_State *L) {
    unsigned int i = 0;
    if(luaL_loadbuffer(L,crypto_box_lua,crypto_box_lua_length - 1,"crypto_box.lua") ) {
        return lua_error(L);
    }
    i += luasodium_push_init(L);
    i += luasodium_push_constants(L,luasodium_box_constants);
    i += luasodium_push_functions(L,ffi_pointers);
    assert(i == 18);
    if(lua_pcall(L,i,1,0)) {
        return lua_error(L);
    }
    return 1;
}
