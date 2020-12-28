#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

static const ffi_pointer_t ffi_pointers[] = {
    crypto_scalarmult_base,
    crypto_scalarmult,
    NULL,
};

int luaopen_luasodium_crypto_scalarmult_ffi(lua_State *L) {
    unsigned int i = 0;
    if(luaL_loadbuffer(L,crypto_scalarmult_lua,crypto_scalarmult_lua_length - 1,"crypto_scalarmult.lua") ) {
        return lua_error(L);
    }
    i += luasodium_push_constants(L,luasodium_crypto_scalarmult_constants);
    i += luasodium_push_functions(L,ffi_pointers);
    assert(i == 4);
    if(lua_pcall(L,i,1,0)) {
        return lua_error(L);
    }
    return 1;
}
