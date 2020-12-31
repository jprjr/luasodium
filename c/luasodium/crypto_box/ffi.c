#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

static const luasodium_function_t ls_crypto_box_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_box_keypair),
    LS_FUNC(crypto_box_seed_keypair),
    LS_FUNC(crypto_box),
    LS_FUNC(crypto_box_open),
    LS_FUNC(crypto_box_easy),
    LS_FUNC(crypto_box_open_easy),
    LS_FUNC(crypto_box_detached),
    LS_FUNC(crypto_box_open_detached),
    LS_FUNC(crypto_box_beforenm),
    LS_FUNC(crypto_box_easy_afternm),
    LS_FUNC(crypto_box_open_easy_afternm),
    LS_FUNC(crypto_box_detached_afternm),
    LS_FUNC(crypto_box_open_detached_afternm),
    { NULL }
};

int luaopen_luasodium_crypto_box_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,crypto_box_lua,crypto_box_lua_length - 1,"crypto_box.lua") ) {
        return lua_error(L);
    }

    luasodium_push_functions(L,ls_crypto_box_functions);
    luasodium_push_constants(L,ls_crypto_box_constants);

    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }
    return 1;
}
