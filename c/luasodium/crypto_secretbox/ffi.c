#include "../luasodium-ffi.h"
#include "constants.h"
#include "functions.h"
#include "core.luah"

static const luasodium_function_t * const ls_crypto_secretbox_functions[] = {
    (const luasodium_function_t *)&ls_crypto_secretbox_keygen_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_open_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_easy_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_open_easy_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_detached_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_open_detached_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_xsalsa20poly1305_keygen_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_xsalsa20poly1305_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_xsalsa20poly1305_open_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_xchacha20poly1305_easy_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_xchacha20poly1305_open_easy_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_xchacha20poly1305_detached_func,
    (const luasodium_function_t *)&ls_crypto_secretbox_xchacha20poly1305_open_detached_func,
    NULL
};



int
luaopen_luasodium_crypto_secretbox_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,crypto_secretbox_lua,crypto_secretbox_lua_length - 1,"crypto_secretbox.lua")) {
        return lua_error(L);
    }

    luasodium_push_inittable(L);
    luasodium_push_constants(L,ls_crypto_secretbox_constants);
    luasodium_push_functions(L,ls_crypto_secretbox_functions);

    if(lua_pcall(L,3,1,0)) {
        return lua_error(L);
    }
    return 1;
}
