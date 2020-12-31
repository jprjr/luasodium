#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

static const luasodium_function_t ls_utils_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(sodium_memcmp),
    LS_FUNC(sodium_bin2hex),
    LS_FUNC(sodium_hex2bin),
    LS_FUNC(sodium_bin2base64),
    LS_FUNC(sodium_base642bin),
    LS_FUNC(sodium_increment),
    LS_FUNC(sodium_add),
    LS_FUNC(sodium_sub),
    LS_FUNC(sodium_compare),
    LS_FUNC(sodium_is_zero),
    LS_FUNC(sodium_pad),
    LS_FUNC(sodium_unpad),
    LS_FUNC(sodium_base64_encoded_len),
    { NULL, NULL },
};

int
luaopen_luasodium_utils_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,utils_lua,utils_lua_length - 1,"utils.lua")) {
        return lua_error(L);
    }
    luasodium_push_functions(L,ls_utils_functions);
    luasodium_push_constants(L,ls_utils_constants);

    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }
    return 1;
}

