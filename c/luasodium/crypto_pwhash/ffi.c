#include "../luasodium.h"

#include "../internals/ls_lua_push_constants.h"
#include "../internals/ls_lua_push_functions.h"

#include "constants.h"

static const luasodium_function_t ls_crypto_pwhash_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_pwhash),
    LS_FUNC(crypto_pwhash_str),
    LS_FUNC(crypto_pwhash_str_verify),
    LS_FUNC(crypto_pwhash_str_needs_rehash),
    LS_FUNC(crypto_pwhash_argon2i),
    LS_FUNC(crypto_pwhash_argon2i_str),
    LS_FUNC(crypto_pwhash_argon2i_str_verify),
    LS_FUNC(crypto_pwhash_argon2i_str_needs_rehash),
    LS_FUNC(crypto_pwhash_argon2id),
    LS_FUNC(crypto_pwhash_argon2id_str),
    LS_FUNC(crypto_pwhash_argon2id_str_verify),
    LS_FUNC(crypto_pwhash_argon2id_str_needs_rehash),
    { NULL }
};


LS_PUBLIC
int luaopen_luasodium_crypto_pwhash_ffi(lua_State *L) {
    /* use our own variant of LOAD_FFI since we have a string
     * constant to include */

    lua_getglobal(L,"require");
    lua_pushliteral(L,"luasodium._ffi.ffi_loader");
    if(lua_pcall(L,1,1,0)) {
        return lua_error(L);
    }

    lua_pushstring(L,"crypto_pwhash");
    ls_lua_push_functions(L,ls_crypto_pwhash_functions);
    ls_lua_push_constants(L,ls_crypto_pwhash_constants);

    /* top of stack is the constant table */
    lua_pushliteral(L,crypto_pwhash_STRPREFIX);
    lua_setfield(L,-2,"crypto_pwhash_STRPREFIX");
    lua_pushliteral(L,crypto_pwhash_argon2i_STRPREFIX);
    lua_setfield(L,-2,"crypto_pwhash_argon2i_STRPREFIX");
    lua_pushliteral(L,crypto_pwhash_argon2id_STRPREFIX);
    lua_setfield(L,-2,"crypto_pwhash_argon2id_STRPREFIX");

    if(lua_pcall(L,3,1,0)) {
        return lua_error(L);
    }
    return 1;
}
