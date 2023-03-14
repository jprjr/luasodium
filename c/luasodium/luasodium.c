#include "luasodium.h"

static void
copydown(lua_State *L) {
    /* copies keys and values from table on top of stack, to table below */
    lua_pushnil(L);
    while(lua_next(L,-2) != 0) {
        lua_pushvalue(L,-2);
        lua_insert(L,-2);
        lua_settable(L,-5);
    }
    lua_pop(L,1);
}

LS_PUBLIC
int luaopen_luasodium_core(lua_State *L) {
    /* fallback, we need to just open each module individually */
    lua_newtable(L);

    luaopen_luasodium_crypto_aead_core(L);
    copydown(L);
    luaopen_luasodium_crypto_auth_core(L);
    copydown(L);
    luaopen_luasodium_crypto_box_core(L);
    copydown(L);
    luaopen_luasodium_crypto_generichash_core(L);
    copydown(L);
    luaopen_luasodium_crypto_hash_core(L);
    copydown(L);
    luaopen_luasodium_crypto_kx_core(L);
    copydown(L);
    luaopen_luasodium_crypto_onetimeauth_core(L);
    copydown(L);
    luaopen_luasodium_crypto_pwhash_core(L);
    copydown(L);
    luaopen_luasodium_crypto_scalarmult_core(L);
    copydown(L);
    luaopen_luasodium_crypto_secretbox_core(L);
    copydown(L);
    luaopen_luasodium_crypto_secretstream_core(L);
    copydown(L);
    luaopen_luasodium_crypto_shorthash_core(L);
    copydown(L);
    luaopen_luasodium_crypto_sign_core(L);
    copydown(L);
    luaopen_luasodium_crypto_stream_core(L);
    copydown(L);
    luaopen_luasodium_crypto_verify_core(L);
    copydown(L);
    luaopen_luasodium_randombytes_core(L);
    copydown(L);
    luaopen_luasodium_utils_core(L);
    copydown(L);
    luaopen_luasodium_version_core(L);
    copydown(L);

    return 1;
}

/* basically a copy of the lua-based module loaders, in case this
 * is compiled as a static C library */
LS_PUBLIC
int luaopen_luasodium(lua_State *L) {
    int r = 0;

    /* if we're running in some kind of restricted/reduced environment,
     * require may not exist and/or fail */
    lua_getglobal(L,"require");
    r = lua_gettop(L);

    if(lua_type(L,r) != LUA_TFUNCTION) {
        lua_pop(L,1);
        goto fallback;
    }


    lua_pushvalue(L,r);
    lua_pushliteral(L,"luasodium.ffi");

    if(lua_pcall(L,1,1,0) == 0) {
        return 1;
    }

    lua_settop(L,r);
    lua_pushvalue(L,r);
    lua_pushliteral(L,"luasodium.core");
    if(lua_pcall(L,1,1,0) == 0) {
        return 1;
    }

    lua_settop(L,r);
    lua_pushvalue(L,r);
    lua_pushliteral(L,"luasodium.pureffi");
    if(lua_pcall(L,1,1,0) == 0) {
        return 1;
    }

    fallback:
    return luaopen_luasodium_core(L);
}

/* allows doing just require'sodium' */
LS_PUBLIC
int luaopen_sodium(lua_State *L) {
    return luaopen_luasodium(L);
}
