#include "../luasodium-c.h"
#include "constants.h"

static int
ls_crypto_hash(lua_State *L) {
    unsigned char h[crypto_hash_BYTES];
    const unsigned char *m = NULL;
    size_t mlen = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);

    if(crypto_hash(h,m,mlen) == -1) {
        return luaL_error(L,"crypto_hash error");
    }

    lua_pushlstring(L,(const char *)h,crypto_hash_BYTES);
    sodium_memzero(h,crypto_hash_BYTES);
    return 1;
}

static int
ls_crypto_hash_sha256(lua_State *L) {
    unsigned char h[crypto_hash_sha256_BYTES];
    const unsigned char *m = NULL;
    size_t mlen = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);

    if(crypto_hash_sha256(h,m,mlen) == -1) {
        return luaL_error(L,"crypto_hash error");
    }

    lua_pushlstring(L,(const char *)h,crypto_hash_sha256_BYTES);
    sodium_memzero(h,crypto_hash_sha256_BYTES);
    return 1;
}

static int
ls_crypto_hash_sha512(lua_State *L) {
    unsigned char h[crypto_hash_sha512_BYTES];
    const unsigned char *m = NULL;
    size_t mlen = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);

    if(crypto_hash_sha512(h,m,mlen) == -1) {
        return luaL_error(L,"crypto_hash error");
    }

    lua_pushlstring(L,(const char *)h,crypto_hash_sha512_BYTES);
    sodium_memzero(h,crypto_hash_sha512_BYTES);
    return 1;
}

static const struct luaL_Reg ls_crypto_hash_functions[] = {
    LS_LUA_FUNC(crypto_hash),
    LS_LUA_FUNC(crypto_hash_sha256),
    LS_LUA_FUNC(crypto_hash_sha512),
    { NULL, NULL },
};

static int
ls_crypto_hash_core_setup(lua_State *L) {
    luasodium_set_constants(L,ls_crypto_hash_constants);
    luaL_setfuncs(L,ls_crypto_hash_functions,0);
    return 0;
}

