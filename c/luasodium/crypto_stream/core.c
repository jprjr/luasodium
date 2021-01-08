#include "../luasodium-c.h"
#include "constants.h"

static int
ls_crypto_stream(lua_State *L) {
    unsigned char *c = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;
    size_t clen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameter");
    }

    clen = lua_tointeger(L,1);
    n = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != crypto_stream_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",
          crypto_stream_NONCEBYTES);
    }

    if(klen != crypto_stream_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",
          crypto_stream_KEYBYTES);
    }

    c = lua_newuserdata(L,clen);
    /* LCOV_EXCL_START */
    if(c == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(crypto_stream(c,clen,n,k) == -1) {
        return luaL_error(L,"crypto_stream error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)c,clen);
    sodium_memzero(c,clen);
    return 1;
}

static int
ls_crypto_stream_xor(lua_State *L) {
    unsigned char *c = NULL;
    const unsigned char *m = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;
    size_t mlen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameter");
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != crypto_stream_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",
          crypto_stream_NONCEBYTES);
    }

    if(klen != crypto_stream_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",
          crypto_stream_KEYBYTES);
    }

    c = lua_newuserdata(L,mlen);
    /* LCOV_EXCL_START */
    if(c == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(crypto_stream_xor(c,m,mlen,n,k) == -1) {
        return luaL_error(L,"crypto_stream_xor error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)c,mlen);
    sodium_memzero(c,mlen);
    return 1;
}

static int
ls_crypto_stream_keygen(lua_State *L) {
    unsigned char k[crypto_stream_KEYBYTES];

    crypto_stream_keygen(k);

    lua_pushlstring(L,(const char *)k,crypto_stream_KEYBYTES);
    sodium_memzero(k,crypto_stream_KEYBYTES);
    return 1;
}

static const struct luaL_Reg ls_crypto_stream_functions[] = {
    LS_LUA_FUNC(crypto_stream),
    LS_LUA_FUNC(crypto_stream_xor),
    LS_LUA_FUNC(crypto_stream_keygen),
    { NULL, NULL },
};

static int
ls_crypto_stream_core_setup(lua_State *L) {
    luasodium_set_constants(L,ls_crypto_stream_constants,lua_gettop(L));
    luaL_setfuncs(L,ls_crypto_stream_functions,0);
    return 0;
}


int luaopen_luasodium_crypto_stream_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_crypto_stream_core_setup(L);

    return 1;
}


