#include "../luasodium-c.h"
#include "constants.h"

#include <stdlib.h>
#include <string.h>

/* crypto_secretbox_keygen() */
static int
ls_crypto_secretbox_keygen(lua_State *L) {
    unsigned char k[crypto_secretbox_KEYBYTES];
    crypto_secretbox_keygen(k);
    lua_pushlstring(L,(const char *)k,crypto_secretbox_KEYBYTES);
    sodium_memzero(k,crypto_secretbox_KEYBYTES);
    return 1;
}


/* crypto_secretbox, crypto_secretbox_xsalsa20poly1305, etc */
static int
ls_crypto_secretbox(lua_State *L) {
    unsigned char *c      = NULL;
    const unsigned char *m = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    unsigned char *tmp_m   = NULL;

    size_t clen = 0;
    size_t mlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != crypto_secretbox_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_secretbox_NONCEBYTES);
    }

    if(keylen != crypto_secretbox_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_secretbox_KEYBYTES);
    }

    clen = mlen + crypto_secretbox_MACBYTES;

    tmp_m = (unsigned char *)lua_newuserdata(L,mlen + crypto_secretbox_ZEROBYTES);
    /* LCOV_EXCL_START */
    if(tmp_m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    c = (unsigned char *)lua_newuserdata(L,clen + crypto_secretbox_BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_m,crypto_secretbox_ZEROBYTES);
    sodium_memzero(c,crypto_secretbox_BOXZEROBYTES);

    memcpy(&tmp_m[crypto_secretbox_ZEROBYTES],m,mlen);

    /* LCOV_EXCL_START */
    if(crypto_secretbox(c,tmp_m,mlen+crypto_secretbox_ZEROBYTES,nonce,key) == -1) {
        return luaL_error(L,"crypto_secretbox error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)&c[crypto_secretbox_BOXZEROBYTES],clen);
    sodium_memzero(tmp_m,mlen + crypto_secretbox_ZEROBYTES);
    sodium_memzero(c,clen + crypto_secretbox_BOXZEROBYTES);
    return 1;
}

/* crypto_secretbox_open, crypto_secretbox_xsalsa20poly1305_open, etc */
static int
ls_crypto_secretbox_open(lua_State *L) {
    unsigned char *m      = NULL;
    const unsigned char *c = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    unsigned char *tmp_c   = NULL;

    size_t mlen = 0;
    size_t clen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    c = (const unsigned char *)lua_tolstring(L,1,&clen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(clen <= crypto_secretbox_MACBYTES) {
        return luaL_error(L,"wrong mac size, expected at least: %d",crypto_secretbox_MACBYTES);
    }

    if(noncelen != crypto_secretbox_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_secretbox_NONCEBYTES);
    }

    if(keylen != crypto_secretbox_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_secretbox_KEYBYTES);
    }

    mlen = clen - crypto_secretbox_MACBYTES;

    tmp_c = (unsigned char *)lua_newuserdata(L,clen + crypto_secretbox_BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(tmp_c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    m = (unsigned char *)lua_newuserdata(L,mlen + crypto_secretbox_ZEROBYTES);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_c,crypto_secretbox_BOXZEROBYTES);
    sodium_memzero(m,crypto_secretbox_ZEROBYTES);

    memcpy(&tmp_c[crypto_secretbox_BOXZEROBYTES],c,clen);

    if(crypto_secretbox_open(m,tmp_c,clen+crypto_secretbox_BOXZEROBYTES,nonce,key) == -1) {
        return luaL_error(L,"crypto_secretbox_open error");
    }

    lua_pushlstring(L,(const char *)&m[crypto_secretbox_ZEROBYTES],mlen);
    sodium_memzero(tmp_c,clen + crypto_secretbox_BOXZEROBYTES);
    sodium_memzero(m,mlen + crypto_secretbox_ZEROBYTES);
    return 1;
}

/* crypto_secretbox, crypto_secretbox_xsalsa20poly1305, etc */
static int
ls_crypto_secretbox_easy(lua_State *L) {
    unsigned char *output      = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    size_t outputlen = 0;
    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != crypto_secretbox_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_secretbox_NONCEBYTES);
    }

    if(keylen != crypto_secretbox_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_secretbox_KEYBYTES);
    }

    outputlen = inputlen + crypto_secretbox_MACBYTES;

    output = (unsigned char *)lua_newuserdata(L,outputlen);

    /* LCOV_EXCL_START */
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(crypto_secretbox_easy(output,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"crypto_secretbox_easy error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)output,outputlen);
    sodium_memzero(output,outputlen);
    return 1;
}

/* crypto_secretbox, crypto_secretbox_xsalsa20poly1305, etc */
static int
ls_crypto_secretbox_open_easy(lua_State *L) {
    unsigned char *output      = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    size_t outputlen = 0;
    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(inputlen <= crypto_secretbox_MACBYTES) {
        return luaL_error(L,"wrong mac size, expected at least: %d",crypto_secretbox_MACBYTES);
    }

    if(noncelen != crypto_secretbox_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_secretbox_NONCEBYTES);
    }

    if(keylen != crypto_secretbox_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_secretbox_KEYBYTES);
    }

    outputlen = inputlen - crypto_secretbox_MACBYTES;

    output = (unsigned char *)lua_newuserdata(L,outputlen);

    /* LCOV_EXCL_START */
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    if(crypto_secretbox_open_easy(output,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"crypto_secretbox_open_easy error");
    }

    lua_pushlstring(L,(const char *)output,outputlen);
    sodium_memzero(output,outputlen);
    return 1;
}

/* crypto_secretbox_detached(message, nonce, key) */
static int
ls_crypto_secretbox_detached(lua_State *L) {
    unsigned char *output = NULL;
    unsigned char mac[crypto_secretbox_MACBYTES];
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key = NULL;

    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != crypto_secretbox_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_secretbox_NONCEBYTES);
    }

    if(keylen != crypto_secretbox_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_secretbox_KEYBYTES);
    }

    output = lua_newuserdata(L,inputlen);

    /* LCOV_EXCL_START */
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(crypto_secretbox_detached(output,mac,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"crypto_secretbox_detached error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)output,inputlen);
    lua_pushlstring(L,(const char *)mac,crypto_secretbox_MACBYTES);

    sodium_memzero(output,inputlen);
    sodium_memzero(mac,crypto_secretbox_MACBYTES);
    return 2;
}

/* crypto_secretbox_open_detached(cipher, mac, nonce, key) */
static int
ls_crypto_secretbox_open_detached(lua_State *L) {
    unsigned char *output = NULL;
    const unsigned char *input = NULL;
    const unsigned char *mac = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key = NULL;

    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;
    size_t maclen = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    mac   = (const unsigned char *)lua_tolstring(L,2,&maclen);
    nonce = (const unsigned char *)lua_tolstring(L,3,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,4,&keylen);

    if(maclen != crypto_secretbox_MACBYTES) {
        return luaL_error(L,"wrong mac size, expected: %d",crypto_secretbox_MACBYTES);
    }

    if(noncelen != crypto_secretbox_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_secretbox_NONCEBYTES);
    }

    if(keylen != crypto_secretbox_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_secretbox_KEYBYTES);
    }

    output = lua_newuserdata(L,inputlen);

    /* LCOV_EXCL_START */
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    if(crypto_secretbox_open_detached(output,input,mac,inputlen,nonce,key) == -1) {
        return luaL_error(L,"crypto_secretbox_open_detached error");
    }

    lua_pushlstring(L,(const char *)output,inputlen);
    sodium_memzero(output,inputlen);
    return 1;
}

static const struct luaL_Reg ls_crypto_secretbox_funcs[] = {
    LS_LUA_FUNC(crypto_secretbox_keygen),
    LS_LUA_FUNC(crypto_secretbox),
    LS_LUA_FUNC(crypto_secretbox_open),
    LS_LUA_FUNC(crypto_secretbox_easy),
    LS_LUA_FUNC(crypto_secretbox_open_easy),
    LS_LUA_FUNC(crypto_secretbox_detached),
    LS_LUA_FUNC(crypto_secretbox_open_detached),
    { NULL, NULL }
};

static int
ls_crypto_secretbox_core_setup(lua_State *L) {
    luasodium_set_constants(L,ls_crypto_secretbox_constants,lua_gettop(L));
    luaL_setfuncs(L,ls_crypto_secretbox_funcs,0);
    return 0;
}

int
luaopen_luasodium_crypto_secretbox_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L)
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_crypto_secretbox_core_setup(L);
    return 1;
}
