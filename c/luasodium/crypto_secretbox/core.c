#include "../luasodium-c.h"
#include "constants.h"

#include <stdlib.h>
#include <string.h>

/* crypto_secretbox_keygen() */
static int
ls_crypto_secretbox_keygen(lua_State *L) {
    unsigned char *k = NULL;

    k = lua_newuserdata(L,crypto_secretbox_KEYBYTES);
    if(k == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);
    crypto_secretbox_keygen(k);
    lua_pushlstring(L,(const char *)k,crypto_secretbox_KEYBYTES);
    sodium_memzero(k,crypto_secretbox_KEYBYTES);
    return 1;
}


/* crypto_secretbox, crypto_secretbox_xsalsa20poly1305, etc */
static int
ls_crypto_secretbox(lua_State *L) {
    unsigned char *output      = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    unsigned char *tmp_input   = NULL;

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

    tmp_input = (unsigned char *)lua_newuserdata(L,inputlen + crypto_secretbox_ZEROBYTES);
    if(tmp_input == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    output = (unsigned char *)lua_newuserdata(L,outputlen + crypto_secretbox_BOXZEROBYTES);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    sodium_memzero(tmp_input,crypto_secretbox_ZEROBYTES);
    sodium_memzero(output,crypto_secretbox_BOXZEROBYTES);

    memcpy(&tmp_input[crypto_secretbox_ZEROBYTES],input,inputlen);

    if(crypto_secretbox(output,tmp_input,inputlen+crypto_secretbox_ZEROBYTES,nonce,key) == -1) {
        return luaL_error(L,"crypto_secretbox error");
    }

    lua_pushlstring(L,(const char *)&output[crypto_secretbox_BOXZEROBYTES],outputlen);
    sodium_memzero(tmp_input,inputlen + crypto_secretbox_ZEROBYTES);
    sodium_memzero(output,outputlen + crypto_secretbox_BOXZEROBYTES);
    return 1;
}

/* crypto_secretbox_open, crypto_secretbox_xsalsa20poly1305_open, etc */
static int
ls_crypto_secretbox_open(lua_State *L) {
    unsigned char *output      = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    unsigned char *tmp_input   = NULL;

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
        return luaL_error(L,"wront mac size, expected at least: %d",crypto_secretbox_MACBYTES);
    }

    if(noncelen != crypto_secretbox_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_secretbox_NONCEBYTES);
    }

    if(keylen != crypto_secretbox_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_secretbox_KEYBYTES);
    }

    outputlen = inputlen - crypto_secretbox_MACBYTES;

    tmp_input = (unsigned char *)lua_newuserdata(L,inputlen + crypto_secretbox_BOXZEROBYTES);
    if(tmp_input == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    output = (unsigned char *)lua_newuserdata(L,outputlen + crypto_secretbox_ZEROBYTES);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    sodium_memzero(tmp_input,crypto_secretbox_BOXZEROBYTES);
    sodium_memzero(output,crypto_secretbox_ZEROBYTES);

    memcpy(&tmp_input[crypto_secretbox_BOXZEROBYTES],input,inputlen);

    if(crypto_secretbox_open(output,tmp_input,inputlen+crypto_secretbox_BOXZEROBYTES,nonce,key) == -1) {
        return luaL_error(L,"crypto_secretbox_open error");
    }

    lua_pushlstring(L,(const char *)&output[crypto_secretbox_ZEROBYTES],outputlen);
    sodium_memzero(tmp_input,inputlen + crypto_secretbox_BOXZEROBYTES);
    sodium_memzero(output,outputlen + crypto_secretbox_ZEROBYTES);
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
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(crypto_secretbox_easy(output,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"crypto_secretbox_easy error");
    }

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
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
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
    unsigned char *mac = NULL;
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
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    mac = lua_newuserdata(L,crypto_secretbox_MACBYTES);
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(crypto_secretbox_detached(output,mac,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"crypto_secretbox_detached error");
    }

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
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }

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

int
luaopen_luasodium_crypto_secretbox_core(lua_State *L) {
    LUASODIUM_INIT(L)
    lua_newtable(L);
    luasodium_set_constants(L,ls_crypto_secretbox_constants);
    luaL_setfuncs(L,ls_crypto_secretbox_funcs,0);

    return 1;
}
