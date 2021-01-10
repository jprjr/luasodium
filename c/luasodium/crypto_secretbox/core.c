#include "../luasodium-c.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

#include <stdlib.h>
#include <string.h>

typedef void (*ls_crypto_secretbox_keygen_ptr)(unsigned char *);

typedef int (*ls_crypto_secretbox_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_secretbox_open_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_secretbox_easy_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_secretbox_open_easy_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_secretbox_detached_ptr)(
  unsigned char *,
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_secretbox_open_detached_ptr)(
  unsigned char *,
  const unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

/* crypto_secretbox_keygen() */
static int
ls_crypto_secretbox_keygen(lua_State *L) {
    unsigned char *k = NULL;

    ls_crypto_secretbox_keygen_ptr f = NULL;
    size_t KEYBYTES = 0;

    f = (ls_crypto_secretbox_keygen_ptr) lua_touserdata(L,lua_upvalueindex(1));
    KEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(2));

    k = lua_newuserdata(L,KEYBYTES);

    /* LCOV_EXCL_START */
    if(k == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    f(k);
    lua_pushlstring(L,(const char *)k,KEYBYTES);
    sodium_memzero(k,KEYBYTES);
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

    const char *fname = NULL;
    ls_crypto_secretbox_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t KEYBYTES = 0;
    size_t ZEROBYTES = 0;
    size_t BOXZEROBYTES = 0;

    size_t clen = 0;
    size_t mlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_secretbox_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    KEYBYTES = lua_tointeger(L,lua_upvalueindex(5));
    ZEROBYTES = lua_tointeger(L,lua_upvalueindex(6));
    BOXZEROBYTES = lua_tointeger(L,lua_upvalueindex(7));

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",NONCEBYTES);
    }

    if(keylen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",KEYBYTES);
    }

    clen = mlen + MACBYTES;

    tmp_m = (unsigned char *)lua_newuserdata(L,mlen + ZEROBYTES);
    /* LCOV_EXCL_START */
    if(tmp_m == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    c = (unsigned char *)lua_newuserdata(L,clen + BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_m, ZEROBYTES);
    sodium_memzero(c,     BOXZEROBYTES);

    memcpy(&tmp_m[ZEROBYTES],m,mlen);

    /* LCOV_EXCL_START */
    if(f(c,tmp_m,mlen+ZEROBYTES,nonce,key) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)&c[BOXZEROBYTES],clen);
    sodium_memzero(tmp_m,mlen + ZEROBYTES);
    sodium_memzero(c,clen + BOXZEROBYTES);
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

    const char *fname = NULL;
    ls_crypto_secretbox_open_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t KEYBYTES = 0;
    size_t ZEROBYTES = 0;
    size_t BOXZEROBYTES = 0;

    size_t mlen = 0;
    size_t clen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_secretbox_open_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    KEYBYTES = lua_tointeger(L,lua_upvalueindex(5));
    ZEROBYTES = lua_tointeger(L,lua_upvalueindex(6));
    BOXZEROBYTES = lua_tointeger(L,lua_upvalueindex(7));

    c = (const unsigned char *)lua_tolstring(L,1,&clen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(clen < MACBYTES) {
        return luaL_error(L,"wrong mac size, expected at least: %d",MACBYTES);
    }

    if(noncelen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",NONCEBYTES);
    }

    if(keylen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",KEYBYTES);
    }

    mlen = clen - MACBYTES;

    tmp_c = (unsigned char *)lua_newuserdata(L,clen + BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(tmp_c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    m = (unsigned char *)lua_newuserdata(L,mlen + ZEROBYTES);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_c,BOXZEROBYTES);
    sodium_memzero(m,ZEROBYTES);

    memcpy(&tmp_c[BOXZEROBYTES],c,clen);

    if(f(m,tmp_c,clen+BOXZEROBYTES,nonce,key) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)&m[ZEROBYTES],mlen);
    sodium_memzero(tmp_c,clen + BOXZEROBYTES);
    sodium_memzero(m,mlen + ZEROBYTES);
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

    const char *fname = NULL;
    ls_crypto_secretbox_easy_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_secretbox_easy_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    KEYBYTES = lua_tointeger(L,lua_upvalueindex(5));

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",NONCEBYTES);
    }

    if(keylen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",KEYBYTES);
    }

    outputlen = inputlen + MACBYTES;

    output = (unsigned char *)lua_newuserdata(L,outputlen);

    /* LCOV_EXCL_START */
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(output,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"%s error",fname);
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

    const char *fname = NULL;
    ls_crypto_secretbox_open_easy_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_secretbox_open_easy_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    KEYBYTES = lua_tointeger(L,lua_upvalueindex(5));

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(inputlen < MACBYTES) {
        return luaL_error(L,"wrong mac size, expected at least: %d",MACBYTES);
    }

    if(noncelen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",NONCEBYTES);
    }

    if(keylen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",KEYBYTES);
    }

    outputlen = inputlen - MACBYTES;

    output = (unsigned char *)lua_newuserdata(L,outputlen);

    /* LCOV_EXCL_START */
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    if(f(output,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"%s error",fname);
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

    const char *fname = NULL;
    ls_crypto_secretbox_detached_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_secretbox_detached_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    KEYBYTES = lua_tointeger(L,lua_upvalueindex(5));

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",NONCEBYTES);
    }

    if(keylen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",KEYBYTES);
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
    if(f(output,mac,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)output,inputlen);
    lua_pushlstring(L,(const char *)mac,MACBYTES);

    sodium_memzero(output,inputlen);
    sodium_memzero(mac,MACBYTES);
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

    const char *fname = NULL;
    ls_crypto_secretbox_open_detached_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 parameters");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_secretbox_open_detached_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    KEYBYTES = lua_tointeger(L,lua_upvalueindex(5));

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    mac   = (const unsigned char *)lua_tolstring(L,2,&maclen);
    nonce = (const unsigned char *)lua_tolstring(L,3,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,4,&keylen);

    if(maclen != MACBYTES) {
        return luaL_error(L,"wrong mac size, expected: %d",MACBYTES);
    }

    if(noncelen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",NONCEBYTES);
    }

    if(keylen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",KEYBYTES);
    }

    output = lua_newuserdata(L,inputlen);

    /* LCOV_EXCL_START */
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    if(f(output,input,mac,inputlen,nonce,key) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)output,inputlen);
    sodium_memzero(output,inputlen);
    return 1;
}


LS_PUBLIC
int
luaopen_luasodium_crypto_secretbox_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L)
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_secretbox_constants,lua_gettop(L));

    lua_pushlightuserdata(L,crypto_secretbox_keygen);
    lua_pushinteger(L,crypto_secretbox_KEYBYTES);
    lua_pushcclosure(L,ls_crypto_secretbox_keygen,2);
    lua_setfield(L,-2,"crypto_secretbox_keygen");

    lua_pushliteral(L,"crypto_secretbox");
    lua_pushlightuserdata(L,crypto_secretbox);
    lua_pushinteger(L,crypto_secretbox_MACBYTES);
    lua_pushinteger(L,crypto_secretbox_NONCEBYTES);
    lua_pushinteger(L,crypto_secretbox_KEYBYTES);
    lua_pushinteger(L,crypto_secretbox_ZEROBYTES);
    lua_pushinteger(L,crypto_secretbox_BOXZEROBYTES);
    lua_pushcclosure(L,ls_crypto_secretbox,7);
    lua_setfield(L,-2,"crypto_secretbox");

    lua_pushliteral(L,"crypto_secretbox_open");
    lua_pushlightuserdata(L,crypto_secretbox_open);
    lua_pushinteger(L,crypto_secretbox_MACBYTES);
    lua_pushinteger(L,crypto_secretbox_NONCEBYTES);
    lua_pushinteger(L,crypto_secretbox_KEYBYTES);
    lua_pushinteger(L,crypto_secretbox_ZEROBYTES);
    lua_pushinteger(L,crypto_secretbox_BOXZEROBYTES);
    lua_pushcclosure(L,ls_crypto_secretbox_open,7);
    lua_setfield(L,-2,"crypto_secretbox_open");

    lua_pushliteral(L,"crypto_secretbox_easy");
    lua_pushlightuserdata(L,crypto_secretbox_easy);
    lua_pushinteger(L,crypto_secretbox_MACBYTES);
    lua_pushinteger(L,crypto_secretbox_NONCEBYTES);
    lua_pushinteger(L,crypto_secretbox_KEYBYTES);
    lua_pushcclosure(L,ls_crypto_secretbox_easy,5);
    lua_setfield(L,-2,"crypto_secretbox_easy");

    lua_pushliteral(L,"crypto_secretbox_open_easy");
    lua_pushlightuserdata(L,crypto_secretbox_open_easy);
    lua_pushinteger(L,crypto_secretbox_MACBYTES);
    lua_pushinteger(L,crypto_secretbox_NONCEBYTES);
    lua_pushinteger(L,crypto_secretbox_KEYBYTES);
    lua_pushcclosure(L,ls_crypto_secretbox_open_easy,5);
    lua_setfield(L,-2,"crypto_secretbox_open_easy");

    lua_pushliteral(L,"crypto_secretbox_detached");
    lua_pushlightuserdata(L,crypto_secretbox_detached);
    lua_pushinteger(L,crypto_secretbox_MACBYTES);
    lua_pushinteger(L,crypto_secretbox_NONCEBYTES);
    lua_pushinteger(L,crypto_secretbox_KEYBYTES);
    lua_pushcclosure(L,ls_crypto_secretbox_detached,5);
    lua_setfield(L,-2,"crypto_secretbox_detached");

    lua_pushliteral(L,"crypto_secretbox_open_detached");
    lua_pushlightuserdata(L,crypto_secretbox_open_detached);
    lua_pushinteger(L,crypto_secretbox_MACBYTES);
    lua_pushinteger(L,crypto_secretbox_NONCEBYTES);
    lua_pushinteger(L,crypto_secretbox_KEYBYTES);
    lua_pushcclosure(L,ls_crypto_secretbox_open_detached,5);
    lua_setfield(L,-2,"crypto_secretbox_open_detached");

    lua_pushlightuserdata(L,crypto_secretbox_xsalsa20poly1305_keygen);
    lua_pushinteger(L,crypto_secretbox_xsalsa20poly1305_KEYBYTES);
    lua_pushcclosure(L,ls_crypto_secretbox_keygen,2);
    lua_setfield(L,-2,"crypto_secretbox_xsalsa20poly1305_keygen");

    lua_pushliteral(L,"crypto_secretbox_xsalsa20poly1305");
    lua_pushlightuserdata(L,crypto_secretbox_xsalsa20poly1305);
    lua_pushinteger(L,crypto_secretbox_xsalsa20poly1305_MACBYTES);
    lua_pushinteger(L,crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
    lua_pushinteger(L,crypto_secretbox_xsalsa20poly1305_KEYBYTES);
    lua_pushinteger(L,crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
    lua_pushinteger(L,crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
    lua_pushcclosure(L,ls_crypto_secretbox,7);
    lua_setfield(L,-2,"crypto_secretbox_xsalsa20poly1305");

    lua_pushliteral(L,"crypto_secretbox_xsalsa20poly1305_open");
    lua_pushlightuserdata(L,crypto_secretbox_xsalsa20poly1305_open);
    lua_pushinteger(L,crypto_secretbox_xsalsa20poly1305_MACBYTES);
    lua_pushinteger(L,crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
    lua_pushinteger(L,crypto_secretbox_xsalsa20poly1305_KEYBYTES);
    lua_pushinteger(L,crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
    lua_pushinteger(L,crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
    lua_pushcclosure(L,ls_crypto_secretbox_open,7);
    lua_setfield(L,-2,"crypto_secretbox_xsalsa20poly1305_open");

    return 1;
}
