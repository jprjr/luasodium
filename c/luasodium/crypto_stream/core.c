#include "../luasodium-c.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef int (*ls_crypto_stream_ptr)(
  unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_stream_xor_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef void (*ls_crypto_stream_keygen_ptr)(
  unsigned char *);

static int
ls_crypto_stream(lua_State *L) {
    unsigned char *c = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;
    size_t clen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    const char *fname = NULL;
    ls_crypto_stream_ptr f = NULL;
    size_t NONCEBYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameter");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_stream_ptr) lua_touserdata(L,lua_upvalueindex(2));
    NONCEBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(3));
    KEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(4));

    clen = lua_tointeger(L,1);
    n = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",
          NONCEBYTES);
    }

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",
          KEYBYTES);
    }

    c = lua_newuserdata(L,clen);
    /* LCOV_EXCL_START */
    if(c == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(c,clen,n,k) == -1) {
        return luaL_error(L,"%s error",fname);
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

    const char *fname = NULL;
    ls_crypto_stream_xor_ptr f = NULL;
    size_t NONCEBYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameter");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_stream_xor_ptr) lua_touserdata(L,lua_upvalueindex(2));
    NONCEBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(3));
    KEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(4));

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",
          NONCEBYTES);
    }

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",
          KEYBYTES);
    }

    c = lua_newuserdata(L,mlen);
    /* LCOV_EXCL_START */
    if(c == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(c,m,mlen,n,k) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)c,mlen);
    sodium_memzero(c,mlen);
    return 1;
}

static int
ls_crypto_stream_keygen(lua_State *L) {
    unsigned char *k = NULL;

    ls_crypto_stream_keygen_ptr f = NULL;
    size_t KEYBYTES = 0;

    f = (ls_crypto_stream_keygen_ptr) lua_touserdata(L,lua_upvalueindex(1));
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

#define LS_PUSH_CRYPTO_STREAM(x,y) \
  lua_pushliteral(L, #x); \
  lua_pushlightuserdata(L, x); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, y, 4); \
  lua_setfield(L,-2, #x)

#define LS_PUSH_CRYPTO_STREAM_XOR(x,y) \
  lua_pushliteral(L, #x); \
  lua_pushlightuserdata(L, x ## _xor); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, y, 4); \
  lua_setfield(L,-2, #x "_xor")

#define LS_PUSH_CRYPTO_STREAM_KEYGEN(x,y) \
  lua_pushlightuserdata(L, x ## _keygen); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, y, 2); \
  lua_setfield(L,-2, #x "_keygen")

LS_PUBLIC
int luaopen_luasodium_crypto_stream_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_stream_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_STREAM(crypto_stream,ls_crypto_stream);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream,ls_crypto_stream_xor);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream,ls_crypto_stream_keygen);

    LS_PUSH_CRYPTO_STREAM(crypto_stream_xsalsa20,ls_crypto_stream);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream_xsalsa20,ls_crypto_stream_xor);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream_xsalsa20,ls_crypto_stream_keygen);

    LS_PUSH_CRYPTO_STREAM(crypto_stream_salsa20,ls_crypto_stream);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream_salsa20,ls_crypto_stream_xor);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream_salsa20,ls_crypto_stream_keygen);

    LS_PUSH_CRYPTO_STREAM(crypto_stream_salsa2012,ls_crypto_stream);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream_salsa2012,ls_crypto_stream_xor);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream_salsa2012,ls_crypto_stream_keygen);

    return 1;
}

