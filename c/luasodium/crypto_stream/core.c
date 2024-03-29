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

typedef int (*ls_crypto_stream_xor_ic_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *, uint64_t ic,
  const unsigned char *);

typedef int (*ls_crypto_stream_xor_ic32_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *, uint32_t ic,
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

    /* LCOV_EXCL_START */
    if(f(c,clen,n,k) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
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
        return luaL_error(L,"requires 3 parameters");
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

    /* LCOV_EXCL_START */
    if(f(c,m,mlen,n,k) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)c,mlen);
    sodium_memzero(c,mlen);
    return 1;
}

static int
ls_crypto_stream_xor_ic(lua_State *L) {
    unsigned char *c = NULL;
    const unsigned char *m = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;
    size_t mlen = 0;
    size_t nlen = 0;
    size_t klen = 0;
    uint64_t ic = 0;

    const char *fname = NULL;
    ls_crypto_stream_xor_ic_ptr f = NULL;
    size_t NONCEBYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,4)) {
        return luaL_error(L,"requires 4 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_stream_xor_ic_ptr) lua_touserdata(L,lua_upvalueindex(2));
    NONCEBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(3));
    KEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(4));

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k = (const unsigned char *)lua_tolstring(L,3,&klen);
    ic = (uint64_t) lua_tointeger(L,4);

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

    /* LCOV_EXCL_START */
    if(f(c,m,mlen,n,ic,k) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)c,mlen);
    sodium_memzero(c,mlen);
    return 1;
}

static int
ls_crypto_stream_xor_ic32(lua_State *L) {
    unsigned char *c = NULL;
    const unsigned char *m = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;
    size_t mlen = 0;
    size_t nlen = 0;
    size_t klen = 0;
    uint32_t ic = 0;

    const char *fname = NULL;
    ls_crypto_stream_xor_ic32_ptr f = NULL;
    size_t NONCEBYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,4)) {
        return luaL_error(L,"requires 4 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_stream_xor_ic32_ptr) lua_touserdata(L,lua_upvalueindex(2));
    NONCEBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(3));
    KEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(4));

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k = (const unsigned char *)lua_tolstring(L,3,&klen);
    ic = (uint32_t) lua_tointeger(L,4);

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

    /* LCOV_EXCL_START */
    if(f(c,m,mlen,n,ic,k) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
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

    f(k);

    lua_pushlstring(L,(const char *)k,KEYBYTES);
    sodium_memzero(k,KEYBYTES);
    return 1;
}

#define LS_PUSH_CRYPTO_STREAM(x) \
  lua_pushliteral(L, #x); \
  lua_pushlightuserdata(L, x); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_stream, 4); \
  lua_setfield(L,-2, #x)

#define LS_PUSH_CRYPTO_STREAM_XOR(x) \
  lua_pushliteral(L, #x); \
  lua_pushlightuserdata(L, x ## _xor); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_stream_xor, 4); \
  lua_setfield(L,-2, #x "_xor")

#define LS_PUSH_CRYPTO_STREAM_XOR_IC(x) \
  lua_pushliteral(L, #x); \
  lua_pushlightuserdata(L, x ## _xor_ic); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_stream_xor_ic, 4); \
  lua_setfield(L,-2, #x "_xor_ic")

#define LS_PUSH_CRYPTO_STREAM_XOR_IC32(x) \
  lua_pushliteral(L, #x); \
  lua_pushlightuserdata(L, x ## _xor_ic); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_stream_xor_ic32, 4); \
  lua_setfield(L,-2, #x "_xor_ic")

#define LS_PUSH_CRYPTO_STREAM_KEYGEN(x) \
  lua_pushlightuserdata(L, x ## _keygen); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_stream_keygen, 2); \
  lua_setfield(L,-2, #x "_keygen")

LS_PUBLIC
int luaopen_luasodium_crypto_stream_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_stream_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_STREAM(crypto_stream);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream);

    LS_PUSH_CRYPTO_STREAM(crypto_stream_xsalsa20);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream_xsalsa20);
    LS_PUSH_CRYPTO_STREAM_XOR_IC(crypto_stream_xsalsa20);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream_xsalsa20);

    LS_PUSH_CRYPTO_STREAM(crypto_stream_salsa20);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream_salsa20);
    LS_PUSH_CRYPTO_STREAM_XOR_IC(crypto_stream_salsa20);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream_salsa20);

    LS_PUSH_CRYPTO_STREAM(crypto_stream_salsa2012);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream_salsa2012);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream_salsa2012);

    LS_PUSH_CRYPTO_STREAM(crypto_stream_salsa208);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream_salsa208);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream_salsa208);

    LS_PUSH_CRYPTO_STREAM(crypto_stream_xchacha20);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream_xchacha20);
    LS_PUSH_CRYPTO_STREAM_XOR_IC(crypto_stream_xchacha20);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream_xchacha20);

    LS_PUSH_CRYPTO_STREAM(crypto_stream_chacha20);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream_chacha20);
    LS_PUSH_CRYPTO_STREAM_XOR_IC(crypto_stream_chacha20);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream_chacha20);

    LS_PUSH_CRYPTO_STREAM(crypto_stream_chacha20_ietf);
    LS_PUSH_CRYPTO_STREAM_XOR(crypto_stream_chacha20_ietf);
    LS_PUSH_CRYPTO_STREAM_XOR_IC32(crypto_stream_chacha20_ietf);
    LS_PUSH_CRYPTO_STREAM_KEYGEN(crypto_stream_chacha20_ietf);

    return 1;
}

