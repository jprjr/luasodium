#include "../luasodium-c.h"
#include "../internals/ls_lua_equal.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef void (*ls_crypto_generichash_keygen_ptr)(
  unsigned char *);

typedef int (*ls_crypto_generichash_ptr)(
  unsigned char *, size_t ,
  const unsigned char *, unsigned long long,
  const unsigned char *, size_t);

static int
ls_crypto_generichash_keygen(lua_State *L) {
    unsigned char *k = NULL;
    ls_crypto_generichash_keygen_ptr f = NULL;
    size_t KEYBYTES = 0;

    f = (ls_crypto_generichash_keygen_ptr) lua_touserdata(L,lua_upvalueindex(1));
    KEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(2));

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

static int
ls_crypto_generichash(lua_State *L) {
    unsigned char *out = NULL;
    const unsigned char *in = NULL;
    const unsigned char *key = NULL;

    size_t outlen = 0;
    size_t inlen = 0;
    size_t keylen = 0;

    const char *fname = NULL;
    ls_crypto_generichash_ptr f = NULL;

    size_t BYTES = 0;
    size_t BYTES_MIN = 0;
    size_t BYTES_MAX = 0;

    size_t KEYBYTES_MIN = 0;
    size_t KEYBYTES_MAX = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires at least 1 parameter");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_generichash_ptr)lua_touserdata(L,lua_upvalueindex(2));
    BYTES = (size_t) lua_tointeger(L, lua_upvalueindex(3));
    BYTES_MIN = (size_t) lua_tointeger(L, lua_upvalueindex(4));
    BYTES_MAX = (size_t) lua_tointeger(L, lua_upvalueindex(5));
    KEYBYTES_MIN = (size_t) lua_tointeger(L, lua_upvalueindex(6));
    KEYBYTES_MAX = (size_t) lua_tointeger(L, lua_upvalueindex(7));

    in = (const unsigned char *)lua_tolstring(L,1,&inlen);

    if(lua_isstring(L,2)) {
        key = (const unsigned char *)lua_tolstring(L,2,&keylen);
        if(keylen < KEYBYTES_MIN) {
            return luaL_error(L,"key too small, required minimum: %d",
              KEYBYTES_MIN);
        } else if(keylen > KEYBYTES_MAX) {
            return luaL_error(L,"key too large, required maximum: %d",
              KEYBYTES_MAX);
        }
    }

    if(lua_isnumber(L,3)) {
        outlen = (size_t)lua_tointeger(L,3);
        if(outlen < BYTES_MIN) {
            return luaL_error(L,"hash too small, required minimum: %d",
              BYTES_MIN);
        } else if(outlen > BYTES_MAX) {
            return luaL_error(L,"hash too large, required maximum: %d",
              BYTES_MAX);
        }
    } else {
        outlen = BYTES;
    }

    out = lua_newuserdata(L,outlen);

    /* LCOV_EXCL_START */
    if(out == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(out,outlen,in,inlen,key,keylen) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)out,outlen);
    sodium_memzero(out,outlen);

    return 1;
}

#define LS_PUSH_CRYPTO_GENERICHASH_KEYGEN(x) \
  lua_pushlightuserdata(L, x ## _keygen); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_generichash_keygen, 2); \
  lua_setfield(L,-2, #x "_keygen")

#define LS_PUSH_CRYPTO_GENERICHASH(x) \
  lua_pushliteral(L, #x ); \
  lua_pushlightuserdata(L, x ); \
  lua_pushinteger(L, x ## _BYTES); \
  lua_pushinteger(L, x ## _BYTES_MIN); \
  lua_pushinteger(L, x ## _BYTES_MAX); \
  lua_pushinteger(L, x ## _KEYBYTES_MIN); \
  lua_pushinteger(L, x ## _KEYBYTES_MAX); \
  lua_pushcclosure(L, ls_crypto_generichash, 7); \
  lua_setfield(L,-2, #x )

LS_PUBLIC
int luaopen_luasodium_crypto_generichash_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */

    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_generichash_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_GENERICHASH_KEYGEN(crypto_generichash);
    LS_PUSH_CRYPTO_GENERICHASH(crypto_generichash);

    return 1;
}
