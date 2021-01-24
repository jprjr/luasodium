#include "../luasodium-c.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef int (*ls_crypto_shorthash_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *);

typedef void (*ls_crypto_shorthash_keygen_ptr)(
  unsigned char *);

static int
ls_crypto_shorthash(lua_State *L) {
    unsigned char *out = NULL;
    const unsigned char *in = NULL;
    const unsigned char *k  = NULL;
    size_t inlen = 0;
    size_t klen = 0;

    const char *fname = NULL;
    ls_crypto_shorthash_ptr f = NULL;
    size_t BYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_shorthash_ptr)lua_touserdata(L,lua_upvalueindex(2));
    BYTES = (size_t) lua_tointeger(L,lua_upvalueindex(3));
    KEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(4));

    in = (const unsigned char *)lua_tolstring(L,1,&inlen);
    k = (const unsigned char *)lua_tolstring(L,2,&klen);

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key length, expected: %d",
          KEYBYTES);
    }

    out = lua_newuserdata(L,BYTES);

    /* LCOV_EXCL_START */
    if(out == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(out,in,inlen,k) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)out,BYTES);
    sodium_memzero(out,BYTES);
    return 1;
}

static int
ls_crypto_shorthash_keygen(lua_State *L) {
    unsigned char *k = NULL;
    ls_crypto_shorthash_keygen_ptr f = NULL;
    size_t KEYBYTES = 0;

    f = (ls_crypto_shorthash_keygen_ptr) lua_touserdata(L,lua_upvalueindex(1));
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

#define LS_CRYPTO_SHORTHASH_KEYGEN(x) \
  lua_pushlightuserdata(L, x ## _keygen); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_shorthash_keygen, 2); \
  lua_setfield(L,-2, #x "_keygen")

#define LS_CRYPTO_SHORTHASH(x) \
  lua_pushliteral(L, #x ); \
  lua_pushlightuserdata(L, x ); \
  lua_pushinteger(L, x ## _BYTES); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_shorthash, 4); \
  lua_setfield(L,-2, #x )

LS_PUBLIC
int luaopen_luasodium_crypto_shorthash_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */

    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_shorthash_constants,lua_gettop(L));
    LS_CRYPTO_SHORTHASH_KEYGEN(crypto_shorthash);

    LS_CRYPTO_SHORTHASH(crypto_shorthash);
    LS_CRYPTO_SHORTHASH(crypto_shorthash_siphashx24);

    return 1;
}

