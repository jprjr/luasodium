#include "../luasodium-c.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef int (*ls_crypto_auth_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *);

typedef int (*ls_crypto_auth_verify_ptr)(
  const unsigned char *m,
  const unsigned char *,
  unsigned long long,
  const unsigned char *);

typedef void (*ls_crypto_auth_keygen_ptr)(
  unsigned char *);

static int
ls_crypto_auth(lua_State *L) {
    unsigned char *out = NULL;
    const unsigned char *in = NULL;
    const unsigned char *k = NULL;

    size_t inlen = 0;
    size_t klen = 0;

    const char *fname = NULL;
    ls_crypto_auth_ptr f = NULL;
    size_t BYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 parameters");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f     = (ls_crypto_auth_ptr)lua_touserdata(L,lua_upvalueindex(2));
    BYTES = lua_tointeger(L,lua_upvalueindex(3));
    KEYBYTES = lua_tointeger(L,lua_upvalueindex(4));

    in = (const unsigned char *)lua_tolstring(L,1,&inlen);
    k =  (const unsigned char *)lua_tolstring(L,2,&klen);

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d", KEYBYTES);
    }

    out = (unsigned char *)lua_newuserdata(L,BYTES);

    /* LCOV_EXCL_START */
    if(out == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(out,in,inlen,k) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)out,BYTES);
    sodium_memzero(out,BYTES);
    return 1;
}

static int
ls_crypto_auth_verify(lua_State *L) {
    const unsigned char *h = NULL;
    const unsigned char *in = NULL;
    const unsigned char *k = NULL;

    size_t hlen = 0;
    size_t inlen = 0;
    size_t klen = 0;

    ls_crypto_auth_verify_ptr f = NULL;
    size_t BYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    f     = (ls_crypto_auth_verify_ptr)lua_touserdata(L,lua_upvalueindex(1));
    BYTES = lua_tointeger(L,lua_upvalueindex(2));
    KEYBYTES = lua_tointeger(L,lua_upvalueindex(3));

    h =  (const unsigned char *)lua_tolstring(L,1,&hlen);
    in = (const unsigned char *)lua_tolstring(L,2,&inlen);
    k =  (const unsigned char *)lua_tolstring(L,3,&klen);

    if(hlen != BYTES) {
        return luaL_error(L,"wrong tag size, expected: %d", BYTES);
    }

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d", KEYBYTES);
    }

    lua_pushboolean(L,f(h,in,inlen,k) == 0);
    return 1;
}

static int
ls_crypto_auth_keygen(lua_State *L) {
    unsigned char *k = NULL;

    ls_crypto_auth_keygen_ptr f = NULL;
    size_t KEYBYTES = 0;

    f     = (ls_crypto_auth_keygen_ptr)lua_touserdata(L,lua_upvalueindex(1));
    KEYBYTES = lua_tointeger(L,lua_upvalueindex(2));

    k = (unsigned char *)lua_newuserdata(L,KEYBYTES);

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

#define LS_PUSH_CRYPTO_AUTH(x) \
  lua_pushliteral(L, #x ); \
  lua_pushlightuserdata(L, x); \
  lua_pushinteger(L, x ## _BYTES); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_auth , 4); \
  lua_setfield(L,-2, #x);

#define LS_PUSH_CRYPTO_AUTH_VERIFY(x) \
  lua_pushlightuserdata(L, x ## _verify); \
  lua_pushinteger(L, x ## _BYTES); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_auth_verify, 3); \
  lua_setfield(L,-2, #x "_verify");

#define LS_PUSH_CRYPTO_AUTH_KEYGEN(x) \
  lua_pushlightuserdata(L, x ## _keygen); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L,ls_crypto_auth_keygen, 2); \
  lua_setfield(L,-2, #x "_keygen");


LS_PUBLIC
int luaopen_luasodium_crypto_auth_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_auth_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_AUTH(crypto_auth);
    LS_PUSH_CRYPTO_AUTH_VERIFY(crypto_auth);
    LS_PUSH_CRYPTO_AUTH_KEYGEN(crypto_auth);

    LS_PUSH_CRYPTO_AUTH(crypto_auth_hmacsha256);
    LS_PUSH_CRYPTO_AUTH_VERIFY(crypto_auth_hmacsha256);
    LS_PUSH_CRYPTO_AUTH_KEYGEN(crypto_auth_hmacsha256);

    LS_PUSH_CRYPTO_AUTH(crypto_auth_hmacsha512256);
    LS_PUSH_CRYPTO_AUTH_VERIFY(crypto_auth_hmacsha512256);
    LS_PUSH_CRYPTO_AUTH_KEYGEN(crypto_auth_hmacsha512256);

    LS_PUSH_CRYPTO_AUTH(crypto_auth_hmacsha512);
    LS_PUSH_CRYPTO_AUTH_VERIFY(crypto_auth_hmacsha512);
    LS_PUSH_CRYPTO_AUTH_KEYGEN(crypto_auth_hmacsha512);

    return 1;
}
