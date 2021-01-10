#include "../luasodium-c.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef int (*ls_crypto_scalarmult_ptr)(
  unsigned char *,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_scalarmult_base_ptr)(
  unsigned char *,
  const unsigned char *);


static int
ls_crypto_scalarmult_base(lua_State *L) {
    unsigned char *q = NULL;
    const unsigned char *n = NULL;
    size_t n_len = 0;

    const char *fname = NULL;
    ls_crypto_scalarmult_base_ptr f = NULL;
    size_t BYTES = 0;
    size_t SCALARBYTES = 0;

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"requires 1 argument");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_scalarmult_base_ptr)lua_touserdata(L,lua_upvalueindex(2));

    BYTES = lua_tointeger(L,lua_upvalueindex(3));
    SCALARBYTES = lua_tointeger(L,lua_upvalueindex(4));

    n = (const unsigned char *)lua_tolstring(L,1,&n_len);
    if(n_len != SCALARBYTES) {
        return luaL_error(L,"wrong scalar length, expected: %d",
          SCALARBYTES);
    }

    q = (unsigned char *)lua_newuserdata(L,BYTES);

    /* LCOV_EXCL_START */
    if(q == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(q,n) == -1) {
        return luaL_error(L,"%s error", fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)q,BYTES);
    sodium_memzero(q,BYTES);
    return 1;
}

static int
ls_crypto_scalarmult(lua_State *L) {
    unsigned char *q = NULL;
    const unsigned char *n = NULL;
    const unsigned char *p = NULL;
    size_t n_len = 0;
    size_t p_len = 0;

    const char *fname = NULL;
    ls_crypto_scalarmult_ptr f = NULL;
    size_t BYTES = 0;
    size_t SCALARBYTES = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_scalarmult_ptr)lua_touserdata(L,lua_upvalueindex(2));

    BYTES = lua_tointeger(L,lua_upvalueindex(3));
    SCALARBYTES = lua_tointeger(L,lua_upvalueindex(4));

    n = (const unsigned char *)lua_tolstring(L,1,&n_len);
    if(n_len != SCALARBYTES) {
        return luaL_error(L,"wrong scalar length, expected: %d",
          SCALARBYTES);
    }

    p = (const unsigned char *)lua_tolstring(L,2,&p_len);
    if(p_len != BYTES) {
        return luaL_error(L,"wrong scalar length, expected: %d",
          BYTES);
    }

    q = (unsigned char *)lua_newuserdata(L,BYTES);

    /* LCOV_EXCL_START */
    if(q == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(q,n,p) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)q,BYTES);
    sodium_memzero(q,BYTES);
    return 1;
}

LS_PUBLIC
int luaopen_luasodium_crypto_scalarmult_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L)
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_scalarmult_constants,lua_gettop(L));

    lua_pushliteral(L,"crypto_scalarmult");
    lua_pushlightuserdata(L,crypto_scalarmult);
    lua_pushinteger(L,crypto_scalarmult_BYTES);
    lua_pushinteger(L,crypto_scalarmult_SCALARBYTES);
    lua_pushcclosure(L,ls_crypto_scalarmult,4);
    lua_setfield(L,-2,"crypto_scalarmult");

    lua_pushliteral(L,"crypto_scalarmult_base");
    lua_pushlightuserdata(L,crypto_scalarmult_base);
    lua_pushinteger(L,crypto_scalarmult_BYTES);
    lua_pushinteger(L,crypto_scalarmult_SCALARBYTES);
    lua_pushcclosure(L,ls_crypto_scalarmult_base,4);
    lua_setfield(L,-2,"crypto_scalarmult_base");

    lua_pushliteral(L,"crypto_scalarmult_curve25519");
    lua_pushlightuserdata(L,crypto_scalarmult_curve25519);
    lua_pushinteger(L,crypto_scalarmult_curve25519_BYTES);
    lua_pushinteger(L,crypto_scalarmult_curve25519_SCALARBYTES);
    lua_pushcclosure(L,ls_crypto_scalarmult,4);
    lua_setfield(L,-2,"crypto_scalarmult_curve25519");

    lua_pushliteral(L,"crypto_scalarmult_curve25519_base");
    lua_pushlightuserdata(L,crypto_scalarmult_curve25519_base);
    lua_pushinteger(L,crypto_scalarmult_curve25519_BYTES);
    lua_pushinteger(L,crypto_scalarmult_curve25519_SCALARBYTES);
    lua_pushcclosure(L,ls_crypto_scalarmult_base,4);
    lua_setfield(L,-2,"crypto_scalarmult_curve25519_base");

    return 1;
}

