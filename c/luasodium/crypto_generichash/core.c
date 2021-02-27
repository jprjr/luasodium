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

typedef int (*ls_crypto_generichash_init_ptr)(
  void *,
  const unsigned char *,
  const size_t, const size_t);

typedef int (*ls_crypto_generichash_update_ptr)(
  void *,
  const unsigned char *,
  unsigned long long);

typedef int (*ls_crypto_generichash_final_ptr)(
  void *,
  unsigned char *, const size_t);

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

    /* LCOV_EXCL_START */
    if(f(out,outlen,in,inlen,key,keylen) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)out,outlen);
    sodium_memzero(out,outlen);

    return 1;
}

static int
ls_crypto_generichash_init(lua_State *L) {
    void *state = NULL;
    const unsigned char *key = NULL;

    size_t keylen = 0;
    size_t outlen = 0;

    const char *fname = NULL;
    ls_crypto_generichash_init_ptr f = NULL;

    size_t BYTES = 0;
    size_t BYTES_MIN = 0;
    size_t BYTES_MAX = 0;

    size_t KEYBYTES_MIN = 0;
    size_t KEYBYTES_MAX = 0;
    size_t STATEBYTES = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_generichash_init_ptr)lua_touserdata(L,lua_upvalueindex(2));
    BYTES = (size_t) lua_tointeger(L, lua_upvalueindex(3));
    BYTES_MIN = (size_t) lua_tointeger(L, lua_upvalueindex(4));
    BYTES_MAX = (size_t) lua_tointeger(L, lua_upvalueindex(5));
    KEYBYTES_MIN = (size_t) lua_tointeger(L, lua_upvalueindex(6));
    KEYBYTES_MAX = (size_t) lua_tointeger(L, lua_upvalueindex(7));
    STATEBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(8));

    if(lua_isstring(L,1)) {
        key = (const unsigned char *)lua_tolstring(L,1,&keylen);
        if(keylen < KEYBYTES_MIN) {
            return luaL_error(L,"key too small, required minimum: %d",
              KEYBYTES_MIN);
        } else if(keylen > KEYBYTES_MAX) {
            return luaL_error(L,"key too large, required maximum: %d",
              KEYBYTES_MAX);
        }
    }

    if(lua_isnumber(L,2)) {
        outlen = (size_t)lua_tointeger(L,2);
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

    lua_newtable(L);

    state = lua_newuserdata(L, STATEBYTES);
    lua_pushvalue(L, lua_upvalueindex(10));
    lua_setmetatable(L,-2);

    /* LCOV_EXCL_START */
    if(state == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(state, key, keylen, outlen) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_setfield(L,-2,"state");

    lua_pushinteger(L,outlen);
    lua_setfield(L,-2,"outlen");

    lua_pushvalue(L, lua_upvalueindex(9));
    lua_setmetatable(L,-2);

    return 1;
}

static int
ls_crypto_generichash_update(lua_State *L) {
    void *state = NULL;
    const unsigned char *in = NULL;
    size_t inlen = 0;

    ls_crypto_generichash_update_ptr f = NULL;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    f = (ls_crypto_generichash_update_ptr) lua_touserdata(L, lua_upvalueindex(1));

    lua_pushvalue(L, lua_upvalueindex(2));
    lua_getmetatable(L,1);
    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    lua_getfield(L,1,"state");
    state = lua_touserdata(L,-1);

    in = (const unsigned char *)lua_tolstring(L,2,&inlen);

    /* LCOV_EXCL_START */
    lua_pushboolean(L, f(state,in,inlen) == 0);
    /* LCOV_EXCL_STOP */

    return 1;
}

static int
ls_crypto_generichash_final(lua_State *L) {
    void *state = NULL;
    unsigned char *out = NULL;
    size_t outlen = 0;

    const char *fname = NULL;
    ls_crypto_generichash_final_ptr f = NULL;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameters");
    }

    fname = lua_tostring(L, lua_upvalueindex(1));
    f = (ls_crypto_generichash_final_ptr) lua_touserdata(L, lua_upvalueindex(2));

    lua_pushvalue(L, lua_upvalueindex(3));
    lua_getmetatable(L,1);
    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    lua_getfield(L, 1, "state");
    state = lua_touserdata(L,-1);

    if(lua_isnumber(L,2)) {
        outlen = (size_t) lua_tointeger(L,2);
    } else {
        lua_getfield(L, 1, "outlen");
        outlen = (size_t) lua_tointeger(L,-1);
        lua_pop(L,1);
    }

    out = lua_newuserdata(L,outlen);

    /* LCOV_EXCL_START */
    if(out == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(state,out,outlen) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)out,outlen);
    sodium_memzero(out,outlen);
    return 1;
}

static int
ls_crypto_generichash__gc(lua_State *L) {
    void *state = lua_touserdata(L,1);
    sodium_memzero(state,lua_tointeger(L, lua_upvalueindex(1)));
    return 0;
}

static void
ls_crypto_generichash_setup(lua_State *L,
  size_t BYTES,
  size_t BYTES_MIN,
  size_t BYTES_MAX,
  size_t KEYBYTES_MIN,
  size_t KEYBYTES_MAX,
  size_t STATEBYTES,
  const char *init_name,
  ls_crypto_generichash_init_ptr init_ptr,
  const char *update_name,
  ls_crypto_generichash_update_ptr update_ptr,
  const char *final_name,
  ls_crypto_generichash_final_ptr final_ptr) {

    int module_index = 0;
    int metatable_index = 0;
    int ud_metatable_index = 0;

    module_index = lua_gettop(L);
    lua_newtable(L);
    metatable_index = lua_gettop(L);

    /* we need two metatables, one for the wrapper table,
     * one just for the userdata (for the __gc method) */
    lua_newtable(L);
    ud_metatable_index = lua_gettop(L);

    lua_pushinteger(L, STATEBYTES);
    lua_pushcclosure(L, ls_crypto_generichash__gc, 1);
    lua_setfield(L, ud_metatable_index, "__gc");

    lua_pushstring(L, init_name);
    lua_pushlightuserdata(L, init_ptr);
    lua_pushinteger(L, BYTES);
    lua_pushinteger(L, BYTES_MIN);
    lua_pushinteger(L, BYTES_MAX);
    lua_pushinteger(L, KEYBYTES_MIN);
    lua_pushinteger(L, KEYBYTES_MAX);
    lua_pushinteger(L, STATEBYTES);
    lua_pushvalue(L, metatable_index);
    lua_pushvalue(L, ud_metatable_index);
    lua_pushcclosure(L, ls_crypto_generichash_init, 10);
    lua_setfield(L, module_index, init_name);

    lua_pushlightuserdata(L,update_ptr);
    lua_pushvalue(L, metatable_index);
    lua_pushcclosure(L, ls_crypto_generichash_update, 2);
    lua_setfield(L, module_index, update_name);

    lua_pushstring(L,final_name);
    lua_pushlightuserdata(L,final_ptr);
    lua_pushvalue(L, metatable_index);
    lua_pushcclosure(L, ls_crypto_generichash_final, 3);
    lua_setfield(L, module_index, final_name);

    lua_newtable(L);

    lua_getfield(L, module_index, update_name);
    lua_setfield(L,-2,"update");

    lua_getfield(L, module_index, final_name);
    lua_setfield(L,-2,"final");

    lua_setfield(L,metatable_index,"__index");

    lua_pop(L,2);
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

#define LS_CRYPTO_GENERICHASH_SETUP(x) \
  ls_crypto_generichash_setup(L, \
    x ## _BYTES, \
    x ## _BYTES_MIN, \
    x ## _BYTES_MAX, \
    x ## _KEYBYTES_MIN, \
    x ## _KEYBYTES_MAX, \
    x ## _statebytes(), \
    #x "_init", \
    (ls_crypto_generichash_init_ptr)x ## _init, \
    #x "_update", \
    (ls_crypto_generichash_update_ptr)x ## _update, \
    #x "_final", \
    (ls_crypto_generichash_final_ptr)x ## _final)

LS_PUBLIC
int luaopen_luasodium_crypto_generichash_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */

    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_generichash_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_GENERICHASH_KEYGEN(crypto_generichash);
    LS_PUSH_CRYPTO_GENERICHASH(crypto_generichash);

    LS_CRYPTO_GENERICHASH_SETUP(crypto_generichash);

    return 1;
}
