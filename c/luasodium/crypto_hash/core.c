#include "../luasodium-c.h"
#include "../internals/ls_lua_equal.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef int (*ls_crypto_hash_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long);

typedef int (*ls_crypto_hash_init_ptr)(
  void *);

typedef int (*ls_crypto_hash_update_ptr)(
  void *,
  const unsigned char *,
  unsigned long long);

typedef int (*ls_crypto_hash_final_ptr)(
  void *,
  unsigned char *);

static int
ls_crypto_hash(lua_State *L) {
    unsigned char *h = NULL; /*[crypto_hash_BYTES];*/
    const unsigned char *m = NULL;
    size_t mlen = 0;

    const char *fname = NULL;
    ls_crypto_hash_ptr f = NULL;
    size_t BYTES = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_hash_ptr)lua_touserdata(L,lua_upvalueindex(2));
    BYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);

    h = (unsigned char *)lua_newuserdata(L,BYTES);

    /* LCOV_EXCL_START */
    if(h == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(h,m,mlen) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)h,BYTES);
    sodium_memzero(h,BYTES);
    return 1;
}

static int
ls_crypto_hash_init(lua_State *L) {
    void *state = NULL;

    const char *fname = NULL;
    ls_crypto_hash_init_ptr f = NULL;
    size_t STATEBYTES = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_hash_init_ptr)lua_touserdata(L,lua_upvalueindex(2));
    STATEBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));

    state = lua_newuserdata(L, STATEBYTES);

    /* LCOV_EXCL_START */
    if(state == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(state) == -1) {
        lua_pop(L,1);
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushvalue(L,lua_upvalueindex(4));
    lua_setmetatable(L,-2);

    return 1;
}

static int
ls_crypto_hash_update(lua_State *L) {
    void *state = NULL;
    const unsigned char *m   = NULL;
    size_t mlen = 0;

    ls_crypto_hash_update_ptr f = NULL;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(2));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    f     = (ls_crypto_hash_update_ptr)lua_touserdata(L,lua_upvalueindex(1));

    state = (crypto_hash_sha256_state *)lua_touserdata(L,1);
    m   = (const unsigned char *)lua_tolstring(L,2,&mlen);

    lua_pushboolean(L,
    /* LCOV_EXCL_START */
      (f(
      state,m,mlen) != -1)
    /* LCOV_EXCL_STOP */
    );
    return 1;
}

static int
ls_crypto_hash_final(lua_State *L) {
    void *state = NULL;
    unsigned char *h = NULL;

    const char *fname = NULL;
    ls_crypto_hash_final_ptr f = NULL;
    size_t BYTES = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameters");
    }

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(4));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_hash_final_ptr) lua_touserdata(L,lua_upvalueindex(2));
    BYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));

    state = lua_touserdata(L,1);

    h = lua_newuserdata(L,BYTES);

    /* LCOV_EXCL_START */
    if(h == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(state,h) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)h,BYTES);
    sodium_memzero(h,BYTES);

    return 1;
}

static int
ls_crypto_hash_state__gc(lua_State *L) {
    void *state = lua_touserdata(L,1);
    sodium_memzero(state,(size_t)lua_tointeger(L,lua_upvalueindex(1)));
    return 0;
}

#define LS_PUSH_CRYPTO_HASH(x) \
  lua_pushliteral(L,#x); \
  lua_pushlightuserdata(L, x); \
  lua_pushinteger(L, x ## _BYTES ); \
  lua_pushcclosure(L, ls_crypto_hash, 3); \
  lua_setfield(L,-2, #x );

static void
ls_crypto_hash_state_setup(lua_State *L,
  size_t STATEBYTES,
  size_t BYTES,
  const char *initname,
  ls_crypto_hash_init_ptr init_ptr,
  const char *updatename,
  ls_crypto_hash_update_ptr update_ptr,
  const char *finalname,
  ls_crypto_hash_final_ptr final_ptr) {
    int module_index = 0;
    int metatable_index = 0;
    module_index = lua_gettop(L);
    lua_newtable(L);
    metatable_index = lua_gettop(L);

    /* first the init method since we don't need it later */
    lua_pushstring(L,initname);
    lua_pushlightuserdata(L,init_ptr);
    lua_pushinteger(L,STATEBYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_hash_init,4);
    lua_setfield(L,module_index,initname);

    /* let's add the gc method to the metatable */
    lua_pushinteger(L,STATEBYTES);
    lua_pushcclosure(L,ls_crypto_hash_state__gc,1);
    lua_setfield(L,metatable_index,"__gc");

    /* now let's add the update/final methods to the module */
    lua_pushlightuserdata(L,update_ptr);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_hash_update,2);
    lua_setfield(L,module_index,updatename);

    /* and the final method */
    lua_pushstring(L,finalname);
    lua_pushlightuserdata(L,final_ptr);
    lua_pushinteger(L,BYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_hash_final,4);
    lua_setfield(L,module_index,finalname);

    /* now we add these methods to the metatable index */
    lua_newtable(L);
    lua_getfield(L,module_index,updatename);
    lua_setfield(L,-2,"update");
    lua_getfield(L,module_index,finalname);
    lua_setfield(L,-2,"final");
    lua_setfield(L,-2,"__index");
    lua_pop(L,1);
}


LS_PUBLIC
int luaopen_luasodium_crypto_hash_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_hash_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_HASH(crypto_hash);
    LS_PUSH_CRYPTO_HASH(crypto_hash_sha256);
    LS_PUSH_CRYPTO_HASH(crypto_hash_sha512);

    ls_crypto_hash_state_setup(L,
      crypto_hash_sha256_statebytes(),
      crypto_hash_sha256_BYTES,
      "crypto_hash_sha256_init",
      (ls_crypto_hash_init_ptr)crypto_hash_sha256_init,
      "crypto_hash_sha256_update",
      (ls_crypto_hash_update_ptr)crypto_hash_sha256_update,
      "crypto_hash_sha256_final",
      (ls_crypto_hash_final_ptr)crypto_hash_sha256_final);

    ls_crypto_hash_state_setup(L,
      crypto_hash_sha512_statebytes(),
      crypto_hash_sha512_BYTES,
      "crypto_hash_sha512_init",
      (ls_crypto_hash_init_ptr)crypto_hash_sha512_init,
      "crypto_hash_sha512_update",
      (ls_crypto_hash_update_ptr)crypto_hash_sha512_update,
      "crypto_hash_sha512_final",
      (ls_crypto_hash_final_ptr)crypto_hash_sha512_final);

    return 1;
}

