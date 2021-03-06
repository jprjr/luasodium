#include "../luasodium-c.h"
#include "../internals/ls_lua_equal.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef int (*ls_crypto_onetimeauth_ptr)(unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *);

typedef int (*ls_crypto_onetimeauth_verify_ptr)(
  const unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *);

typedef void (*ls_crypto_onetimeauth_keygen_ptr)(
  unsigned char *);

typedef int (*ls_crypto_onetimeauth_init_ptr)(
  void *state,
  const unsigned char *key);

typedef int (*ls_crypto_onetimeauth_update_ptr)(
  void *state,
  const unsigned char *in,
  unsigned long long inlen);

typedef int (*ls_crypto_onetimeauth_final_ptr)(
  void *state,
  unsigned char *out);

static int
ls_crypto_onetimeauth(lua_State *L) {
    unsigned char *c = NULL;
    const unsigned char *m = NULL;
    const unsigned char *k = NULL;
    size_t mlen = 0;
    size_t klen = 0;

    const char *fname = NULL;
    ls_crypto_onetimeauth_ptr f = NULL;
    size_t KEYBYTES = 0;
    size_t BYTES = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 arguments");
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    k = (const unsigned char *)lua_tolstring(L,2,&klen);

    fname    = (const char *)lua_tostring(L,lua_upvalueindex(1));
    f        = (ls_crypto_onetimeauth_ptr)lua_touserdata(L,lua_upvalueindex(2));
    KEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    BYTES    = (size_t)lua_tointeger(L,lua_upvalueindex(4));

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",
          KEYBYTES);
    }

    c = lua_newuserdata(L,BYTES);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(c,m,mlen,k) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)c,BYTES);
    sodium_memzero(c,BYTES);
    return 1;
}

static int
ls_crypto_onetimeauth_verify(lua_State *L) {
    const unsigned char *c = NULL;
    const unsigned char *m = NULL;
    const unsigned char *k = NULL;
    size_t clen = 0;
    size_t mlen = 0;
    size_t klen = 0;

    ls_crypto_onetimeauth_verify_ptr f = NULL;
    size_t KEYBYTES = 0;
    size_t BYTES = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 arguments");
    }

    c = (const unsigned char *)lua_tolstring(L,1,&clen);
    m = (const unsigned char *)lua_tolstring(L,2,&mlen);
    k = (const unsigned char *)lua_tolstring(L,3,&klen);

    f        = (ls_crypto_onetimeauth_verify_ptr)lua_touserdata(L,lua_upvalueindex(1));
    KEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(2));
    BYTES    = (size_t)lua_tointeger(L,lua_upvalueindex(3));

    if(clen != BYTES) {
        return luaL_error(L,"wrong authenticator size, expected: %d",
          BYTES);
    }

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",
          KEYBYTES);
    }

    lua_pushboolean(L,f(c,m,mlen,k) == 0);
    return 1;
}

static int
ls_crypto_onetimeauth_keygen(lua_State *L) {
    unsigned char *k = NULL;

    ls_crypto_onetimeauth_keygen_ptr f = NULL;
    size_t KEYBYTES = 0;

    f        = (ls_crypto_onetimeauth_keygen_ptr)lua_touserdata(L,lua_upvalueindex(1));
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
ls_crypto_onetimeauth_init(lua_State *L) {
    void *state = NULL;
    const unsigned char *k = NULL;
    size_t klen = 0;

    const char *fname = NULL;
    ls_crypto_onetimeauth_init_ptr f = NULL;
    size_t KEYBYTES = 0;
    size_t STATEBYTES = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    fname    = (const char *)lua_tostring(L,lua_upvalueindex(1));
    f        = (ls_crypto_onetimeauth_init_ptr)lua_touserdata(L,lua_upvalueindex(2));
    KEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    STATEBYTES    = (size_t)lua_tointeger(L,lua_upvalueindex(4));

    k = (const unsigned char *)lua_tolstring(L,1,&klen);

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",
          KEYBYTES);
    }

    state = lua_newuserdata(L,
      STATEBYTES);

    /* LCOV_EXCL_START */
    if(state == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(state,k) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushvalue(L,lua_upvalueindex(5));
    lua_setmetatable(L,-2);

    return 1;
}

static int
ls_crypto_onetimeauth_update(lua_State *L) {
    void *state = NULL;
    const unsigned char *m   = NULL;
    size_t mlen = 0;

    ls_crypto_onetimeauth_update_ptr f = NULL;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    f = (ls_crypto_onetimeauth_update_ptr)lua_touserdata(L,lua_upvalueindex(1));

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(2));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    state = (void *)lua_touserdata(L,1);
    m   = (const unsigned char *)lua_tolstring(L,2,&mlen);

    lua_pushboolean(L,f(
      state,m,mlen) != -1);
    return 1;
}

static int
ls_crypto_onetimeauth_final(lua_State *L) {
    void *state = NULL;
    unsigned char *h = NULL;

    const char *fname = NULL;
    ls_crypto_onetimeauth_final_ptr f = NULL;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_onetimeauth_final_ptr)lua_touserdata(L,lua_upvalueindex(2));
    size_t BYTES = lua_tointeger(L,lua_upvalueindex(3));

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(4));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    state = lua_touserdata(L,1);

    h = (unsigned char *)lua_newuserdata(L,BYTES);

    /* LCOV_EXCL_START */
    if(h == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(state,h) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)h,BYTES);
    sodium_memzero(h,BYTES);

    return 1;
}

static int
ls_crypto_onetimeauth_state__gc(lua_State *L) {
    void *state = lua_touserdata(L,1);
    size_t STATEBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(1));
    sodium_memzero(state,STATEBYTES);
    return 0;
}

#define LS_PUSH_CRYPTO_ONETIMEAUTH(x) \
    lua_pushliteral(L, #x ); \
    lua_pushlightuserdata(L, x ); \
    lua_pushinteger(L,x ## _KEYBYTES); \
    lua_pushinteger(L,x ## _BYTES); \
    lua_pushcclosure(L,ls_crypto_onetimeauth,4); \
    lua_setfield(L,-2, #x );

#define LS_PUSH_CRYPTO_ONETIMEAUTH_VERIFY(x) \
    lua_pushlightuserdata(L, x ## _verify ); \
    lua_pushinteger(L,x ## _KEYBYTES); \
    lua_pushinteger(L,x ## _BYTES); \
    lua_pushcclosure(L,ls_crypto_onetimeauth_verify,3); \
    lua_setfield(L,-2, #x "_verify" );

#define LS_PUSH_CRYPTO_ONETIMEAUTH_KEYGEN(x) \
    lua_pushlightuserdata(L, x ## _keygen ); \
    lua_pushinteger(L,x ## _KEYBYTES); \
    lua_pushcclosure(L,ls_crypto_onetimeauth_keygen,2); \
    lua_setfield(L,-2, #x "_keygen" );


static void
ls_crypto_onetimeauth_state_setup(lua_State *L,
  size_t STATEBYTES,
  size_t KEYBYTES,
  size_t BYTES,
  const char *initname,
  ls_crypto_onetimeauth_init_ptr init_ptr,
  const char *updatename,
  ls_crypto_onetimeauth_update_ptr update_ptr,
  const char *finalname,
  ls_crypto_onetimeauth_final_ptr final_ptr) {

    int module_index = 0;
    int metatable_index = 0;

    module_index = lua_gettop(L);

    /* create our metatable for crypto_onetimeauth_state */
    lua_newtable(L);
    metatable_index = lua_gettop(L);

    /* first the init method */
    lua_pushstring(L,initname);
    lua_pushlightuserdata(L,init_ptr);
    lua_pushinteger(L,KEYBYTES);
    lua_pushinteger(L,STATEBYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_onetimeauth_init,5);
    lua_setfield(L,module_index,initname);

    /* __gc method */
    lua_pushinteger(L,STATEBYTES);
    lua_pushcclosure(L,ls_crypto_onetimeauth_state__gc,1);
    lua_setfield(L,-2,"__gc");

    lua_pushlightuserdata(L,update_ptr);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_onetimeauth_update,2);
    lua_setfield(L,module_index,updatename);

    lua_pushstring(L,finalname);
    lua_pushlightuserdata(L,final_ptr);
    lua_pushinteger(L,BYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_onetimeauth_final,4);
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

#define LS_CRYPTO_ONETIMEAUTH_STATE_SETUP(x) \
    ls_crypto_onetimeauth_state_setup(L, \
      x ## _statebytes(), \
      x ## _KEYBYTES, \
      x ## _BYTES, \
      #x "_init", \
      (ls_crypto_onetimeauth_init_ptr)x ## _init, \
      #x "_update", \
      (ls_crypto_onetimeauth_update_ptr) x ## _update, \
      #x "_final", \
      (ls_crypto_onetimeauth_final_ptr)x ## _final);

LS_PUBLIC
int luaopen_luasodium_crypto_onetimeauth_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */

    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_onetimeauth_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_ONETIMEAUTH(crypto_onetimeauth);
    LS_PUSH_CRYPTO_ONETIMEAUTH_VERIFY(crypto_onetimeauth);
    LS_PUSH_CRYPTO_ONETIMEAUTH_KEYGEN(crypto_onetimeauth);

    LS_PUSH_CRYPTO_ONETIMEAUTH(crypto_onetimeauth_poly1305);
    LS_PUSH_CRYPTO_ONETIMEAUTH_VERIFY(crypto_onetimeauth_poly1305);
    LS_PUSH_CRYPTO_ONETIMEAUTH_KEYGEN(crypto_onetimeauth_poly1305);

    LS_CRYPTO_ONETIMEAUTH_STATE_SETUP(crypto_onetimeauth);
    LS_CRYPTO_ONETIMEAUTH_STATE_SETUP(crypto_onetimeauth_poly1305);

    return 1;
}

