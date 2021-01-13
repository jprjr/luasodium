#include "../luasodium-c.h"
#include "../internals/ls_lua_equal.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef void (*ls_crypto_secretstream_keygen_ptr)(
  unsigned char *);

typedef int (*ls_crypto_secretstream_init_push_ptr)(
  void *state,
  unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_secretstream_push_ptr)(
  void *state,
  unsigned char *,
  unsigned long long *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  unsigned long long,
  unsigned char);

typedef int (*ls_crypto_secretstream_init_pull_ptr)(
  void *state,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_secretstream_pull_ptr)(
  void *state,
  unsigned char *,
  unsigned long long *,
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  unsigned long long);

typedef void (*ls_crypto_secretstream_rekey_ptr)(void *);

static int
ls_crypto_secretstream_keygen(lua_State *L) {
    unsigned char *k = NULL;
    ls_crypto_secretstream_keygen_ptr f = NULL;
    size_t KEYBYTES = 0;

    f = (ls_crypto_secretstream_keygen_ptr) lua_touserdata(L,lua_upvalueindex(1));
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
ls_crypto_secretstream_init_push(lua_State *L) {
    void *state = NULL;
    unsigned char *header = NULL;
    const unsigned char *key = NULL;
    size_t keylen = 0;

    const char *fname = NULL;
    ls_crypto_secretstream_init_push_ptr f = NULL;
    size_t STATEBYTES = 0;
    size_t HEADERBYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_secretstream_init_push_ptr) lua_touserdata(L, lua_upvalueindex(2));
    STATEBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(3));
    HEADERBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(4));
    KEYBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(5));

    key = (const unsigned char *)lua_tolstring(L,1,&keylen);

    if(keylen != KEYBYTES) {
        return luaL_error(L,"wrong key length, expected: %d",
          KEYBYTES);
    }

    state = lua_newuserdata(L, STATEBYTES);

    /* LCOV_EXCL_START */
    if(state == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    header = lua_newuserdata(L, HEADERBYTES);

    /* LCOV_EXCL_START */
    if(header == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(state,header,key) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushvalue(L,lua_upvalueindex(6));
    lua_setmetatable(L,-2);

    lua_pushlstring(L,(const char *)header,HEADERBYTES);
    sodium_memzero(header,HEADERBYTES);

    return 2;
}

static int
ls_crypto_secretstream_push(lua_State *L) {
    void *state = NULL;
    unsigned char *c = NULL;
    const unsigned char *m = NULL;
    const unsigned char *ad = NULL;
    unsigned long long clen = 0;
    unsigned char tag = 0;
    size_t mlen = 0;
    size_t adlen = 0;

    const char *fname = NULL;
    ls_crypto_secretstream_push_ptr f = NULL;
    size_t ABYTES = 0;

    /* requires: state, message, tag
     * optional: ad */
    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_secretstream_push_ptr) lua_touserdata(L, lua_upvalueindex(2));
    ABYTES = (size_t) lua_tointeger(L, lua_upvalueindex(3));

    lua_pushvalue(L,lua_upvalueindex(4));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    if(!lua_isstring(L,2)) {
        return luaL_error(L,"invalid message");
    }

    if(!lua_isnumber(L,3)) {
        return luaL_error(L,"invalid tag");
    }

    state = lua_touserdata(L,1);
    m = (const unsigned char *)lua_tolstring(L,2,&mlen);
    tag = (unsigned char)lua_tointeger(L,3);

    if(lua_isstring(L,4)) {
        ad = (const unsigned char *)lua_tolstring(L,4,&adlen);
    }

    c = lua_newuserdata(L,mlen + ABYTES);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    if(f(state,c,&clen,m,mlen,ad,adlen,tag) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)c,clen);
    sodium_memzero(c,mlen + ABYTES);


    return 1;
}

static int
ls_crypto_secretstream_push_tagged(lua_State *L) {
    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    lua_pushvalue(L,lua_upvalueindex(2));
    lua_insert(L,1);

    lua_pushnil(L);
    lua_pushinteger(L,lua_tointeger(L,lua_upvalueindex(1)));
    lua_insert(L,4);

    lua_settop(L,5); /* stack should be:
      function
      userdata
      string
      tag
      string or nil */

    lua_call(L,4,1);
    return 1;
}

/* used for state:rekey() (does an explicit rekey) and
 * state:rekey(message) (does a push with TAG_REKEY) */

static int
ls_crypto_secretstream_push_rekey(lua_State *L) {
    void *state = NULL;
    ls_crypto_secretstream_rekey_ptr f = NULL;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameters");
    }

    if(lua_isnoneornil(L,2)) {
        f = lua_touserdata(L, lua_upvalueindex(3));
        state = lua_touserdata(L, 1);
        f(state);
        return 0;
    }

    lua_pushvalue(L,lua_upvalueindex(2));
    lua_insert(L,1);

    lua_pushnil(L);
    lua_pushinteger(L,lua_tointeger(L,lua_upvalueindex(1)));
    lua_insert(L,4);

    lua_settop(L,5); /* stack should be:
      function
      userdata
      string
      tag
      string or nil */

    lua_call(L,4,1);
    return 1;

}

static int
ls_crypto_secretstream_init_pull(lua_State *L) {
    void *state = NULL;
    const unsigned char *header = NULL;
    const unsigned char *key = NULL;
    size_t keylen = 0;
    size_t headerlen = 0;

    const char *fname = NULL;
    ls_crypto_secretstream_init_pull_ptr f = NULL;
    size_t STATEBYTES = 0;
    size_t HEADERBYTES = 0;
    size_t KEYBYTES = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_secretstream_init_pull_ptr) lua_touserdata(L, lua_upvalueindex(2));
    STATEBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(3));
    HEADERBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(4));
    KEYBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(5));

    header = (const unsigned char *)lua_tolstring(L,1,&headerlen);
    key = (const unsigned char *)lua_tolstring(L,2,&keylen);

    if(headerlen != HEADERBYTES) {
        return luaL_error(L,"wrong header length, expected: %d",
          HEADERBYTES);
    }

    if(keylen != KEYBYTES) {
        return luaL_error(L,"wrong key length, expected: %d",
          KEYBYTES);
    }

    state = lua_newuserdata(L, STATEBYTES);

    /* LCOV_EXCL_START */
    if(state == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    if(f(state,header,key) == -1) {
        lua_pop(L,1);
        lua_pushnil(L);
        lua_pushfstring(L,"%s: invalid header",fname);
        return 2;
    }

    lua_pushvalue(L,lua_upvalueindex(6));
    lua_setmetatable(L,-2);

    return 1;
}

static int
ls_crypto_secretstream_pull(lua_State *L) {
    void *state = NULL;
    unsigned char *m = NULL;
    const unsigned char *c = NULL;
    const unsigned char *ad = NULL;
    unsigned long long mlen = 0;
    unsigned char tag = 0;
    size_t clen = 0;
    size_t adlen = 0;

    const char *fname = NULL;
    ls_crypto_secretstream_pull_ptr f = NULL;
    size_t ABYTES = 0;

    /* requires: state, message
     * optional: ad */
    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_secretstream_pull_ptr) lua_touserdata(L, lua_upvalueindex(2));
    ABYTES = (size_t) lua_tointeger(L, lua_upvalueindex(3));

    lua_pushvalue(L,lua_upvalueindex(4));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    if(!lua_isstring(L,2)) {
        return luaL_error(L,"invalid cipher");
    }

    state = lua_touserdata(L,1);
    c = (const unsigned char *)lua_tolstring(L,2,&clen);

    if(lua_isstring(L,3)) {
        ad = (const unsigned char *)lua_tolstring(L,3,&adlen);
    }

    if(clen < ABYTES) {
        return luaL_error(L,"invalid cipher length, expected at least: %d",
          ABYTES);
    }

    m = lua_newuserdata(L,clen - ABYTES);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    if(f(state,m,&mlen,&tag,c,clen,ad,adlen) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s: invalid cipher",fname);
        return 2;
    }

    lua_pushlstring(L,(const char *)m,mlen);
    sodium_memzero(m,clen - ABYTES);

    lua_pushinteger(L, tag);

    return 2;
}

static int
ls_crypto_secretstream_rekey(lua_State *L) {
    void *state = NULL;
    ls_crypto_secretstream_rekey_ptr f = NULL;

    /* requires: state */
    if(!lua_isuserdata(L,1)) {
        return luaL_error(L,"requires 1 parameters");
    }

    f = (ls_crypto_secretstream_rekey_ptr) lua_touserdata(L, lua_upvalueindex(1));

    state = lua_touserdata(L,1);
    f(state);

    return 0;
}

static int
ls_crypto_secretstream__gc(lua_State *L) {
    void *state = lua_touserdata(L,1);
    sodium_memzero(state, (size_t) lua_tointeger(L, lua_upvalueindex(1)));
    return 0;
}

#define LS_PUSH_CRYPTO_SECRETSTREAM_KEYGEN(x) \
  lua_pushlightuserdata(L, x ## _keygen); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_secretstream_keygen, 2); \
  lua_setfield(L,-2, #x "_keygen")

static void
ls_crypto_secretstream_push_setup(lua_State *L,
  size_t STATEBYTES,
  size_t HEADERBYTES,
  size_t KEYBYTES,
  size_t ABYTES,
  unsigned char TAG_MESSAGE,
  unsigned char TAG_PUSH,
  unsigned char TAG_REKEY,
  unsigned char TAG_FINAL,
  const char *init_push_name,
  ls_crypto_secretstream_init_push_ptr init_push_ptr,
  const char *push_name,
  ls_crypto_secretstream_push_ptr push_ptr,
  const char *init_pull_name,
  ls_crypto_secretstream_init_pull_ptr init_pull_ptr,
  const char *pull_name,
  ls_crypto_secretstream_pull_ptr pull_ptr,
  const char *rekey_name,
  ls_crypto_secretstream_rekey_ptr rekey_ptr) {

    int module_index = 0;
    int metatable_index = 0;

    module_index = lua_gettop(L);

    lua_newtable(L);
    metatable_index = lua_gettop(L);

    lua_pushinteger(L,STATEBYTES);
    lua_pushcclosure(L,ls_crypto_secretstream__gc,1);
    lua_setfield(L,metatable_index,"__gc");

    lua_pushlightuserdata(L,rekey_ptr);
    lua_pushcclosure(L,ls_crypto_secretstream_rekey,1);
    lua_setfield(L,module_index,rekey_name);

    /* init_push method */
    lua_pushstring(L,init_push_name);
    lua_pushlightuserdata(L, init_push_ptr);
    lua_pushinteger(L, STATEBYTES);
    lua_pushinteger(L, HEADERBYTES);
    lua_pushinteger(L, KEYBYTES);
    lua_pushvalue(L, metatable_index);
    lua_pushcclosure(L, ls_crypto_secretstream_init_push, 6);
    lua_setfield(L, module_index, init_push_name);

    lua_pushstring(L,push_name);
    lua_pushlightuserdata(L, push_ptr);
    lua_pushinteger(L, ABYTES);
    lua_pushvalue(L, metatable_index);
    lua_pushcclosure(L, ls_crypto_secretstream_push, 4);
    lua_setfield(L, module_index, push_name);

    lua_newtable(L);

    lua_pushinteger(L,TAG_MESSAGE);
    lua_getfield(L, module_index, push_name);
    lua_pushcclosure(L,ls_crypto_secretstream_push_tagged,2);
    lua_setfield(L,-2,"message");

    lua_pushinteger(L,TAG_PUSH);
    lua_getfield(L, module_index, push_name);
    lua_pushcclosure(L,ls_crypto_secretstream_push_tagged,2);
    lua_setfield(L,-2,"push");

    lua_pushinteger(L,TAG_REKEY);
    lua_getfield(L, module_index, push_name);
    lua_pushlightuserdata(L, rekey_ptr);
    lua_pushcclosure(L,ls_crypto_secretstream_push_rekey,3);
    lua_setfield(L,-2,"rekey");

    lua_pushinteger(L,TAG_FINAL);
    lua_getfield(L, module_index, push_name);
    lua_pushcclosure(L,ls_crypto_secretstream_push_tagged,2);
    lua_setfield(L,-2,"final");

    lua_setfield(L,-2,"__index");

    lua_pop(L,1); /* pops the metatable, leaves module on top of stack */

    lua_newtable(L);
    metatable_index = lua_gettop(L);

    lua_pushinteger(L,STATEBYTES);
    lua_pushcclosure(L,ls_crypto_secretstream__gc,1);
    lua_setfield(L,metatable_index,"__gc");

    /* init_pull method */
    lua_pushstring(L,init_pull_name);
    lua_pushlightuserdata(L, init_pull_ptr);
    lua_pushinteger(L, STATEBYTES);
    lua_pushinteger(L, HEADERBYTES);
    lua_pushinteger(L, KEYBYTES);
    lua_pushvalue(L, metatable_index);
    lua_pushcclosure(L, ls_crypto_secretstream_init_pull, 6);
    lua_setfield(L, module_index, init_pull_name);

    lua_pushstring(L,pull_name);
    lua_pushlightuserdata(L, pull_ptr);
    lua_pushinteger(L, ABYTES);
    lua_pushvalue(L, metatable_index);
    lua_pushcclosure(L, ls_crypto_secretstream_pull, 4);
    lua_setfield(L, module_index, pull_name);

    lua_newtable(L);

    lua_getfield(L,module_index,pull_name);
    lua_setfield(L,-2,"pull");

    lua_getfield(L,module_index,rekey_name);
    lua_setfield(L,-2,"rekey");

    lua_setfield(L,-2,"__index");

    lua_pop(L,1);

}

#define LS_CRYPTO_SECRETSTREAM_PUSH_SETUP(x) \
  ls_crypto_secretstream_push_setup(L, \
    x ## _statebytes(), \
    x ## _HEADERBYTES, \
    x ## _KEYBYTES, \
    x ## _ABYTES, \
    x ## _TAG_MESSAGE, \
    x ## _TAG_PUSH, \
    x ## _TAG_REKEY, \
    x ## _TAG_FINAL, \
    #x "_init_push", \
    (ls_crypto_secretstream_init_push_ptr)x ## _init_push, \
    #x "_push", \
    (ls_crypto_secretstream_push_ptr)x ## _push, \
    #x "_init_pull", \
    (ls_crypto_secretstream_init_pull_ptr)x ## _init_pull, \
    #x "_pull", \
    (ls_crypto_secretstream_pull_ptr)x ## _pull, \
    #x "_rekey", \
    (ls_crypto_secretstream_rekey_ptr)x ## _rekey);

LS_PUBLIC
int luaopen_luasodium_crypto_secretstream_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */

    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_secretstream_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_SECRETSTREAM_KEYGEN(crypto_secretstream_xchacha20poly1305);

    LS_CRYPTO_SECRETSTREAM_PUSH_SETUP(crypto_secretstream_xchacha20poly1305);

    return 1;
}
