#include "../luasodium-c.h"
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
  unsigned long long);

typedef void (*ls_crypto_secretstream_rekey_ptr)(void);

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
  const char *init_name,
  ls_crypto_secretstream_init_push_ptr init_ptr) {

    int module_index = 0;
    int metatable_index = 0;

    module_index = lua_gettop(L);

    lua_newtable(L);
    metatable_index = lua_gettop(L);

    /* init method */
    lua_pushstring(L,init_name);
    lua_pushlightuserdata(L, init_ptr);
    lua_pushinteger(L, STATEBYTES);
    lua_pushinteger(L, HEADERBYTES);
    lua_pushinteger(L, KEYBYTES);
    lua_pushvalue(L, metatable_index);
    lua_pushcclosure(L, ls_crypto_secretstream_init_push, 6);
    lua_setfield(L, module_index, init_name);

    lua_pop(L,1);
}

#define LS_CRYPTO_SECRETSTREAM_PUSH_SETUP(x) \
  ls_crypto_secretstream_push_setup(L, \
    x ## _statebytes(), \
    x ## _HEADERBYTES, \
    x ## _KEYBYTES, \
    #x "_init_push", \
    (ls_crypto_secretstream_init_push_ptr)x ## _init_push);

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
