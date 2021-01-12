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

#define LS_PUSH_CRYPTO_SECRETSTREAM_KEYGEN(x) \
  lua_pushlightuserdata(L, x ## _keygen); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_secretstream_keygen, 2); \
  lua_setfield(L,-2, #x "_keygen")

LS_PUBLIC
int luaopen_luasodium_crypto_secretstream_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */

    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_secretstream_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_SECRETSTREAM_KEYGEN(crypto_secretstream_xchacha20poly1305);

    return 1;
}
