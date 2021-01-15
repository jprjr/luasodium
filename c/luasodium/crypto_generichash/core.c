#include "../luasodium-c.h"
#include "../internals/ls_lua_equal.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef void (*ls_crypto_generichash_keygen_ptr)(
  unsigned char *);

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

#define LS_PUSH_CRYPTO_GENERICHASH_KEYGEN(x) \
  lua_pushlightuserdata(L, x ## _keygen); \
  lua_pushinteger(L, x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_generichash_keygen, 2); \
  lua_setfield(L,-2, #x "_keygen")

LS_PUBLIC
int luaopen_luasodium_crypto_generichash_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */

    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_generichash_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_GENERICHASH_KEYGEN(crypto_generichash);

    return 1;
}
