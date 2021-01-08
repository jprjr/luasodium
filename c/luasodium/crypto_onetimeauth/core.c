#include "../luasodium-c.h"
#include "../internals/ls_lua_equal.h"
#include "../internals/ls_lua_setfuncs.h"
#include "constants.h"

static int
ls_crypto_onetimeauth(lua_State *L) {
    unsigned char c[crypto_onetimeauth_BYTES];
    const unsigned char *m = NULL;
    const unsigned char *k = NULL;
    size_t mlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 arguments");
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    k = (const unsigned char *)lua_tolstring(L,2,&klen);

    if(klen != crypto_onetimeauth_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",
          crypto_onetimeauth_KEYBYTES);
    }

    /* LCOV_EXCL_START */
    if(crypto_onetimeauth(c,m,mlen,k) == -1) {
        return luaL_error(L,"crypto_onetimeauth error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)c,crypto_onetimeauth_BYTES);
    sodium_memzero(c,crypto_onetimeauth_BYTES);
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

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 arguments");
    }

    c = (const unsigned char *)lua_tolstring(L,1,&clen);
    m = (const unsigned char *)lua_tolstring(L,2,&mlen);
    k = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(clen != crypto_onetimeauth_BYTES) {
        return luaL_error(L,"wrong authenticator size, expected: %d",
          crypto_onetimeauth_BYTES);
    }

    if(klen != crypto_onetimeauth_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",
          crypto_onetimeauth_KEYBYTES);
    }

    lua_pushboolean(L,crypto_onetimeauth_verify(c,m,mlen,k) == 0);
    return 1;
}

static int
ls_crypto_onetimeauth_keygen(lua_State *L) {
    unsigned char k[crypto_onetimeauth_KEYBYTES];

    crypto_onetimeauth_keygen(k);

    lua_pushlstring(L,(const char *)k,crypto_onetimeauth_KEYBYTES);
    sodium_memzero(k,crypto_onetimeauth_KEYBYTES);
    return 1;
}

static int
ls_crypto_onetimeauth_init(lua_State *L) {
    crypto_onetimeauth_state *state = NULL;
    const unsigned char *k = NULL;
    size_t klen = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    k = (const unsigned char *)lua_tolstring(L,1,&klen);

    if(klen != crypto_onetimeauth_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",
          crypto_onetimeauth_KEYBYTES);
    }

    state = (crypto_onetimeauth_state *)lua_newuserdata(L,
      crypto_onetimeauth_statebytes());

    /* LCOV_EXCL_START */
    if(state == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(crypto_onetimeauth_init(state,k) == -1) {
        lua_pop(L,1);
        return luaL_error(L,"crypto_onetimeauth_init error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushvalue(L,lua_upvalueindex(1));
    lua_setmetatable(L,-2);

    return 1;
}

static int
ls_crypto_onetimeauth_update(lua_State *L) {
    crypto_onetimeauth_state *state = NULL;
    const unsigned char *m   = NULL;
    size_t mlen = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(1));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    state = (crypto_onetimeauth_state *)lua_touserdata(L,1);
    m   = (const unsigned char *)lua_tolstring(L,2,&mlen);

    lua_pushboolean(L,crypto_onetimeauth_update(
      state,m,mlen) != -1);
    return 1;
}

static int
ls_crypto_onetimeauth_final(lua_State *L) {
    crypto_onetimeauth_state *state = NULL;
    unsigned char h[crypto_onetimeauth_BYTES];

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameters");
    }

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(1));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    state = (crypto_onetimeauth_state *)lua_touserdata(L,1);

    /* LCOV_EXCL_START */
    if(crypto_onetimeauth_final(state,h) == -1) {
        return luaL_error(L,"crypto_onetimeauth_final error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)h,crypto_onetimeauth_BYTES);
    sodium_memzero(h,crypto_onetimeauth_BYTES);

    return 1;
}

static int
ls_crypto_onetimeauth_state__gc(lua_State *L) {
    crypto_onetimeauth_state *state = (crypto_onetimeauth_state *)lua_touserdata(L,1);
    sodium_memzero(state,crypto_onetimeauth_statebytes());
    return 0;
}

static const struct luaL_Reg ls_crypto_onetimeauth_functions[] = {
    LS_LUA_FUNC(crypto_onetimeauth),
    LS_LUA_FUNC(crypto_onetimeauth_verify),
    LS_LUA_FUNC(crypto_onetimeauth_keygen),
    { NULL, NULL },
};

static const struct luaL_Reg ls_crypto_onetimeauth_state_functions[] = {
    LS_LUA_FUNC(crypto_onetimeauth_init),
    LS_LUA_FUNC(crypto_onetimeauth_update),
    LS_LUA_FUNC(crypto_onetimeauth_final),
    { NULL, NULL },
};

static int
ls_crypto_onetimeauth_state_setup(lua_State *L) {
    /* create our metatable for crypto_onetimeauth_state */
    lua_newtable(L);
    lua_pushcclosure(L,ls_crypto_onetimeauth_state__gc,0);
    lua_setfield(L,-2,"__gc");

    /* table of methods */
    lua_newtable(L);
    lua_setfield(L,-2,"__index");

    /* top of stack is our metatable */
    /* push up copies of our module + metatable since setfuncs will pop metatable */
    lua_pushvalue(L,-2); /* module */
    lua_pushvalue(L,-2); /* metatable */
    ls_lua_setfuncs(L,ls_crypto_onetimeauth_state_functions,1);
    lua_pop(L,1); /* module (copy) */

    /* stack is now:
     *   table (our modules)
     *   table (our metatable)
     */

    lua_getfield(L,-1,"__index");
    /* module
     * metatable
     * __index
     */

    lua_getfield(L,-3,"crypto_onetimeauth_update");
    /* module
     * metatable
     * __index
     * function
     */
    lua_setfield(L,-2,"update");

    lua_getfield(L,-3,"crypto_onetimeauth_final");
    lua_setfield(L,-2,"final");

    /* module
     * metatable
     * __index
     */

    lua_pop(L,2);
    return 0;
}

LS_PUBLIC
int luaopen_luasodium_crypto_onetimeauth_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    luasodium_set_constants(L,ls_crypto_onetimeauth_constants,lua_gettop(L));
    ls_lua_setfuncs(L,ls_crypto_onetimeauth_functions,0);
    ls_crypto_onetimeauth_state_setup(L);

    return 1;
}

