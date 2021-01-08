#include "../luasodium-c.h"
#include "../internals/ls_lua_equal.h"
#include "constants.h"

static int
ls_crypto_hash(lua_State *L) {
    unsigned char h[crypto_hash_BYTES];
    const unsigned char *m = NULL;
    size_t mlen = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);

    /* LCOV_EXCL_START */
    if(crypto_hash(h,m,mlen) == -1) {
        return luaL_error(L,"crypto_hash error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)h,crypto_hash_BYTES);
    sodium_memzero(h,crypto_hash_BYTES);
    return 1;
}

static int
ls_crypto_hash_sha256(lua_State *L) {
    unsigned char h[crypto_hash_sha256_BYTES];
    const unsigned char *m = NULL;
    size_t mlen = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);

    /* LCOV_EXCL_START */
    if(crypto_hash_sha256(h,m,mlen) == -1) {
        return luaL_error(L,"crypto_hash error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)h,crypto_hash_sha256_BYTES);
    sodium_memzero(h,crypto_hash_sha256_BYTES);
    return 1;
}

static int
ls_crypto_hash_sha512(lua_State *L) {
    unsigned char h[crypto_hash_sha512_BYTES];
    const unsigned char *m = NULL;
    size_t mlen = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);

    /* LCOV_EXCL_START */
    if(crypto_hash_sha512(h,m,mlen) == -1) {
        return luaL_error(L,"crypto_hash error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)h,crypto_hash_sha512_BYTES);
    sodium_memzero(h,crypto_hash_sha512_BYTES);
    return 1;
}

static int
ls_crypto_hash_sha256_init(lua_State *L) {
    crypto_hash_sha256_state *state = NULL;
    state = (crypto_hash_sha256_state *)lua_newuserdata(L,
      crypto_hash_sha256_statebytes());

    /* LCOV_EXCL_START */
    if(state == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(crypto_hash_sha256_init(state) == -1) {
        lua_pop(L,1);
        return luaL_error(L,"crypto_hash_sha256_init error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushvalue(L,lua_upvalueindex(1));
    lua_setmetatable(L,-2);

    return 1;
}

static int
ls_crypto_hash_sha256_update(lua_State *L) {
    crypto_hash_sha256_state *state = NULL;
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

    state = (crypto_hash_sha256_state *)lua_touserdata(L,1);
    m   = (const unsigned char *)lua_tolstring(L,2,&mlen);

    lua_pushboolean(L,
    /* LCOV_EXCL_START */
      (crypto_hash_sha256_update(
      state,m,mlen) != -1)
    /* LCOV_EXCL_STOP */
    );
    return 1;
}

static int
ls_crypto_hash_sha256_final(lua_State *L) {
    crypto_hash_sha256_state *state = NULL;
    unsigned char h[crypto_hash_sha256_BYTES];

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

    state = (crypto_hash_sha256_state *)lua_touserdata(L,1);

    /* LCOV_EXCL_START */
    if(crypto_hash_sha256_final(state,h) == -1) {
        return luaL_error(L,"crypto_hash_sha256_final error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)h,crypto_hash_sha256_BYTES);
    sodium_memzero(h,crypto_hash_sha256_BYTES);

    return 1;
}

static int
ls_crypto_hash_sha512_init(lua_State *L) {
    crypto_hash_sha512_state *state = NULL;
    state = (crypto_hash_sha512_state *)lua_newuserdata(L,
      crypto_hash_sha512_statebytes());

    /* LCOV_EXCL_START */
    if(state == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(crypto_hash_sha512_init(state) == -1) {
        lua_pop(L,1);
        return luaL_error(L,"crypto_hash_sha512_init error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushvalue(L,lua_upvalueindex(1));
    lua_setmetatable(L,-2);

    return 1;
}

static int
ls_crypto_hash_sha512_update(lua_State *L) {
    crypto_hash_sha512_state *state = NULL;
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

    state = (crypto_hash_sha512_state *)lua_touserdata(L,1);
    m   = (const unsigned char *)lua_tolstring(L,2,&mlen);

    lua_pushboolean(L,
    /* LCOV_EXCL_START */
    (crypto_hash_sha512_update(
      state,m,mlen) != -1)
    /* LCOV_EXCL_STOP */
    );
    return 1;
}

static int
ls_crypto_hash_sha512_final(lua_State *L) {
    crypto_hash_sha512_state *state = NULL;
    unsigned char h[crypto_hash_sha512_BYTES];

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

    state = (crypto_hash_sha512_state *)lua_touserdata(L,1);

    /* LCOV_EXCL_START */
    if(crypto_hash_sha512_final(state,h) == -1) {
        return luaL_error(L,"crypto_hash_sha512_final error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)h,crypto_hash_sha512_BYTES);
    sodium_memzero(h,crypto_hash_sha512_BYTES);

    return 1;
}

static int
ls_crypto_hash_sha256_state__gc(lua_State *L) {
    crypto_hash_sha256_state *state = (crypto_hash_sha256_state *)lua_touserdata(L,1);
    sodium_memzero(state,crypto_hash_sha256_statebytes());
    return 0;
}

static int
ls_crypto_hash_sha512_state__gc(lua_State *L) {
    crypto_hash_sha512_state *state = (crypto_hash_sha512_state *)lua_touserdata(L,1);
    sodium_memzero(state,crypto_hash_sha512_statebytes());
    return 0;
}

static const struct luaL_Reg ls_crypto_hash_functions[] = {
    LS_LUA_FUNC(crypto_hash),
    LS_LUA_FUNC(crypto_hash_sha256),
    LS_LUA_FUNC(crypto_hash_sha512),
    LS_LUA_FUNC(crypto_hash_sha256_init),
    { NULL, NULL },
};


static const struct luaL_Reg ls_crypto_hash_sha256_state_functions[] = {
    LS_LUA_FUNC(crypto_hash_sha256_init),
    LS_LUA_FUNC(crypto_hash_sha256_update),
    LS_LUA_FUNC(crypto_hash_sha256_final),
    { NULL, NULL },
};

static const struct luaL_Reg ls_crypto_hash_sha512_state_functions[] = {
    LS_LUA_FUNC(crypto_hash_sha512_init),
    LS_LUA_FUNC(crypto_hash_sha512_update),
    LS_LUA_FUNC(crypto_hash_sha512_final),
    { NULL, NULL },
};

static int
ls_crypto_hash_sha256_state_setup(lua_State *L) {

    /* create our metatable for crypto_hash_sha256_state */
    lua_newtable(L);
    lua_pushcclosure(L,ls_crypto_hash_sha256_state__gc,0);
    lua_setfield(L,-2,"__gc");

    /* table of methods */
    lua_newtable(L);
    lua_setfield(L,-2,"__index");

    /* top of stack is our metatable */
    /* push up copies of our module + metatable since setfuncs will pop metatable */
    lua_pushvalue(L,-2); /* module */
    lua_pushvalue(L,-2); /* metatable */
    luaL_setfuncs(L,ls_crypto_hash_sha256_state_functions,1);
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

    lua_getfield(L,-3,"crypto_hash_sha256_update");
    /* module
     * metatable
     * __index
     * function
     */
    lua_setfield(L,-2,"update");

    lua_getfield(L,-3,"crypto_hash_sha256_final");
    lua_setfield(L,-2,"final");

    /* module
     * metatable
     * __index
     */

    lua_pop(L,2);
    return 0;
}

static int
ls_crypto_hash_sha512_state_setup(lua_State *L) {

    /* create our metatable for crypto_hash_sha512_state */
    lua_newtable(L);
    lua_pushcclosure(L,ls_crypto_hash_sha512_state__gc,0);
    lua_setfield(L,-2,"__gc");

    /* table of methods */
    lua_newtable(L);
    lua_setfield(L,-2,"__index");

    /* top of stack is our metatable */
    /* push up copies of our module + metatable since setfuncs will pop metatable */
    lua_pushvalue(L,-2); /* module */
    lua_pushvalue(L,-2); /* metatable */
    luaL_setfuncs(L,ls_crypto_hash_sha512_state_functions,1);
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

    lua_getfield(L,-3,"crypto_hash_sha512_update");
    /* module
     * metatable
     * __index
     * function
     */
    lua_setfield(L,-2,"update");

    lua_getfield(L,-3,"crypto_hash_sha512_final");
    lua_setfield(L,-2,"final");

    /* module
     * metatable
     * __index
     */

    lua_pop(L,2);
    return 0;
}

static int
ls_crypto_hash_core_setup(lua_State *L) {
    luasodium_set_constants(L,ls_crypto_hash_constants,lua_gettop(L));
    luaL_setfuncs(L,ls_crypto_hash_functions,0);
    ls_crypto_hash_sha256_state_setup(L);
    ls_crypto_hash_sha512_state_setup(L);
    return 0;
}


int luaopen_luasodium_crypto_hash_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_crypto_hash_core_setup(L);

    return 1;
}

