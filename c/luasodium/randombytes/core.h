#include "../luasodium-c.h"
#include "constants.h"

static int
ls_randombytes_random(lua_State *L) {
    lua_pushinteger(L,randombytes_random());
    return 1;
}

static int
ls_randombytes_uniform(lua_State *L) {
    if(!lua_isnumber(L,1)) {
        lua_pushliteral(L,"missing number argument");
        return lua_error(L);
    }

    lua_pushinteger(L,randombytes_uniform(lua_tointeger(L,1)));
    return 1;
}

static int
ls_randombytes_buf(lua_State *L) {
    char *buf = NULL;
    size_t s = 0;

    if(!lua_isnumber(L,1)) {
        lua_pushliteral(L,"missing number argument");
        return lua_error(L);
    }

    s = lua_tointeger(L,1);
    buf = lua_newuserdata(L,s);
    if(buf == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    randombytes_buf(buf,s);
    lua_pushlstring(L,buf,s);
    sodium_memzero(buf,s);
    return 1;
}

static int
ls_randombytes_buf_deterministic(lua_State *L) {
    const char *seed = NULL;
    size_t seed_len;
    char *buf = NULL;
    size_t s = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    s = lua_tointeger(L,1);
    seed = lua_tolstring(L,2,&seed_len);

    if(seed_len != randombytes_SEEDBYTES) {
        lua_pushliteral(L,"wrong seed length");
        return lua_error(L);
    }

    buf = lua_newuserdata(L,s);
    if(buf == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    randombytes_buf_deterministic(buf,s,(const unsigned char *)seed);

    lua_pushlstring(L,buf,s);
    sodium_memzero(buf,s);

    return 1;
}

/* LCOV_EXCL_START */
static int
ls_randombytes_close(lua_State *L) {
    lua_pushboolean(L,randombytes_close() == 0);
    return 1;
}
/* LCOV_EXCL_STOP */

static int
ls_randombytes_stir(lua_State *L) {
    (void)L;
    randombytes_stir();
    return 0;
}

static const struct luaL_Reg ls_randombytes_functions[] = {
    LS_LUA_FUNC(randombytes_random),
    LS_LUA_FUNC(randombytes_uniform),
    LS_LUA_FUNC(randombytes_buf),
    LS_LUA_FUNC(randombytes_buf_deterministic),
    LS_LUA_FUNC(randombytes_close),
    LS_LUA_FUNC(randombytes_stir),
    { NULL, NULL },
};

static int
ls_randombytes_core_setup(lua_State *L) {
    luasodium_set_constants(L,ls_randombytes_constants,lua_gettop(L));
    luaL_setfuncs(L,ls_randombytes_functions,0);
    return 0;
}

