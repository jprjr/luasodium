#include "../luasodium-c.h"
#include "constants.h"

static int
luasodium_randombytes_random(lua_State *L) {
    lua_pushinteger(L,randombytes_random());
    return 1;
}

static int
luasodium_randombytes_uniform(lua_State *L) {
    if(!lua_isnumber(L,1)) {
        lua_pushliteral(L,"missing number argument");
        return lua_error(L);
    }

    lua_pushinteger(L,randombytes_uniform(lua_tointeger(L,1)));
    return 1;
}

static int
luasodium_randombytes_buf(lua_State *L) {
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
    return 1;
}

static int
luasodium_randombytes_seedbytes(lua_State *L) {
    lua_pushinteger(L,randombytes_seedbytes());
    return 1;
}

static int
luasodium_randombytes_buf_deterministic(lua_State *L) {
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
    return 1;
}

static int
luasodium_randombytes_close(lua_State *L) {
    lua_pushboolean(L,randombytes_close() == 0);
    return 1;
}

static int
luasodium_randombytes_stir(lua_State *L) {
    (void)L;
    randombytes_stir();
    return 0;
}

static const struct luaL_Reg luasodium_randombytes[] = {
    { "randombytes_random", luasodium_randombytes_random },
    { "randombytes_uniform", luasodium_randombytes_uniform },
    { "randombytes_buf", luasodium_randombytes_buf },
    { "randombytes_seedbytes", luasodium_randombytes_seedbytes },
    { "randombytes_buf_deterministic", luasodium_randombytes_buf_deterministic },
    { "randombytes_close", luasodium_randombytes_close },
    { "randombytes_stir", luasodium_randombytes_stir },
    { NULL, NULL },
};

int
luaopen_luasodium_randombytes_core(lua_State *L) {
    LUASODIUM_INIT(L)
    lua_newtable(L);
    luaL_setfuncs(L,luasodium_randombytes,0);
    luasodium_set_constants(L,luasodium_randombytes_constants);

    return 1;
}