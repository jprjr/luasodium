#include "../luasodium.h"
#include "randombytes.luah"

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
    { "random", luasodium_randombytes_random },
    { "uniform", luasodium_randombytes_uniform },
    { "buf", luasodium_randombytes_buf },
    { "seedbytes", luasodium_randombytes_seedbytes },
    { "buf_deterministic", luasodium_randombytes_buf_deterministic },
    { "close", luasodium_randombytes_close },
    { "stir", luasodium_randombytes_stir },
    { NULL, NULL },
};

static const ffi_pointer_t ffi_pointers[] = {
    randombytes_random,
    randombytes_uniform,
    randombytes_buf,
    randombytes_seedbytes,
    randombytes_close,
    randombytes_stir,
    randombytes_buf_deterministic,
    NULL
};

static const luasodium_constant_t luasodium_constants[] = {
    { "SEEDBYTES",  randombytes_SEEDBYTES },
    { NULL, 0 },
};

int
luaopen_luasodium_randombytes(lua_State *L) {
    unsigned int i = 0;
    const ffi_pointer_t *p = ffi_pointers;
    int top = lua_gettop(L);

    if(luaL_loadbuffer(L,randombytes_lua,randombytes_lua_length - 1,"randombytes.lua") == 0) {
        i = luasodium_push_constants(L,luasodium_constants);
        assert(i == 1);

        while(*p != NULL) {
            lua_pushlightuserdata(L,*p);
            p++;
            i++;
        }
        assert(i == 8);
        if(lua_pcall(L,i,1,0) == 0) {
            return 1;
        }
    }

    lua_settop(L,top);
    lua_newtable(L);
    luaL_setfuncs(L,luasodium_randombytes,0);
    luasodium_set_constants(L,luasodium_constants);

    return 1;
}
