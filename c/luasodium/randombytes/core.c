#include "../luasodium-c.h"
#include "constants.h"
#include "functions.h"

static int
lua_randombytes_random(lua_State *L) {
    const ls_randombytes_random_func_def *def = NULL;
    def = (const ls_randombytes_random_func_def *) lua_touserdata(L,lua_upvalueindex(1));
    lua_pushinteger(L,def->func());
    return 1;
}

static int
lua_randombytes_uniform(lua_State *L) {
    const ls_randombytes_uniform_func_def *def = NULL;
    def = (const ls_randombytes_uniform_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(!lua_isnumber(L,1)) {
        lua_pushliteral(L,"missing number argument");
        return lua_error(L);
    }

    lua_pushinteger(L,def->func(lua_tointeger(L,1)));
    return 1;
}

static int
lua_randombytes_buf(lua_State *L) {
    char *buf = NULL;
    size_t s = 0;

    const ls_randombytes_buf_func_def *def = NULL;
    def = (const ls_randombytes_buf_func_def *) lua_touserdata(L,lua_upvalueindex(1));

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
    def->func(buf,s);
    lua_pushlstring(L,buf,s);
    sodium_memzero(buf,s);
    return 1;
}

static int
lua_randombytes_buf_deterministic(lua_State *L) {
    const char *seed = NULL;
    size_t seed_len;
    char *buf = NULL;
    size_t s = 0;

    const ls_randombytes_buf_deterministic_func_def *def = NULL;
    def = (const ls_randombytes_buf_deterministic_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    s = lua_tointeger(L,1);
    seed = lua_tolstring(L,2,&seed_len);

    if(seed_len != def->seedbytes) {
        lua_pushliteral(L,"wrong seed length");
        return lua_error(L);
    }

    buf = lua_newuserdata(L,s);
    if(buf == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);
    def->func(buf,s,(const unsigned char *)seed);
    lua_pushlstring(L,buf,s);

    sodium_memzero(buf,s);

    return 1;
}

static int
lua_randombytes_close(lua_State *L) {
    const ls_randombytes_close_func_def *def = NULL;
    def = (const ls_randombytes_close_func_def *) lua_touserdata(L,lua_upvalueindex(1));
    lua_pushboolean(L,def->func() == 0);
    return 1;
}

static int
lua_randombytes_stir(lua_State *L) {
    const ls_randombytes_stir_func_def *def = NULL;
    def = (const ls_randombytes_stir_func_def *) lua_touserdata(L,lua_upvalueindex(1));
    def->func();
    return 0;
}

static const ls_randombytes_random_func_def * const ls_randombytes_random_funcs[] = {
    &ls_randombytes_random_func,
    NULL,
};

static const ls_randombytes_uniform_func_def * const ls_randombytes_uniform_funcs[] = {
    &ls_randombytes_uniform_func,
    NULL,
};

static const ls_randombytes_buf_func_def * const ls_randombytes_buf_funcs[] = {
    &ls_randombytes_buf_func,
    NULL,
};

static const ls_randombytes_buf_deterministic_func_def * const ls_randombytes_buf_deterministic_funcs[] = {
    &ls_randombytes_buf_deterministic_func,
    NULL,
};

static const ls_randombytes_close_func_def * const ls_randombytes_close_funcs[] = {
    &ls_randombytes_close_func,
    NULL,
};

static const ls_randombytes_stir_func_def * const ls_randombytes_stir_funcs[] = {
    &ls_randombytes_stir_func,
    NULL,
};

static void
ls_push_randombytes_random_closures(lua_State *L) {
    const ls_randombytes_random_func_def * const *f = ls_randombytes_random_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_randombytes_random,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_randombytes_uniform_closures(lua_State *L) {
    const ls_randombytes_uniform_func_def * const *f = ls_randombytes_uniform_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_randombytes_uniform,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_randombytes_buf_closures(lua_State *L) {
    const ls_randombytes_buf_func_def * const *f = ls_randombytes_buf_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_randombytes_buf,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_randombytes_buf_deterministic_closures(lua_State *L) {
    const ls_randombytes_buf_deterministic_func_def * const *f = ls_randombytes_buf_deterministic_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_randombytes_buf_deterministic,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_randombytes_close_closures(lua_State *L) {
    const ls_randombytes_close_func_def * const *f = ls_randombytes_close_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_randombytes_close,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_randombytes_stir_closures(lua_State *L) {
    const ls_randombytes_stir_func_def * const *f = ls_randombytes_stir_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_randombytes_stir,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

int
luaopen_luasodium_randombytes_core(lua_State *L) {
    LUASODIUM_INIT(L)
    lua_newtable(L);
    luasodium_set_constants(L,ls_randombytes_constants);

    ls_push_randombytes_random_closures(L);
    ls_push_randombytes_uniform_closures(L);
    ls_push_randombytes_buf_closures(L);
    ls_push_randombytes_buf_deterministic_closures(L);
    ls_push_randombytes_close_closures(L);
    ls_push_randombytes_stir_closures(L);

    return 1;
}
