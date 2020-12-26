#include <sodium.h>
#include <lua.h>
#include <lauxlib.h>

#if !defined(luaL_newlibtable) \
  && (!defined LUA_VERSION_NUM || LUA_VERSION_NUM==501)
static void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup) {
  luaL_checkstack(L, nup+1, "too many upvalues");
  for (; l->name != NULL; l++) {  /* fill the table with given functions */
    int i;
    lua_pushstring(L, l->name);
    for (i = 0; i < nup; i++)  /* copy upvalues to the top */
      lua_pushvalue(L, -(nup+1));
    lua_pushcclosure(L, l->func, nup);  /* closure with those upvalues */
    lua_settable(L, -(nup + 3));
  }
  lua_pop(L, nup);  /* remove upvalues */
}
#endif

static int
luasodium_randombytes_random(lua_State *L) {
    lua_pushinteger(L,randombytes_random());
    return 1;
}

static int
luasodium_randombytes_uniform(lua_State *L) {
    lua_pushinteger(L,randombytes_uniform(lua_tointeger(L,1)));
    return 1;
}

static int
luasodium_randombytes_buf(lua_State *L) {
    char *buf = NULL;
    size_t s = lua_tointeger(L,1);
    buf = lua_newuserdata(L,s);
    if(buf == NULL) {
        lua_pushboolean(L,1);
        lua_pushstring(L,"out of memory");
        return 2;
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
    size_t s = lua_tointeger(L,1);
    seed = lua_tolstring(L,2,&seed_len);

    if(seed_len != randombytes_SEEDBYTES) {
        lua_pushnil(L),
        lua_pushstring(L,"wrong seed length");
        return 2;
    }

    buf = lua_newuserdata(L,s);
    if(buf == NULL) {
        lua_pushboolean(L,1);
        lua_pushstring(L,"out of memory");
        return 2;
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

int
luaopen_luasodium_randombytes_core(lua_State *L) {
    lua_newtable(L);
    luaL_setfuncs(L,luasodium_randombytes,0);

    lua_pushinteger(L,randombytes_seedbytes());
    lua_setfield(L,-2,"SEEDBYTES");

    return 1;
}
