#ifndef LS_LUA_PUSH_CONSTANTS
#define LS_LUA_PUSH_CONSTANTS

static void
ls_lua_push_constants(lua_State *L, const luasodium_constant_t *c) {
    lua_newtable(L);
    for(; c->name != NULL; c++) {
        lua_newtable(L);
        lua_pushlightuserdata(L,c->func);
        lua_setfield(L,-2,"func");
        lua_pushinteger(L,c->type);
        lua_setfield(L,-2,"type");
        lua_setfield(L,-2,c->name);
    }
}

#endif
