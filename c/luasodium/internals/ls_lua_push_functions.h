#ifndef LS_LUA_PUSH_FUNCTIONS_H
#define LS_LUA_PUSH_FUNCTIONS_H

static void
ls_lua_push_functions(lua_State *L, const luasodium_function_t *f) {
    lua_newtable(L);
    for(; f->name != NULL; f++) {
        lua_pushlightuserdata(L,f->func);
        lua_setfield(L,-2,f->name);
    }
}

#endif
