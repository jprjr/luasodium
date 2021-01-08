#ifndef LS_LUA_SET_CONSTANTS_H
#define LS_LUA_SET_CONSTANTS_H

static void
ls_lua_set_constants(lua_State *L, const luasodium_constant_t *c,int index) {
    for(; c->name != NULL; c++) {
        lua_pushinteger(L,c->value);
        lua_setfield(L,index,c->name);
    }
}

#endif
