#ifndef LS_LUA_SET_CONSTANTS_H
#define LS_LUA_SET_CONSTANTS_H

#include <lua.h>

#if LUA_VERSION_NUM != 502
static void ls_pushunsigned(lua_State *L, size_t value) {
    size_t max;
    switch(sizeof(lua_Integer)) {
        case 8: max = 9223372036854775807L; break;
        case 4: max = 2147483647; break;
        default: abort();
    }
    if(value > max) value = max;
    lua_pushinteger(L,(lua_Integer)value);
}
#else
#define ls_pushunsigned(L,n) lua_pushunsigned(L,n)
#endif

static void
ls_lua_set_constants(lua_State *L, const luasodium_constant_t *c,int index) {
    for(; c->name != NULL; c++) {
        ls_pushunsigned(L,c->value);
        lua_setfield(L,index,c->name);
    }
}

#endif
