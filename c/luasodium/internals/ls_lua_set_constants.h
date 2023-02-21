#ifndef LS_LUA_SET_CONSTANTS_H
#define LS_LUA_SET_CONSTANTS_H

#include <lua.h>

static void
ls_lua_set_constants(lua_State *L, const luasodium_constant_t *c,int index) {
    size_t (*f)(void) = NULL;
    int (*i)(void) = NULL;
    const char* (*str)(void) = NULL;

    for(; c->name != NULL; c++) {
        switch(c->type) {
            case 0: {
                i = (int (*)(void)) c->func;
                lua_pushinteger(L,i());
                break;
            }
            case 1: {
                f = (size_t (*)(void))c->func;
                lua_pushinteger(L,f());
                break;
            }
            case 2: {
                str = (const char * (*)(void))c->func;
                lua_pushstring(L,str());
                break;
            }
            default: abort();
        }
        lua_setfield(L,index,c->name);
    }
}

#endif
