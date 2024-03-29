#ifndef LS_LUA_SET_CONSTANTS_H
#define LS_LUA_SET_CONSTANTS_H

#include <lua.h>

static void
ls_lua_set_constants(lua_State *L, const luasodium_constant_t *c,int index) {
    /* 0 */ int (*i)(void) = NULL;
    /* 1 */ size_t (*f)(void) = NULL;
    /* 2 */ const char* (*str)(void) = NULL;
    /* 3 */ unsigned char (*uchar)(void) = NULL;

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
			case 3: {
				uchar = (unsigned char (*)(void))c->func;
				lua_pushinteger(L,uchar());
				break;
			}
            default: abort();
        }
        lua_setfield(L,index,c->name);
    }
}

#endif
