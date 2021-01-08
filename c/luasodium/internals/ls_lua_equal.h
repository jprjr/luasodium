#ifndef LS_LUA_EQUAL_H
#define LS_LUA_EQUAL_H

#include <lua.h>

#if LUA_VERSION_NUM >= 502
static int
ls_lua_equal(lua_State *L, int index1, int index2) {
    return lua_compare(L,index1,index2,LUA_OPEQ);
}
#else
#define ls_lua_equal(L,index1,index2) lua_equal(L,index1,index2)
#endif

#endif
