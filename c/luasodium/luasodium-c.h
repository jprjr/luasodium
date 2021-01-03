#ifndef LUASODIUM_C_H
#define LUASODIUM_C_H

#include "luasodium.h"

#define LS_LUA_FUNC(x) { #x, ls_ ## x }

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

#define LUASODIUM_INIT(L) \
if(sodium_init() == -1) { \
    lua_pushliteral(L,"sodium_init error"); \
    return lua_error(L); \
}

#if LUA_VERSION_NUM >= 502
static int
ls_lua_equal(lua_State *L, int index1, int index2) {
    return lua_compare(L,index1,index2,LUA_OPEQ);
}
#else
#define ls_lua_equal(L,index1,index2) lua_equal(L,index1,index2)
#endif


#endif
