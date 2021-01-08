#ifndef LS_LUA_PUSH_CONSTANTS
#define LS_LUA_PUSH_CONSTANTS

#include "ls_lua_set_constants.h"

static void
ls_lua_push_constants(lua_State *L, const luasodium_constant_t *c) {
    lua_newtable(L);
    ls_lua_set_constants(L,c,lua_gettop(L));
}

#endif
