#include <lua.h>
#include <lauxlib.h>
#include "ffi-implementation.h"

static void
ls_version_copydown_table(lua_State *L,int target, int source) {
    lua_pushnil(L);
    while(lua_next(L,source) != 0) {
        lua_setfield(L,target,lua_tostring(L,-2));
    }
}

static int
ls_version_core_setup(lua_State *L) {
    int target = lua_gettop(L);

    if(luaL_loadbuffer(L,ls_version_ffi_implementation,ls_version_ffi_implementation_length - 1, "version.lua")) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }

    ls_version_copydown_table(L,target,lua_gettop(L));
    lua_pop(L,1);

    return 0;
}


