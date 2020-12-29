#include <lua.h>
#include <lauxlib.h>
#include "core.luah"

/* some duplication here but it's minor */

int
luaopen_luasodium_version_core(lua_State*L) {

    if(luaL_loadbuffer(L,version_lua,version_lua_length - 1, "version.lua")) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }

    return 1;
}


