#include "luasodium.h"

/* basically a copy of luasodium.lua (the FFI/Core/PureFFI loader,
 * since luarocks can only support a single "luasodium" module. We'll
 * integrate it into the C library */

LS_PUBLIC
int luaopen_luasodium(lua_State *L) {
    int r = 0;

    lua_getglobal(L,"require");

    r = lua_gettop(L);

    lua_pushvalue(L,r);
    lua_pushliteral(L,"luasodium.ffi");

    if(lua_pcall(L,1,1,0) == 0) {
        return 1;
    }

    lua_settop(L,r);
    lua_pushvalue(L,r);
    lua_pushliteral(L,"luasodium.core");
    if(lua_pcall(L,1,1,0) == 0) {
        return 1;
    }

    lua_settop(L,r);
    lua_pushvalue(L,r);
    lua_pushliteral(L,"luasodium.pureffi");
    if(lua_pcall(L,1,1,0)) {
        return lua_error(L);
    }

    return 1;
}
