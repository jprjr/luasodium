#include <lua.h>
#include <lauxlib.h>
#include <sodium.h>
#include "ffi-implementation.h"

static int
ls_sodium_version_string(lua_State *L) {
    lua_pushstring(L,sodium_version_string());
    return 1;
}

static int
ls_sodium_library_version_major(lua_State *L) {
    lua_pushinteger(L,sodium_library_version_major());
    return 1;
}

static int
ls_sodium_library_version_minor(lua_State *L) {
    lua_pushinteger(L,sodium_library_version_minor());
    return 1;
}

static int
ls_sodium_library_minimal(lua_State *L) {
    lua_pushinteger(L,sodium_library_minimal());
    return 1;
}

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

    lua_pushcclosure(L,ls_sodium_version_string,0);
    lua_setfield(L,-2,"sodium_version_string");

    lua_pushcclosure(L,ls_sodium_library_version_major,0);
    lua_setfield(L,-2,"sodium_library_version_major");

    lua_pushcclosure(L,ls_sodium_library_version_minor,0);
    lua_setfield(L,-2,"sodium_library_version_minor");

    lua_pushcclosure(L,ls_sodium_library_minimal,0);
    lua_setfield(L,-2,"sodium_library_minimal");

    return 0;
}


