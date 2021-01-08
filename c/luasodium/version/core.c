#include <lua.h>
#include <lauxlib.h>
#include <sodium.h>

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

    lua_getglobal(L,"require");
    lua_pushliteral(L,"luasodium.version.implementation");
    if(lua_pcall(L,1,1,0)) {
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

int luaopen_luasodium_version_core(lua_State *L) {
    lua_newtable(L);
    ls_version_core_setup(L);
    return 1;
}
