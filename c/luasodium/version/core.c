#include "../luasodium-c.h"
#include "../internals/ls_lua_set_functions.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"


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

static const struct luaL_Reg ls_version_functions[] = {
    LS_LUA_FUNC(sodium_version_string),
    LS_LUA_FUNC(sodium_library_version_major),
    LS_LUA_FUNC(sodium_library_version_minor),
    LS_LUA_FUNC(sodium_library_minimal),
    { NULL, NULL },
};

LS_PUBLIC
int luaopen_luasodium_version_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L)
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_lua_set_constants(L,ls_version_constants,lua_gettop(L));
    ls_lua_set_functions(L,ls_version_functions,0);
    lua_pushliteral(L,LUASODIUM_VERSION);
    lua_setfield(L,-2,"_VERSION");

    return 1;
}
