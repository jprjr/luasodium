#include "core.h"

int luaopen_luasodium_version_core(lua_State *L) {
    lua_newtable(L);
    ls_version_core_setup(L);
    return 1;
}
