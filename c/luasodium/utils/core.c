#include "core.h"

int
luaopen_luasodium_utils_core(lua_State *L) {
    LUASODIUM_INIT(L)
    lua_newtable(L);

    ls_utils_core_setup(L);

    return 1;
}
