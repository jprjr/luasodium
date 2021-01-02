#include "core.h"
int
luaopen_luasodium_randombytes_core(lua_State *L) {
    LUASODIUM_INIT(L)
    lua_newtable(L);

    ls_randombytes_core_setup(L);

    return 1;
}
