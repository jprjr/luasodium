#include "core.h"

int luaopen_luasodium_crypto_auth_core(lua_State *L) {
    LUASODIUM_INIT(L);
    lua_newtable(L);

    ls_crypto_auth_core_setup(L);

    return 1;
}
