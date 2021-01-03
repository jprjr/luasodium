#include "core.h"

int luaopen_luasodium_crypto_onetimeauth_core(lua_State *L) {
    LUASODIUM_INIT(L);
    lua_newtable(L);

    ls_crypto_onetimeauth_core_setup(L);

    return 1;
}

