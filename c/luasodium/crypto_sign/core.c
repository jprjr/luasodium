#include "core.h"

int luaopen_luasodium_crypto_sign_core(lua_State *L) {
    LUASODIUM_INIT(L);
    lua_newtable(L);

    ls_crypto_sign_core_setup(L);
    return 1;
}
