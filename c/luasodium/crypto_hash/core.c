#include "core.h"

int luaopen_luasodium_crypto_hash_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_crypto_hash_core_setup(L);

    return 1;
}

