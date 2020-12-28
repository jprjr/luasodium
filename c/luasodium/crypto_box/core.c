#include "../luasodium-c.h"
#include "constants.h"


static const struct luaL_Reg luasodium_box[] = {
    { NULL, NULL },
};

int luaopen_luasodium_crypto_box_core(lua_State *L) {
    lua_newtable(L);

    luaL_setfuncs(L,luasodium_box,0);
    luasodium_set_constants(L,luasodium_box_constants);

    return 1;
}
