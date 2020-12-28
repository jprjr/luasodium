#include "../luasodium-c.h"
#include "constants.h"

static int
lua_crypto_box_keypair(lua_State *L) {
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;

    pk = lua_newuserdata(L,crypto_box_PUBLICKEYBYTES);
    if(pk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    sk = lua_newuserdata(L,crypto_box_PUBLICKEYBYTES);
    if(sk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);
    if(crypto_box_keypair(pk,sk) == -1) {
        lua_pushliteral(L,"crypto_box_keypair error");
        return lua_error(L);
    }
    lua_pushlstring(L,(const char *)pk,crypto_box_PUBLICKEYBYTES);
    lua_pushlstring(L,(const char *)sk,crypto_box_SECRETKEYBYTES);
    return 2;
}


static const struct luaL_Reg luasodium_box[] = {
    { "keypair", lua_crypto_box_keypair },
    { NULL, NULL },
};

int luaopen_luasodium_crypto_box_core(lua_State *L) {
    lua_newtable(L);

    luaL_setfuncs(L,luasodium_box,0);
    luasodium_set_constants(L,luasodium_box_constants);

    return 1;
}
