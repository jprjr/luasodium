#include "../luasodium.h"
#include "crypto_box.luah"


static const struct luaL_Reg luasodium_box[] = {
    { NULL, NULL },
};

static const luasodium_constant_t luasodium_constants[] = {
    { "PUBLICKEYBYTES", crypto_box_PUBLICKEYBYTES },
    { "SECRETKEYBYTES", crypto_box_SECRETKEYBYTES },
    { "MACBYTES",       crypto_box_MACBYTES       },
    { "NONCEBYTES",     crypto_box_NONCEBYTES     },
    { "SEEDBYTES",      crypto_box_SEEDBYTES      },
    { "BEFORENMBYTES",  crypto_box_BEFORENMBYTES  },
    { NULL, 0 },
};

static const ffi_pointer_t ffi_pointers[] = {
    NULL,
};

int luaopen_luasodium_crypto_box(lua_State *L) {
    unsigned int i = 0;
    const ffi_pointer_t *p = ffi_pointers;
    int top = lua_gettop(L);

    if(luaL_loadbuffer(L,crypto_box_lua,crypto_box_lua_length - 1,"crypto_box.lua") == 0) {
        i = luasodium_push_constants(L,luasodium_constants);
        assert(i == 6);
        while(*p != NULL) {
            lua_pushlightuserdata(L,*p);
            p++;
            i++;
        }
        assert(i == 6);
        if(lua_pcall(L,i,1,0) == 0) {
            return 1;
        }
    }

    lua_settop(L,top);
    lua_newtable(L);

    luaL_setfuncs(L,luasodium_box,0);
    luasodium_set_constants(L,luasodium_constants);

    return 1;
}
