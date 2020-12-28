#include "../luasodium-c.h"
#include "constants.h"

static int
lua_crypto_scalarmult_base(lua_State *L) {
    unsigned char *q = NULL;
    const unsigned char *n = NULL;
    size_t n_len = 0;

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"requires 1 argument");
        return lua_error(L);
    }

    n = (const unsigned char *)lua_tolstring(L,1,&n_len);
    if(n_len != crypto_scalarmult_SCALARBYTES) {
        return luaL_error(L,"wrong scalar length, expected: %d",
          crypto_scalarmult_SCALARBYTES);
    }

    q = lua_newuserdata(L,crypto_scalarmult_BYTES);
    if(q == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(crypto_scalarmult_base(q,n) == -1) {
        lua_pushliteral(L,"crypto_scalarmult_base error");
        return lua_error(L);
    }

    lua_pushlstring(L,(const char *)q,crypto_scalarmult_BYTES);
    return 1;
}

static int
lua_crypto_scalarmult(lua_State *L) {
    unsigned char *q = NULL;
    const unsigned char *n = NULL;
    const unsigned char *p = NULL;
    size_t n_len = 0;
    size_t p_len = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    n = (const unsigned char *)lua_tolstring(L,1,&n_len);
    if(n_len != crypto_scalarmult_SCALARBYTES) {
        return luaL_error(L,"wrong scalar length, expected: %d",
          crypto_scalarmult_SCALARBYTES);
    }

    p = (const unsigned char *)lua_tolstring(L,1,&p_len);
    if(p_len != crypto_scalarmult_BYTES) {
        return luaL_error(L,"wrong scalar length, expected: %d",
          crypto_scalarmult_BYTES);
    }

    q = lua_newuserdata(L,crypto_scalarmult_BYTES);
    if(q == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(crypto_scalarmult(q,n,p) == -1) {
        lua_pushliteral(L,"crypto_scalarmult error");
        return lua_error(L);
    }

    lua_pushlstring(L,(const char *)q,crypto_scalarmult_BYTES);
    return 1;
}

static const struct luaL_Reg luasodium_crypto_scalarmult[] = {
    { "base", lua_crypto_scalarmult_base },
    { "scalarmult", lua_crypto_scalarmult }, /* TODO ?? */
    { NULL, NULL },
};

int luaopen_luasodium_crypto_scalarmult_core(lua_State *L) {
    lua_newtable(L);

    luaL_setfuncs(L,luasodium_crypto_scalarmult,0);
    luasodium_set_constants(L,luasodium_crypto_scalarmult_constants);

    return 1;
}
