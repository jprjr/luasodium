#include "../luasodium-c.h"
#include "constants.h"

static int
ls_crypto_scalarmult_base(lua_State *L) {
    unsigned char q[crypto_scalarmult_BYTES];
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

    if(crypto_scalarmult_base(q,n) == -1) {
        return luaL_error(L,"crypto_scalarmult_base error");
    }

    lua_pushlstring(L,(const char *)q,crypto_scalarmult_BYTES);
    sodium_memzero(q,crypto_scalarmult_BYTES);
    return 1;
}

static int
ls_crypto_scalarmult(lua_State *L) {
    unsigned char q[crypto_scalarmult_BYTES];
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

    if(crypto_scalarmult(q,n,p) == -1) {
        return luaL_error(L,"crypto_scalarmult error");
    }

    lua_pushlstring(L,(const char *)q,crypto_scalarmult_BYTES);
    sodium_memzero(q,crypto_scalarmult_BYTES);
    return 1;
}

static const luaL_Reg ls_crypto_scalarmult_functions[] = {
    LS_LUA_FUNC(crypto_scalarmult_base),
    LS_LUA_FUNC(crypto_scalarmult),
    { NULL }
};

static int
ls_crypto_scalarmult_core_setup(lua_State *L) {
    luasodium_set_constants(L,ls_crypto_scalarmult_constants,lua_gettop(L));
    luaL_setfuncs(L,ls_crypto_scalarmult_functions,0);
    return 0;
}
