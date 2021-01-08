#include "../luasodium-c.h"
#include "../internals/ls_lua_setfuncs.h"
#include "constants.h"

static int
ls_crypto_auth(lua_State *L) {
    unsigned char out[crypto_auth_BYTES];
    const unsigned char *in = NULL;
    const unsigned char *k = NULL;

    size_t inlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 parameters");
        return lua_error(L);
    }

    in = (const unsigned char *)lua_tolstring(L,1,&inlen);
    k =  (const unsigned char *)lua_tolstring(L,2,&klen);

    if(klen != crypto_auth_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d", crypto_auth_KEYBYTES);
    }

    /* LCOV_EXCL_START */
    if(crypto_auth(out,in,inlen,k) == -1) {
        return luaL_error(L,"crypto_auth error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)out,crypto_auth_BYTES);
    sodium_memzero(out,crypto_auth_BYTES);
    return 1;
}

static int
ls_crypto_auth_verify(lua_State *L) {
    const unsigned char *h = NULL;
    const unsigned char *in = NULL;
    const unsigned char *k = NULL;

    size_t hlen = 0;
    size_t inlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    h =  (const unsigned char *)lua_tolstring(L,1,&hlen);
    in = (const unsigned char *)lua_tolstring(L,2,&inlen);
    k =  (const unsigned char *)lua_tolstring(L,3,&klen);

    if(hlen != crypto_auth_BYTES) {
        return luaL_error(L,"wrong tag size, expected: %d", crypto_auth_BYTES);
    }

    if(klen != crypto_auth_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d", crypto_auth_KEYBYTES);
    }

    lua_pushboolean(L,crypto_auth_verify(h,in,inlen,k) == 0);
    return 1;
}

static int
ls_crypto_auth_keygen(lua_State *L) {
    unsigned char k[crypto_auth_KEYBYTES];
    crypto_auth_keygen(k);
    lua_pushlstring(L,(const char *)k,crypto_auth_KEYBYTES);
    sodium_memzero(k,crypto_auth_KEYBYTES);
    return 1;
}

static const struct luaL_Reg ls_crypto_auth_functions[] = {
    LS_LUA_FUNC(crypto_auth),
    LS_LUA_FUNC(crypto_auth_verify),
    LS_LUA_FUNC(crypto_auth_keygen),
    { NULL, NULL },
};

LS_PUBLIC
int luaopen_luasodium_crypto_auth_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    luasodium_set_constants(L,ls_crypto_auth_constants,lua_gettop(L));
    ls_lua_setfuncs(L,ls_crypto_auth_functions,0);

    return 1;
}
