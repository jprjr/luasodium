#include "../luasodium-c.h"
#include "constants.h"

typedef int (*ls_verify_func_ptr)(const unsigned char *x, const unsigned char *y);
typedef struct ls_crypto_verify_def_s {
    const char *name;
    ls_verify_func_ptr func;
    size_t len;
} ls_crypto_verify_def;

#define LS_CRYPTO_VERIFY(x) { "crypto_verify_" #x, crypto_verify_ ## x, x }

static int
ls_crypto_verify(lua_State *L) {
    const unsigned char *x = NULL;
    const unsigned char *y = NULL;
    size_t xlen = 0;
    size_t ylen = 0;

    ls_verify_func_ptr f = NULL;
    size_t len = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    f = lua_touserdata(L,lua_upvalueindex(1));
    len = lua_tointeger(L,lua_upvalueindex(2));

    x = (const unsigned char *)lua_tolstring(L,1,&xlen);
    y = (const unsigned char *)lua_tolstring(L,2,&ylen);

    if(xlen != len || ylen != len) {
        return luaL_error(L,"incorrect string size, expected: %d",
          len);
    }

    lua_pushboolean(L,f(x,y) == 0);
    return 1;
}

static const ls_crypto_verify_def ls_crypto_verify_defs[] = {
    LS_CRYPTO_VERIFY(16),
    LS_CRYPTO_VERIFY(32),
    { NULL }
};

static int
ls_crypto_verify_core_setup(lua_State *L) {
    const ls_crypto_verify_def *d = ls_crypto_verify_defs;
    luasodium_set_constants(L,ls_crypto_verify_constants,lua_gettop(L));

    for(; d->name != NULL; d++) {
        lua_pushlightuserdata(L,d->func);
        lua_pushinteger(L,d->len);
        lua_pushcclosure(L,ls_crypto_verify,2);
        lua_setfield(L,-2,d->name);
    }
    return 0;
}


int luaopen_luasodium_crypto_verify_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_crypto_verify_core_setup(L);

    return 1;
}

