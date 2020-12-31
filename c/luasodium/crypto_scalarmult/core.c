#include "../luasodium-c.h"
#include "constants.h"
#include "functions.h"

static int
lua_crypto_scalarmult_base(lua_State *L) {
    unsigned char *q = NULL;
    const unsigned char *n = NULL;
    size_t n_len = 0;

    const ls_crypto_scalarmult_base_func_def *def = NULL;
    def = (const ls_crypto_scalarmult_base_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"requires 1 argument");
        return lua_error(L);
    }

    n = (const unsigned char *)lua_tolstring(L,1,&n_len);
    if(n_len != def->scalarbytes) {
        return luaL_error(L,"wrong scalar length, expected: %d",
          def->scalarbytes);
    }

    q = lua_newuserdata(L,def->bytes);
    if(q == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(def->func(q,n) == -1) {
        return luaL_error(L,"%s error",def->name);
    }

    lua_pushlstring(L,(const char *)q,def->bytes);
    sodium_memzero(q,def->bytes);
    return 1;
}

static int
lua_crypto_scalarmult(lua_State *L) {
    unsigned char *q = NULL;
    const unsigned char *n = NULL;
    const unsigned char *p = NULL;
    size_t n_len = 0;
    size_t p_len = 0;

    const ls_crypto_scalarmult_func_def *def = NULL;
    def = (const ls_crypto_scalarmult_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    n = (const unsigned char *)lua_tolstring(L,1,&n_len);
    if(n_len != def->scalarbytes) {
        return luaL_error(L,"wrong scalar length, expected: %d",
          def->scalarbytes);
    }

    p = (const unsigned char *)lua_tolstring(L,1,&p_len);
    if(p_len != def->bytes) {
        return luaL_error(L,"wrong scalar length, expected: %d",
          def->bytes);
    }

    q = lua_newuserdata(L,def->bytes);
    if(q == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(def->func(q,n,p) == -1) {
        return luaL_error(L,"%s error",def->name);
    }

    lua_pushlstring(L,(const char *)q,def->bytes);
    sodium_memzero(q,def->bytes);
    return 1;
}

int luaopen_luasodium_crypto_scalarmult_core(lua_State *L) {
    LUASODIUM_INIT(L)
    lua_newtable(L);

    luasodium_set_constants(L,ls_crypto_scalarmult_constants);

    lua_pushlightuserdata(L,(void *)&ls_crypto_scalarmult_base_func);
    lua_pushcclosure(L,lua_crypto_scalarmult_base,1);
    lua_setfield(L,-2,"crypto_scalarmult_base");

    lua_pushlightuserdata(L,(void *)&ls_crypto_scalarmult_func);
    lua_pushcclosure(L,lua_crypto_scalarmult,1);
    lua_setfield(L,-2,"crypto_scalarmult");

    return 1;
}
