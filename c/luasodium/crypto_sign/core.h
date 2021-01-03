#include "../luasodium-c.h"
#include "constants.h"

static int
ls_crypto_sign_keypair(lua_State *L) {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];

    if(crypto_sign_keypair(pk,sk) == -1) {
        return luaL_error(L,"crypto_sign_keypair error");
    }

    lua_pushlstring(L,(const char *)pk,crypto_sign_PUBLICKEYBYTES);
    lua_pushlstring(L,(const char *)sk,crypto_sign_SECRETKEYBYTES);

    sodium_memzero(pk,crypto_sign_PUBLICKEYBYTES);
    sodium_memzero(sk,crypto_sign_SECRETKEYBYTES);

    return 2;
}

static int
ls_crypto_sign_seed_keypair(lua_State *L) {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    const unsigned char *seed = NULL;
    size_t seedlen = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    seed = (const unsigned char *)lua_tolstring(L,1,&seedlen);

    if(seedlen != crypto_sign_SEEDBYTES) {
        return luaL_error(L,"wrong seed size, expected: %d",
          crypto_sign_SEEDBYTES);
    }

    if(crypto_sign_seed_keypair(pk,sk,seed) == -1) {
        return luaL_error(L,"crypto_sign_keypair error");
    }

    lua_pushlstring(L,(const char *)pk,crypto_sign_PUBLICKEYBYTES);
    lua_pushlstring(L,(const char *)sk,crypto_sign_SECRETKEYBYTES);

    sodium_memzero(pk,crypto_sign_PUBLICKEYBYTES);
    sodium_memzero(sk,crypto_sign_SECRETKEYBYTES);

    return 2;
}

static int
ls_crypto_sign(lua_State *L) {
    unsigned char *sm = NULL;
    const unsigned char *m = NULL;
    const unsigned char *sk = NULL;
    unsigned long long smlen;
    size_t smlen_a = 0;
    size_t mlen = 0;
    size_t sklen = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    sk = (const unsigned char *)lua_tolstring(L,2,&sklen);

    if(sklen != crypto_sign_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",
          crypto_sign_SECRETKEYBYTES);
    }

    smlen_a = mlen + crypto_sign_BYTES;

    sm = lua_newuserdata(L,smlen_a);
    if(sm == NULL) {
        return luaL_error(L,"out of memory");
    }
    lua_pop(L,1);

    if(crypto_sign(sm,&smlen,m,mlen,sk) == -1) {
        return luaL_error(L,"crypto_sign error");
    }
    lua_pushlstring(L,(const char *)sm,smlen);
    sodium_memzero(sm,smlen_a);
    return 1;
}

static int
ls_crypto_sign_open(lua_State *L) {
    unsigned char *m = NULL;
    const unsigned char *sm = NULL;
    const unsigned char *pk = NULL;
    unsigned long long mlen;
    size_t smlen = 0;
    size_t pklen = 0;
    int r = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    sm = (const unsigned char *)lua_tolstring(L,1,&smlen);
    pk = (const unsigned char *)lua_tolstring(L,2,&pklen);

    if(pklen != crypto_sign_PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",
          crypto_sign_PUBLICKEYBYTES);
    }

    m = lua_newuserdata(L,smlen);
    if(sm == NULL) {
        return luaL_error(L,"out of memory");
    }
    lua_pop(L,1);

    if(crypto_sign_open(m,&mlen,sm,smlen,pk) == 0) {
        lua_pushlstring(L,(const char *)m,mlen);
        r = 1;
    }
    sodium_memzero(m,smlen);
    return r;
}

static int
ls_crypto_sign_detached(lua_State *L) {
    unsigned char sig[crypto_sign_BYTES];
    const unsigned char *m = NULL;
    const unsigned char *sk = NULL;
    unsigned long long siglen;
    size_t mlen = 0;
    size_t sklen = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    sk = (const unsigned char *)lua_tolstring(L,2,&sklen);

    if(sklen != crypto_sign_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",
          crypto_sign_SECRETKEYBYTES);
    }

    if(crypto_sign_detached(sig,&siglen,m,mlen,sk) == -1) {
        return luaL_error(L,"crypto_sign_detached error");
    }
    lua_pushlstring(L,(const char *)sig,siglen);
    sodium_memzero(sig,crypto_sign_BYTES);
    return 1;
}

static int
ls_crypto_sign_verify_detached(lua_State *L) {
    const unsigned char *sig = NULL;
    const unsigned char *m   = NULL;
    const unsigned char *pk  = NULL;
    size_t siglen = 0;
    size_t mlen = 0;
    size_t pklen = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    sig = (const unsigned char *)lua_tolstring(L,1,&siglen);
    m   = (const unsigned char *)lua_tolstring(L,2,&mlen);
    pk  = (const unsigned char *)lua_tolstring(L,3,&pklen);

    if(pklen != crypto_sign_PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",
          crypto_sign_PUBLICKEYBYTES);
    }

    lua_pushboolean(L,crypto_sign_verify_detached(
      sig,m,mlen,pk) == 0);
    return 1;
}

static int
ls_crypto_sign_init(lua_State *L) {
    crypto_sign_state *state = NULL;

    state = (crypto_sign_state *)lua_newuserdata(L,
      crypto_sign_statebytes());
    if(crypto_sign_init(state) == -1) {
        lua_pop(L,1);
        return luaL_error(L,"crypto_sign_init error");
    }

    lua_pushvalue(L,lua_upvalueindex(1));
    lua_setmetatable(L,-2);

    return 1;
}

static int
ls_crypto_sign_update(lua_State *L) {
    crypto_sign_state *state = NULL;
    const unsigned char *m   = NULL;
    size_t mlen = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(1));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    state = (crypto_sign_state *)lua_touserdata(L,1);
    m   = (const unsigned char *)lua_tolstring(L,2,&mlen);

    lua_pushboolean(L,crypto_sign_update(
      state,m,mlen) != -1);
    return 1;
}

static int
ls_crypto_sign_final_create(lua_State *L) {
    crypto_sign_state *state = NULL;
    unsigned char sig[crypto_sign_BYTES];
    const unsigned char *sk   = NULL;
    unsigned long long siglen = 0;
    size_t sklen = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(1));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    state = (crypto_sign_state *)lua_touserdata(L,1);
    sk  = (const unsigned char *)lua_tolstring(L,2,&sklen);

    if(sklen != crypto_sign_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",
          crypto_sign_SECRETKEYBYTES);
    }

    if(crypto_sign_final_create(state,sig,&siglen,sk) == -1) {
        return luaL_error(L,"crypto_sign_final_create error");
    }

    lua_pushlstring(L,(const char *)sig,siglen);
    sodium_memzero(sig,siglen);
    return 1;
}

static int
ls_crypto_sign_final_verify(lua_State *L) {
    crypto_sign_state *state  = NULL;
    const unsigned char *sig  = NULL;
    const unsigned char *pk   = NULL;
    size_t siglen = 0;
    size_t pklen = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(1));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    state = (crypto_sign_state *)lua_touserdata(L,1);
    sig = (const unsigned char *)lua_tolstring(L,2,&siglen);
    pk  = (const unsigned char *)lua_tolstring(L,3,&pklen);

    if(pklen != crypto_sign_PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",
          crypto_sign_PUBLICKEYBYTES);
    }

    lua_pushboolean(L,crypto_sign_final_verify(
      state,sig,pk) == 0);
    return 1;
}

static int
ls_crypto_sign_ed25519_sk_to_seed(lua_State *L) {
    unsigned char seed[crypto_sign_SEEDBYTES];
    const unsigned char *sk = NULL;
    size_t sklen = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    sk  = (const unsigned char *)lua_tolstring(L,1,&sklen);

    if(sklen != crypto_sign_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",
          crypto_sign_SECRETKEYBYTES);
    }

    if(crypto_sign_ed25519_sk_to_seed(seed,sk) == -1) {
        return luaL_error(L,"crypto_sign_ed25519_sk_to_seed error");
    }
    lua_pushlstring(L,(const char *)seed,crypto_sign_SEEDBYTES);
    sodium_memzero(seed,crypto_sign_SEEDBYTES);
    return 1;
}

static int
ls_crypto_sign_ed25519_sk_to_pk(lua_State *L) {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    const unsigned char *sk = NULL;
    size_t sklen = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    sk  = (const unsigned char *)lua_tolstring(L,1,&sklen);

    if(sklen != crypto_sign_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",
          crypto_sign_SECRETKEYBYTES);
    }

    if(crypto_sign_ed25519_sk_to_pk(pk,sk) == -1) {
        return luaL_error(L,"crypto_sign_ed25519_sk_to_pk error");
    }
    lua_pushlstring(L,(const char *)pk,crypto_sign_PUBLICKEYBYTES);
    sodium_memzero(pk,crypto_sign_PUBLICKEYBYTES);
    return 1;
}

static int
ls_crypto_sign_state__gc(lua_State *L) {
    crypto_sign_state *state = (crypto_sign_state *)lua_touserdata(L,1);
    sodium_memzero(state,crypto_sign_statebytes());
    return 0;
}

static const struct luaL_Reg ls_crypto_sign_functions[] = {
    LS_LUA_FUNC(crypto_sign_keypair),
    LS_LUA_FUNC(crypto_sign_seed_keypair),
    LS_LUA_FUNC(crypto_sign),
    LS_LUA_FUNC(crypto_sign_open),
    LS_LUA_FUNC(crypto_sign_detached),
    LS_LUA_FUNC(crypto_sign_verify_detached),
    LS_LUA_FUNC(crypto_sign_ed25519_sk_to_seed),
    LS_LUA_FUNC(crypto_sign_ed25519_sk_to_pk),
    { NULL, NULL },
};

static const struct luaL_Reg ls_crypto_sign_state_functions[] = {
    LS_LUA_FUNC(crypto_sign_init),
    LS_LUA_FUNC(crypto_sign_update),
    LS_LUA_FUNC(crypto_sign_final_create),
    LS_LUA_FUNC(crypto_sign_final_verify),
    { NULL, NULL },
};

static int
ls_crypto_sign_core_setup(lua_State *L) {
    luasodium_set_constants(L,ls_crypto_sign_constants,lua_gettop(L));
    luaL_setfuncs(L,ls_crypto_sign_functions,0);

    /* create our metatable for crypto_sign_state */
    lua_newtable(L);
    lua_pushcclosure(L,ls_crypto_sign_state__gc,0);
    lua_setfield(L,-2,"__gc");

    /* table of methods */
    lua_newtable(L);
    lua_setfield(L,-2,"__index");

    /* top of stack is our metatable */
    /* push up copies of our module + metatable since setfuncs will pop metatable */
    lua_pushvalue(L,-2); /* module */
    lua_pushvalue(L,-2); /* metatable */
    luaL_setfuncs(L,ls_crypto_sign_state_functions,1);
    lua_pop(L,1); /* module (copy) */

    /* stack is now:
     *   table (our modules)
     *   table (our metatable)
     */

    lua_getfield(L,-1,"__index");
    /* module
     * metatable
     * __index
     */

    lua_getfield(L,-3,"crypto_sign_update");
    /* module
     * metatable
     * __index
     * function
     */
    lua_setfield(L,-2,"update");

    lua_getfield(L,-3,"crypto_sign_final_create");
    lua_setfield(L,-2,"final_create");

    lua_getfield(L,-3,"crypto_sign_final_verify");
    lua_setfield(L,-2,"final_verify");

    /* module
     * metatable
     * __index
     */

    lua_pop(L,2);

    return 0;
}

