#include "../luasodium-c.h"
#include "constants.h"

static int
ls_crypto_box_keypair(lua_State *L) {
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;

    pk = lua_newuserdata(L,crypto_box_PUBLICKEYBYTES);
    if(pk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }

    sk = lua_newuserdata(L,crypto_box_SECRETKEYBYTES);
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

    sodium_memzero(pk,crypto_box_PUBLICKEYBYTES);
    sodium_memzero(sk,crypto_box_SECRETKEYBYTES);

    return 2;
}

static int
ls_crypto_box_seed_keypair(lua_State *L) {
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;
    const unsigned char *seed = NULL;
    size_t seed_len = 0;

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"requires 1 argument");
        return lua_error(L);
    }

    seed = (const unsigned char *)lua_tolstring(L,1,&seed_len);

    if(seed_len != crypto_box_SEEDBYTES) {
        return luaL_error(L,"wrong seed length, expected: %d",
          crypto_box_SEEDBYTES);
    }

    pk = lua_newuserdata(L,crypto_box_PUBLICKEYBYTES);
    if(pk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    sk = lua_newuserdata(L,crypto_box_SECRETKEYBYTES);
    if(sk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(crypto_box_seed_keypair(pk,sk,seed) == -1) {
        return luaL_error(L,"crypto_box_seed_keypair error");
    }
    lua_pushlstring(L,(const char *)pk,crypto_box_PUBLICKEYBYTES);
    lua_pushlstring(L,(const char *)sk,crypto_box_SECRETKEYBYTES);

    sodium_memzero(pk,crypto_box_PUBLICKEYBYTES);
    sodium_memzero(sk,crypto_box_SECRETKEYBYTES);

    return 2;
}

static int
ls_crypto_box_easy(lua_State *L) {
    unsigned char *c = NULL;
    const unsigned char *m = NULL;
    const unsigned char *n = NULL;
    const unsigned char *pk = NULL;
    const unsigned char *sk = NULL;
    size_t clen = 0;
    size_t mlen = 0;
    size_t nlen = 0;
    size_t pklen = 0;
    size_t sklen = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(nlen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          crypto_box_NONCEBYTES);
    }

    if(pklen != crypto_box_PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key length, expected: %d",
          crypto_box_PUBLICKEYBYTES);
    }

    if(sklen != crypto_box_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          crypto_box_SECRETKEYBYTES);
    }

    clen = mlen + crypto_box_MACBYTES;

    c = lua_newuserdata(L,clen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(crypto_box_easy(c,m,mlen,n,pk,sk) == -1) {
        return luaL_error(L,"crypto_box_easy error");
    }

    lua_pushlstring(L,(const char *)c,clen);
    sodium_memzero(c,clen);
    return 1;
}

static int
ls_crypto_box_open_easy(lua_State *L) {
    unsigned char *m = NULL;
    const unsigned char *c = NULL;
    const unsigned char *n = NULL;
    const unsigned char *pk = NULL;
    const unsigned char *sk = NULL;
    size_t mlen = 0;
    size_t clen = 0;
    size_t nlen = 0;
    size_t pklen = 0;
    size_t sklen = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    c  = (const unsigned char *)lua_tolstring(L,1,&clen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(clen <= crypto_box_MACBYTES) {
        return luaL_error(L,"wrong cipher length, expected at least: %d",
          crypto_box_MACBYTES);
    }

    if(nlen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          crypto_box_NONCEBYTES);
    }

    if(pklen != crypto_box_PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key length, expected: %d",
          crypto_box_PUBLICKEYBYTES);
    }

    if(sklen != crypto_box_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          crypto_box_SECRETKEYBYTES);
    }

    mlen = clen - crypto_box_MACBYTES;

    m = lua_newuserdata(L,mlen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(crypto_box_open_easy(m,c,clen,n,pk,sk) == -1) {
        return luaL_error(L,"crypto_box_open_easy error");
    }

    lua_pushlstring(L,(const char *)m,mlen);
    sodium_memzero(m,mlen);
    return 1;
}

static int
ls_crypto_box_detached(lua_State *L) {
    unsigned char *c   = NULL;
    unsigned char *mac = NULL;
    const unsigned char *m = NULL;
    const unsigned char *n = NULL;
    const unsigned char *pk = NULL;
    const unsigned char *sk = NULL;
    size_t mlen = 0;
    size_t nlen = 0;
    size_t pklen = 0;
    size_t sklen = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(nlen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          crypto_box_NONCEBYTES);
    }

    if(pklen != crypto_box_PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key length, expected: %d",
          crypto_box_PUBLICKEYBYTES);
    }

    if(sklen != crypto_box_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          crypto_box_SECRETKEYBYTES);
    }

    c = lua_newuserdata(L,mlen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    mac = lua_newuserdata(L,crypto_box_MACBYTES);
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(crypto_box_detached(c,mac,m,mlen,n,pk,sk) == -1) {
        return luaL_error(L,"crypto_box_detached error");
    }

    lua_pushlstring(L,(const char *)c,mlen);
    lua_pushlstring(L,(const char *)mac,crypto_box_MACBYTES);

    sodium_memzero(c,mlen);
    sodium_memzero(mac,crypto_box_MACBYTES);
    return 2;
}

static int
ls_crypto_box_open_detached(lua_State *L) {
    unsigned char *m = NULL;
    const unsigned char *c = NULL;
    const unsigned char *mac = NULL;
    const unsigned char *n = NULL;
    const unsigned char *pk = NULL;
    const unsigned char *sk = NULL;
    size_t clen = 0;
    size_t maclen = 0;
    size_t nlen = 0;
    size_t pklen = 0;
    size_t sklen = 0;

    if(lua_isnoneornil(L,5)) {
        lua_pushliteral(L,"requires 5 arguments");
        return lua_error(L);
    }

    c   = (const unsigned char *)lua_tolstring(L,1,&clen);
    mac = (const unsigned char *)lua_tolstring(L,2,&maclen);
    n   = (const unsigned char *)lua_tolstring(L,3,&nlen);
    pk  = (const unsigned char *)lua_tolstring(L,4,&pklen);
    sk  = (const unsigned char *)lua_tolstring(L,5,&sklen);

    if(maclen != crypto_box_MACBYTES) {
        return luaL_error(L,"wrong mac length, expected: %d",
          crypto_box_MACBYTES);
    }

    if(nlen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          crypto_box_NONCEBYTES);
    }

    if(pklen != crypto_box_PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key length, expected: %d",
          crypto_box_PUBLICKEYBYTES);
    }

    if(sklen != crypto_box_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          crypto_box_SECRETKEYBYTES);
    }

    m = lua_newuserdata(L,clen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(crypto_box_open_detached(m,c,mac,clen,n,pk,sk) == -1) {
        return luaL_error(L,"crypto_box_open_detached error");
    }

    lua_pushlstring(L,(const char *)m,clen);

    sodium_memzero(m,clen);

    return 1;
}

static int
ls_crypto_box_beforenm(lua_State *L) {
    unsigned char *k = NULL;
    const unsigned char *pk = NULL;
    const unsigned char *sk = NULL;

    size_t pklen = 0;
    size_t sklen = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    pk  = (const unsigned char *)lua_tolstring(L,1,&pklen);
    sk  = (const unsigned char *)lua_tolstring(L,2,&sklen);

    if(pklen != crypto_box_PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key length, expected: %d",
          crypto_box_PUBLICKEYBYTES);
    }

    if(sklen != crypto_box_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          crypto_box_SECRETKEYBYTES);
    }

    k = lua_newuserdata(L,crypto_box_BEFORENMBYTES);
    if(k == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }

    if(crypto_box_beforenm(k,pk,sk) == -1) {
        return luaL_error(L,"crypto_box_beforenm error");
    }

    lua_pushlstring(L,(const char *)k,crypto_box_BEFORENMBYTES);
    sodium_memzero(k,crypto_box_BEFORENMBYTES);
    return 1;
}

static int
ls_crypto_box_easy_afternm(lua_State *L) {
    unsigned char *c = NULL;
    const unsigned char *m = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;
    size_t clen = 0;
    size_t mlen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          crypto_box_NONCEBYTES);
    }

    if(klen != crypto_box_BEFORENMBYTES) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          crypto_box_BEFORENMBYTES);
    }

    clen = mlen + crypto_box_MACBYTES;

    c = lua_newuserdata(L,clen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(crypto_box_easy_afternm(c,m,mlen,n,k) == -1) {
        return luaL_error(L,"crypto_box_easy_afternm error");
    }

    lua_pushlstring(L,(const char *)c,clen);
    sodium_memzero(c,clen);
    return 1;
}

static int
ls_crypto_box_open_easy_afternm(lua_State *L) {
    unsigned char *m = NULL;
    const unsigned char *c = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;
    size_t mlen = 0;
    size_t clen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    c  = (const unsigned char *)lua_tolstring(L,1,&clen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(clen <= crypto_box_MACBYTES) {
        return luaL_error(L,"wrong cipher length, expected at least: %d",
          crypto_box_MACBYTES);
    }

    if(nlen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          crypto_box_NONCEBYTES);
    }

    if(klen != crypto_box_BEFORENMBYTES) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          crypto_box_BEFORENMBYTES);
    }

    mlen = clen - crypto_box_MACBYTES;

    m = lua_newuserdata(L,mlen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(crypto_box_open_easy_afternm(m,c,clen,n,k) == -1) {
        return luaL_error(L,"crypto_box_open_easy_afternm error");
    }

    lua_pushlstring(L,(const char *)m,mlen);
    sodium_memzero(m,mlen);
    return 1;
}

static int
ls_crypto_box_detached_afternm(lua_State *L) {
    unsigned char *c = NULL;
    unsigned char *mac = NULL;
    const unsigned char *m = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;
    size_t mlen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          crypto_box_NONCEBYTES);
    }

    if(klen != crypto_box_BEFORENMBYTES) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          crypto_box_BEFORENMBYTES);
    }

    c = lua_newuserdata(L,mlen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    mac = lua_newuserdata(L,crypto_box_MACBYTES);
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(crypto_box_detached_afternm(c,mac,m,mlen,n,k) == -1) {
        return luaL_error(L,"crypto_box_detached_afternm error");
    }

    lua_pushlstring(L,(const char *)c,mlen);
    lua_pushlstring(L,(const char *)mac,crypto_box_MACBYTES);

    sodium_memzero(c,mlen);
    sodium_memzero(mac,crypto_box_MACBYTES);
    return 2;
}

static int
ls_crypto_box_open_detached_afternm(lua_State *L) {
    unsigned char *m = NULL;
    const unsigned char *c   = NULL;
    const unsigned char *mac = NULL;
    const unsigned char *n   = NULL;
    const unsigned char *k   = NULL;
    size_t clen = 0;
    size_t maclen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    c   = (const unsigned char *)lua_tolstring(L,1,&clen);
    mac = (const unsigned char *)lua_tolstring(L,2,&maclen);
    n   = (const unsigned char *)lua_tolstring(L,3,&nlen);
    k   = (const unsigned char *)lua_tolstring(L,4,&klen);

    if(maclen != crypto_box_MACBYTES) {
        return luaL_error(L,"wrong mac length, expected: %d",
          crypto_box_MACBYTES);
    }

    if(nlen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          crypto_box_NONCEBYTES);
    }

    if(klen != crypto_box_BEFORENMBYTES) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          crypto_box_BEFORENMBYTES);
    }

    m = lua_newuserdata(L,clen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(crypto_box_open_detached_afternm(m,c,mac,clen,n,k) == -1) {
        return luaL_error(L,"crypto_box_open_detached error");
    }

    lua_pushlstring(L,(const char *)m,clen);
    return 1;
}

static const struct luaL_Reg ls_crypto_box_functions[] = {
    LS_LUA_FUNC(crypto_box_keypair),
    LS_LUA_FUNC(crypto_box_seed_keypair),
    LS_LUA_FUNC(crypto_box_easy),
    LS_LUA_FUNC(crypto_box_open_easy),
    LS_LUA_FUNC(crypto_box_detached),
    LS_LUA_FUNC(crypto_box_open_detached),
    LS_LUA_FUNC(crypto_box_beforenm),
    LS_LUA_FUNC(crypto_box_easy_afternm),
    LS_LUA_FUNC(crypto_box_open_easy_afternm),
    LS_LUA_FUNC(crypto_box_detached_afternm),
    LS_LUA_FUNC(crypto_box_open_detached_afternm),
    { NULL, NULL },
};

int luaopen_luasodium_crypto_box_core(lua_State *L) {
    LUASODIUM_INIT(L)
    lua_newtable(L);

    luasodium_set_constants(L,ls_crypto_box_constants);
    luaL_setfuncs(L,ls_crypto_box_functions,0);

    return 1;
}
