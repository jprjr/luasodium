#include "../luasodium-c.h"
#include "../internals/ls_lua_setfuncs.h"
#include "constants.h"

#include <stdlib.h>
#include <string.h>


static int
ls_crypto_box_keypair(lua_State *L) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    /* LCOV_EXCL_START */
    if(crypto_box_keypair(pk,sk) == -1) {
        lua_pushliteral(L,"crypto_box_keypair error");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)pk,crypto_box_PUBLICKEYBYTES);
    lua_pushlstring(L,(const char *)sk,crypto_box_SECRETKEYBYTES);

    sodium_memzero(pk,crypto_box_PUBLICKEYBYTES);
    sodium_memzero(sk,crypto_box_SECRETKEYBYTES);

    return 2;
}

static int
ls_crypto_box_seed_keypair(lua_State *L) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
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

    /* LCOV_EXCL_START */
    if(crypto_box_seed_keypair(pk,sk,seed) == -1) {
        return luaL_error(L,"crypto_box_seed_keypair error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)pk,crypto_box_PUBLICKEYBYTES);
    lua_pushlstring(L,(const char *)sk,crypto_box_SECRETKEYBYTES);

    sodium_memzero(pk,crypto_box_PUBLICKEYBYTES);
    sodium_memzero(sk,crypto_box_SECRETKEYBYTES);

    return 2;
}

static int
ls_crypto_box(lua_State *L) {
    unsigned char *c      = NULL;
    const unsigned char *m = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *pk    = NULL;
    const unsigned char *sk    = NULL;

    unsigned char *tmp_m   = NULL;

    size_t clen = 0;
    size_t mlen = 0;
    size_t noncelen = 0;
    size_t pklen = 0;
    size_t sklen = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 parameters");
        return lua_error(L);
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    pk    = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk    = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(noncelen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_box_NONCEBYTES);
    }

    if(pklen != crypto_box_PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",crypto_box_PUBLICKEYBYTES);
    }

    if(sklen != crypto_box_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",crypto_box_SECRETKEYBYTES);
    }

    clen = mlen + crypto_box_MACBYTES;

    tmp_m = (unsigned char *)lua_newuserdata(L,mlen + crypto_box_ZEROBYTES);

    /* LCOV_EXCL_START */
    if(tmp_m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    c = (unsigned char *)lua_newuserdata(L,clen + crypto_box_BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_m,crypto_box_ZEROBYTES);
    sodium_memzero(c,crypto_box_BOXZEROBYTES);

    memcpy(&tmp_m[crypto_box_ZEROBYTES],m,mlen);

    /* LCOV_EXCL_START */
    if(crypto_box(c,tmp_m,mlen+crypto_box_ZEROBYTES,nonce,pk,sk) == -1) {
        return luaL_error(L,"crypto_box error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)&c[crypto_box_BOXZEROBYTES],clen);
    sodium_memzero(tmp_m,mlen + crypto_box_ZEROBYTES);
    sodium_memzero(c,clen + crypto_box_BOXZEROBYTES);
    return 1;
}

static int
ls_crypto_box_open(lua_State *L) {
    unsigned char *m      = NULL;
    const unsigned char *c = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *pk    = NULL;
    const unsigned char *sk    = NULL;

    unsigned char *tmp_c   = NULL;

    size_t mlen = 0;
    size_t clen = 0;
    size_t noncelen = 0;
    size_t pklen = 0;
    size_t sklen = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 parameters");
        return lua_error(L);
    }

    c = (const unsigned char *)lua_tolstring(L,1,&clen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    pk    = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk    = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(clen < crypto_box_MACBYTES) {
        return luaL_error(L,"wrong mac size, expected at least: %d",crypto_box_MACBYTES);
    }

    if(noncelen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_box_NONCEBYTES);
    }

    if(pklen != crypto_box_PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",crypto_box_PUBLICKEYBYTES);
    }

    if(sklen != crypto_box_SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",crypto_box_SECRETKEYBYTES);
    }

    mlen = clen - crypto_box_MACBYTES;

    tmp_c = (unsigned char *)lua_newuserdata(L,clen + crypto_box_BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(tmp_c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    m = (unsigned char *)lua_newuserdata(L,mlen + crypto_box_ZEROBYTES);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_c,crypto_box_BOXZEROBYTES);
    sodium_memzero(m,crypto_box_ZEROBYTES);

    memcpy(&tmp_c[crypto_box_BOXZEROBYTES],c,clen);

    if(crypto_box_open(m,tmp_c,clen+crypto_box_BOXZEROBYTES,nonce,pk,sk) == -1) {
        return luaL_error(L,"crypto_box_open error");
    }

    lua_pushlstring(L,(const char *)&m[crypto_box_ZEROBYTES],mlen);
    sodium_memzero(tmp_c,clen + crypto_box_BOXZEROBYTES);
    sodium_memzero(m,mlen + crypto_box_ZEROBYTES);
    return 1;
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

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(crypto_box_easy(c,m,mlen,n,pk,sk) == -1) {
        return luaL_error(L,"crypto_box_easy error");
    }
    /* LCOV_EXCL_STOP */

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

    if(clen < crypto_box_MACBYTES) {
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

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

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
    unsigned char mac[crypto_box_MACBYTES];
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

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(crypto_box_detached(c,mac,m,mlen,n,pk,sk) == -1) {
        return luaL_error(L,"crypto_box_detached error");
    }
    /* LCOV_EXCL_STOP */

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

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

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
    unsigned char k[crypto_box_BEFORENMBYTES];
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

    /* LCOV_EXCL_START */
    if(crypto_box_beforenm(k,pk,sk) == -1) {
        return luaL_error(L,"crypto_box_beforenm error");
    }
    /* LCOV_EXCL_STOP */

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

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(crypto_box_easy_afternm(c,m,mlen,n,k) == -1) {
        return luaL_error(L,"crypto_box_easy_afternm error");
    }
    /* LCOV_EXCL_STOP */

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

    if(clen < crypto_box_MACBYTES) {
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

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

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
    unsigned char mac[crypto_box_MACBYTES];
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

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(crypto_box_detached_afternm(c,mac,m,mlen,n,k) == -1) {
        return luaL_error(L,"crypto_box_detached_afternm error");
    }
    /* LCOV_EXCL_STOP */

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

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(crypto_box_open_detached_afternm(m,c,mac,clen,n,k) == -1) {
        return luaL_error(L,"crypto_box_open_detached error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)m,clen);
    return 1;
}

static int
ls_crypto_box_afternm(lua_State *L) {
    unsigned char *c      = NULL;
    const unsigned char *m = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *k    = NULL;

    unsigned char *tmp_m   = NULL;

    size_t clen = 0;
    size_t mlen = 0;
    size_t noncelen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    m     = (const unsigned char *)lua_tolstring(L,1,&mlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    k     = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(noncelen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_box_NONCEBYTES);
    }

    if(klen != crypto_box_BEFORENMBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_box_BEFORENMBYTES);
    }

    clen = mlen + crypto_box_MACBYTES;

    tmp_m = (unsigned char *)lua_newuserdata(L,mlen + crypto_box_ZEROBYTES);

    /* LCOV_EXCL_START */
    if(tmp_m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    c = (unsigned char *)lua_newuserdata(L,clen + crypto_box_BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_m,crypto_box_ZEROBYTES);
    sodium_memzero(c,crypto_box_BOXZEROBYTES);

    memcpy(&tmp_m[crypto_box_ZEROBYTES],m,mlen);

    /* LCOV_EXCL_START */
    if(crypto_box_afternm(c,tmp_m,mlen+crypto_box_ZEROBYTES,nonce,k) == -1) {
        return luaL_error(L,"crypto_box_afternm error");
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)&c[crypto_box_BOXZEROBYTES],clen);
    sodium_memzero(tmp_m,mlen + crypto_box_ZEROBYTES);
    sodium_memzero(c,clen + crypto_box_BOXZEROBYTES);
    return 1;
}

static int
ls_crypto_box_open_afternm(lua_State *L) {
    unsigned char *m      = NULL;
    const unsigned char *c = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *k    = NULL;

    unsigned char *tmp_c   = NULL;

    size_t mlen = 0;
    size_t clen = 0;
    size_t noncelen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    c = (const unsigned char *)lua_tolstring(L,1,&clen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    k     = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(clen < crypto_box_MACBYTES) {
        return luaL_error(L,"wrong mac size, expected at least: %d",crypto_box_MACBYTES);
    }

    if(noncelen != crypto_box_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_box_NONCEBYTES);
    }

    if(klen != crypto_box_BEFORENMBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",crypto_box_BEFORENMBYTES);
    }

    mlen = clen - crypto_box_MACBYTES;

    tmp_c = (unsigned char *)lua_newuserdata(L,clen + crypto_box_BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(tmp_c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    m = (unsigned char *)lua_newuserdata(L,mlen + crypto_box_ZEROBYTES);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_c,crypto_box_BOXZEROBYTES);
    sodium_memzero(m,crypto_box_ZEROBYTES);

    memcpy(&tmp_c[crypto_box_BOXZEROBYTES],c,clen);

    if(crypto_box_open_afternm(m,tmp_c,clen+crypto_box_BOXZEROBYTES,nonce,k) == -1) {
        return luaL_error(L,"crypto_box_open_afternm error");
    }

    lua_pushlstring(L,(const char *)&m[crypto_box_ZEROBYTES],mlen);
    sodium_memzero(tmp_c,clen + crypto_box_BOXZEROBYTES);
    sodium_memzero(m,mlen + crypto_box_ZEROBYTES);
    return 1;
}

static const struct luaL_Reg ls_crypto_box_functions[] = {
    LS_LUA_FUNC(crypto_box),
    LS_LUA_FUNC(crypto_box_open),
    LS_LUA_FUNC(crypto_box_easy),
    LS_LUA_FUNC(crypto_box_open_easy),
    LS_LUA_FUNC(crypto_box_detached),
    LS_LUA_FUNC(crypto_box_open_detached),
    LS_LUA_FUNC(crypto_box_beforenm),
    LS_LUA_FUNC(crypto_box_easy_afternm),
    LS_LUA_FUNC(crypto_box_open_easy_afternm),
    LS_LUA_FUNC(crypto_box_detached_afternm),
    LS_LUA_FUNC(crypto_box_open_detached_afternm),
    LS_LUA_FUNC(crypto_box_keypair),
    LS_LUA_FUNC(crypto_box_seed_keypair),
    LS_LUA_FUNC(crypto_box_afternm),
    LS_LUA_FUNC(crypto_box_open_afternm),
    { NULL, NULL },
};

LS_PUBLIC
int luaopen_luasodium_crypto_box_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L)
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    luasodium_set_constants(L,ls_crypto_box_constants,lua_gettop(L));
    ls_lua_setfuncs(L,ls_crypto_box_functions,0);

    return 1;
}

