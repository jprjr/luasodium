#include "../luasodium-c.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

#include <stdlib.h>
#include <string.h>

/* NaCl functions */

typedef int (*ls_crypto_box_keypair_ptr)(
  unsigned char *,
  unsigned char *);

typedef int (*ls_crypto_box_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_open_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_beforenm_ptr)(
  unsigned char *,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_afternm_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_open_afternm_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_easy_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *,
  const unsigned char *);

/* libsodium functions */

typedef int (*ls_crypto_box_seed_keypair_ptr)(
  unsigned char *,
  unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_open_easy_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_detached_ptr)(
  unsigned char *,
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_open_detached_ptr)(
  unsigned char *,
  const unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_easy_afternm_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_open_easy_afternm_ptr)(
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_detached_afternm_ptr)(
  unsigned char *,
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_box_open_detached_afternm_ptr)(
  unsigned char *,
  const unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

static int
ls_crypto_box_keypair(lua_State *L) {
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;

    const char *fname = NULL;
    ls_crypto_box_keypair_ptr f = NULL;
    size_t PUBLICKEYBYTES = 0;
    size_t SECRETKEYBYTES = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_keypair_ptr)lua_touserdata(L,lua_upvalueindex(2));
    PUBLICKEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(3));
    SECRETKEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(4));

    pk = lua_newuserdata(L,PUBLICKEYBYTES);

    /* LCOV_EXCL_START */
    if(pk == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    sk = lua_newuserdata(L,SECRETKEYBYTES);

    /* LCOV_EXCL_START */
    if(sk == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    /* LCOV_EXCL_START */
    if(f(pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)pk,PUBLICKEYBYTES);
    lua_pushlstring(L,(const char *)sk,SECRETKEYBYTES);

    sodium_memzero(pk,PUBLICKEYBYTES);
    sodium_memzero(sk,SECRETKEYBYTES);

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

    const char *fname = NULL;
    ls_crypto_box_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t PUBLICKEYBYTES = 0;
    size_t SECRETKEYBYTES = 0;
    size_t ZEROBYTES = 0;
    size_t BOXZEROBYTES = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 parameters");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    PUBLICKEYBYTES = lua_tointeger(L,lua_upvalueindex(5));
    SECRETKEYBYTES = lua_tointeger(L,lua_upvalueindex(6));
    ZEROBYTES = lua_tointeger(L,lua_upvalueindex(7));
    BOXZEROBYTES = lua_tointeger(L,lua_upvalueindex(8));

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    pk    = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk    = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(noncelen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",NONCEBYTES);
    }

    if(pklen != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",PUBLICKEYBYTES);
    }

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",SECRETKEYBYTES);
    }

    clen = mlen + MACBYTES;

    tmp_m = (unsigned char *)lua_newuserdata(L,mlen + ZEROBYTES);

    /* LCOV_EXCL_START */
    if(tmp_m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    c = (unsigned char *)lua_newuserdata(L,clen + BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_m,ZEROBYTES);
    sodium_memzero(c,BOXZEROBYTES);

    memcpy(&tmp_m[ZEROBYTES],m,mlen);

    /* LCOV_EXCL_START */
    if(f(c,tmp_m,mlen+ZEROBYTES,nonce,pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)&c[BOXZEROBYTES],clen);
    sodium_memzero(tmp_m,mlen + ZEROBYTES);
    sodium_memzero(c,clen + BOXZEROBYTES);
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

    const char *fname = NULL;
    ls_crypto_box_open_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t PUBLICKEYBYTES = 0;
    size_t SECRETKEYBYTES = 0;
    size_t ZEROBYTES = 0;
    size_t BOXZEROBYTES = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 parameters");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_open_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    PUBLICKEYBYTES = lua_tointeger(L,lua_upvalueindex(5));
    SECRETKEYBYTES = lua_tointeger(L,lua_upvalueindex(6));
    ZEROBYTES = lua_tointeger(L,lua_upvalueindex(7));
    BOXZEROBYTES = lua_tointeger(L,lua_upvalueindex(8));

    c = (const unsigned char *)lua_tolstring(L,1,&clen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    pk    = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk    = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(clen < MACBYTES) {
        return luaL_error(L,"wrong mac size, expected at least: %d",MACBYTES);
    }

    if(noncelen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",NONCEBYTES);
    }

    if(pklen != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",PUBLICKEYBYTES);
    }

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",SECRETKEYBYTES);
    }

    mlen = clen - MACBYTES;

    tmp_c = (unsigned char *)lua_newuserdata(L,clen + BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(tmp_c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    m = (unsigned char *)lua_newuserdata(L,mlen + ZEROBYTES);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_c,BOXZEROBYTES);
    sodium_memzero(m,ZEROBYTES);

    memcpy(&tmp_c[BOXZEROBYTES],c,clen);

    if(f(m,tmp_c,clen+BOXZEROBYTES,nonce,pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)&m[ZEROBYTES],mlen);
    sodium_memzero(tmp_c,clen + BOXZEROBYTES);
    sodium_memzero(m,mlen + ZEROBYTES);
    return 1;
}

static int
ls_crypto_box_beforenm(lua_State *L) {
    unsigned char *k = NULL;
    const unsigned char *pk = NULL;
    const unsigned char *sk = NULL;

    size_t pklen = 0;
    size_t sklen = 0;

    const char *fname = NULL;
    ls_crypto_box_beforenm_ptr f = NULL;
    size_t PUBLICKEYBYTES = 0;
    size_t SECRETKEYBYTES = 0;
    size_t BEFORENMBYTES = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_beforenm_ptr)lua_touserdata(L,lua_upvalueindex(2));
    PUBLICKEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(3));
    SECRETKEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(4));
    BEFORENMBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(5));


    pk  = (const unsigned char *)lua_tolstring(L,1,&pklen);
    sk  = (const unsigned char *)lua_tolstring(L,2,&sklen);

    if(pklen != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key length, expected: %d",
          PUBLICKEYBYTES);
    }

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          SECRETKEYBYTES);
    }

    k = (unsigned char *)lua_newuserdata(L,BEFORENMBYTES);

    /* LCOV_EXCL_START */
    if(k == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(k,pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)k,BEFORENMBYTES);
    sodium_memzero(k,BEFORENMBYTES);
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

    const char *fname = NULL;
    ls_crypto_box_afternm_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t BEFORENMBYTES = 0;
    size_t ZEROBYTES = 0;
    size_t BOXZEROBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_afternm_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    BEFORENMBYTES = lua_tointeger(L,lua_upvalueindex(5));
    ZEROBYTES = lua_tointeger(L,lua_upvalueindex(6));
    BOXZEROBYTES = lua_tointeger(L,lua_upvalueindex(7));

    m     = (const unsigned char *)lua_tolstring(L,1,&mlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    k     = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(noncelen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",NONCEBYTES);
    }

    if(klen != BEFORENMBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",BEFORENMBYTES);
    }

    clen = mlen + MACBYTES;

    tmp_m = (unsigned char *)lua_newuserdata(L,mlen + ZEROBYTES);

    /* LCOV_EXCL_START */
    if(tmp_m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    c = (unsigned char *)lua_newuserdata(L,clen + BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_m,ZEROBYTES);
    sodium_memzero(c,BOXZEROBYTES);

    memcpy(&tmp_m[ZEROBYTES],m,mlen);

    /* LCOV_EXCL_START */
    if(f(c,tmp_m,mlen+ZEROBYTES,nonce,k) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)&c[BOXZEROBYTES],clen);
    sodium_memzero(tmp_m,mlen + ZEROBYTES);
    sodium_memzero(c,clen + BOXZEROBYTES);
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

    const char *fname = NULL;
    ls_crypto_box_open_afternm_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t BEFORENMBYTES = 0;
    size_t ZEROBYTES = 0;
    size_t BOXZEROBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_open_afternm_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    BEFORENMBYTES = lua_tointeger(L,lua_upvalueindex(5));
    ZEROBYTES = lua_tointeger(L,lua_upvalueindex(6));
    BOXZEROBYTES = lua_tointeger(L,lua_upvalueindex(7));

    c = (const unsigned char *)lua_tolstring(L,1,&clen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    k     = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(clen < MACBYTES) {
        return luaL_error(L,"wrong mac size, expected at least: %d",MACBYTES);
    }

    if(noncelen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",NONCEBYTES);
    }

    if(klen != BEFORENMBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",BEFORENMBYTES);
    }

    mlen = clen - MACBYTES;

    tmp_c = (unsigned char *)lua_newuserdata(L,clen + BOXZEROBYTES);

    /* LCOV_EXCL_START */
    if(tmp_c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    m = (unsigned char *)lua_newuserdata(L,mlen + ZEROBYTES);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    sodium_memzero(tmp_c,BOXZEROBYTES);
    sodium_memzero(m,ZEROBYTES);

    memcpy(&tmp_c[BOXZEROBYTES],c,clen);

    if(f(m,tmp_c,clen+BOXZEROBYTES,nonce,k) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)&m[ZEROBYTES],mlen);
    sodium_memzero(tmp_c,clen + BOXZEROBYTES);
    sodium_memzero(m,mlen + ZEROBYTES);
    return 1;
}


/* libsodium additions */

static int
ls_crypto_box_seed_keypair(lua_State *L) {
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;
    const unsigned char *seed = NULL;
    size_t seed_len = 0;

    const char *fname = NULL;
    ls_crypto_box_seed_keypair_ptr f = NULL;
    size_t PUBLICKEYBYTES = 0;
    size_t SECRETKEYBYTES = 0;
    size_t SEEDBYTES = 0;

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"requires 1 argument");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_seed_keypair_ptr)lua_touserdata(L,lua_upvalueindex(2));
    PUBLICKEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(3));
    SECRETKEYBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(4));
    SEEDBYTES = (size_t) lua_tointeger(L,lua_upvalueindex(5));

    seed = (const unsigned char *)lua_tolstring(L,1,&seed_len);

    if(seed_len != SEEDBYTES) {
        return luaL_error(L,"wrong seed length, expected: %d",
          SEEDBYTES);
    }

    pk = lua_newuserdata(L,PUBLICKEYBYTES);

    /* LCOV_EXCL_START */
    if(pk == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    sk = lua_newuserdata(L,SECRETKEYBYTES);

    /* LCOV_EXCL_START */
    if(sk == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    /* LCOV_EXCL_START */
    if(f(pk,sk,seed) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)pk,PUBLICKEYBYTES);
    lua_pushlstring(L,(const char *)sk,SECRETKEYBYTES);

    sodium_memzero(pk,PUBLICKEYBYTES);
    sodium_memzero(sk,SECRETKEYBYTES);

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

    const char *fname = NULL;
    ls_crypto_box_easy_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t PUBLICKEYBYTES = 0;
    size_t SECRETKEYBYTES = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_easy_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    PUBLICKEYBYTES = lua_tointeger(L,lua_upvalueindex(5));
    SECRETKEYBYTES = lua_tointeger(L,lua_upvalueindex(6));

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(nlen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NONCEBYTES);
    }

    if(pklen != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key length, expected: %d",
          PUBLICKEYBYTES);
    }

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          SECRETKEYBYTES);
    }

    clen = mlen + MACBYTES;

    c = lua_newuserdata(L,clen);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(c,m,mlen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
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

    const char *fname = NULL;
    ls_crypto_box_open_easy_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t PUBLICKEYBYTES = 0;
    size_t SECRETKEYBYTES = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    c  = (const unsigned char *)lua_tolstring(L,1,&clen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_open_easy_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    PUBLICKEYBYTES = lua_tointeger(L,lua_upvalueindex(5));
    SECRETKEYBYTES = lua_tointeger(L,lua_upvalueindex(6));

    if(clen < MACBYTES) {
        return luaL_error(L,"wrong cipher length, expected at least: %d",
          MACBYTES);
    }

    if(nlen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NONCEBYTES);
    }

    if(pklen != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key length, expected: %d",
          PUBLICKEYBYTES);
    }

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          SECRETKEYBYTES);
    }

    mlen = clen - MACBYTES;

    m = lua_newuserdata(L,mlen);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    if(f(m,c,clen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
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

    const char *fname = NULL;
    ls_crypto_box_detached_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t PUBLICKEYBYTES = 0;
    size_t SECRETKEYBYTES = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_detached_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    PUBLICKEYBYTES = lua_tointeger(L,lua_upvalueindex(5));
    SECRETKEYBYTES = lua_tointeger(L,lua_upvalueindex(6));

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(nlen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NONCEBYTES);
    }

    if(pklen != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key length, expected: %d",
          PUBLICKEYBYTES);
    }

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          SECRETKEYBYTES);
    }

    c = lua_newuserdata(L,mlen);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    mac = lua_newuserdata(L,MACBYTES);

    /* LCOV_EXCL_START */
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    /* LCOV_EXCL_START */
    if(f(c,mac,m,mlen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)c,mlen);
    lua_pushlstring(L,(const char *)mac,MACBYTES);

    sodium_memzero(c,mlen);
    sodium_memzero(mac,MACBYTES);
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

    const char *fname = NULL;
    ls_crypto_box_open_detached_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t PUBLICKEYBYTES = 0;
    size_t SECRETKEYBYTES = 0;

    if(lua_isnoneornil(L,5)) {
        lua_pushliteral(L,"requires 5 arguments");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_open_detached_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    PUBLICKEYBYTES = lua_tointeger(L,lua_upvalueindex(5));
    SECRETKEYBYTES = lua_tointeger(L,lua_upvalueindex(6));

    c   = (const unsigned char *)lua_tolstring(L,1,&clen);
    mac = (const unsigned char *)lua_tolstring(L,2,&maclen);
    n   = (const unsigned char *)lua_tolstring(L,3,&nlen);
    pk  = (const unsigned char *)lua_tolstring(L,4,&pklen);
    sk  = (const unsigned char *)lua_tolstring(L,5,&sklen);

    if(maclen != MACBYTES) {
        return luaL_error(L,"wrong mac length, expected: %d",
          MACBYTES);
    }

    if(nlen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NONCEBYTES);
    }

    if(pklen != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key length, expected: %d",
          PUBLICKEYBYTES);
    }

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          SECRETKEYBYTES);
    }

    m = lua_newuserdata(L,clen);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    if(f(m,c,mac,clen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)m,clen);

    sodium_memzero(m,clen);

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

    const char *fname = NULL;
    ls_crypto_box_easy_afternm_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t BEFORENMBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_easy_afternm_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    BEFORENMBYTES = lua_tointeger(L,lua_upvalueindex(5));

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NONCEBYTES);
    }

    if(klen != BEFORENMBYTES) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          BEFORENMBYTES);
    }

    clen = mlen + MACBYTES;

    c = lua_newuserdata(L,clen);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    /* LCOV_EXCL_START */
    if(f(c,m,mlen,n,k) == -1) {
        return luaL_error(L,"%s error",fname);
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

    const char *fname = NULL;
    ls_crypto_box_open_easy_afternm_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t BEFORENMBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_open_easy_afternm_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    BEFORENMBYTES = lua_tointeger(L,lua_upvalueindex(5));

    c  = (const unsigned char *)lua_tolstring(L,1,&clen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(clen < MACBYTES) {
        return luaL_error(L,"wrong cipher length, expected at least: %d",
          MACBYTES);
    }

    if(nlen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NONCEBYTES);
    }

    if(klen != BEFORENMBYTES) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          BEFORENMBYTES);
    }

    mlen = clen - MACBYTES;

    m = lua_newuserdata(L,mlen);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,1);

    if(f(m,c,clen,n,k) == -1) {
        return luaL_error(L,"%s error",fname);
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

    const char *fname = NULL;
    ls_crypto_box_detached_afternm_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t BEFORENMBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_detached_afternm_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    BEFORENMBYTES = lua_tointeger(L,lua_upvalueindex(5));

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NONCEBYTES);
    }

    if(klen != BEFORENMBYTES) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          BEFORENMBYTES);
    }

    c = lua_newuserdata(L,mlen);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    mac = lua_newuserdata(L,MACBYTES);

    /* LCOV_EXCL_START */
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pop(L,2);

    /* LCOV_EXCL_START */
    if(f(c,mac,m,mlen,n,k) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)c,mlen);
    lua_pushlstring(L,(const char *)mac,MACBYTES);

    sodium_memzero(c,mlen);
    sodium_memzero(mac,MACBYTES);
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

    const char *fname = NULL;
    ls_crypto_box_open_detached_afternm_ptr f = NULL;

    size_t MACBYTES = 0;
    size_t NONCEBYTES = 0;
    size_t BEFORENMBYTES = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_box_open_detached_afternm_ptr) lua_touserdata(L,lua_upvalueindex(2));
    MACBYTES = lua_tointeger(L,lua_upvalueindex(3));
    NONCEBYTES = lua_tointeger(L,lua_upvalueindex(4));
    BEFORENMBYTES = lua_tointeger(L,lua_upvalueindex(5));

    c   = (const unsigned char *)lua_tolstring(L,1,&clen);
    mac = (const unsigned char *)lua_tolstring(L,2,&maclen);
    n   = (const unsigned char *)lua_tolstring(L,3,&nlen);
    k   = (const unsigned char *)lua_tolstring(L,4,&klen);

    if(maclen != MACBYTES) {
        return luaL_error(L,"wrong mac length, expected: %d",
          MACBYTES);
    }

    if(nlen != NONCEBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NONCEBYTES);
    }

    if(klen != BEFORENMBYTES) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          BEFORENMBYTES);
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
    if(f(m,c,mac,clen,n,k) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)m,clen);
    return 1;
}

#define LS_PUSH_CRYPTO_BOX_KEYPAIR(x, y) \
  lua_pushliteral(L, #x "_keypair" ); \
  lua_pushlightuserdata(L, x ## _keypair); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _keypair, 4); \
  lua_setfield(L,-2, #x "_keypair");

#define LS_PUSH_CRYPTO_BOX(x, y) \
  lua_pushliteral(L, #x ); \
  lua_pushlightuserdata(L, x ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushinteger(L, x ## _ZEROBYTES); \
  lua_pushinteger(L, x ## _BOXZEROBYTES); \
  lua_pushcclosure(L, ls_ ## y , 8); \
  lua_setfield(L,-2, #x );

#define LS_PUSH_CRYPTO_BOX_OPEN(x, y) \
  lua_pushliteral(L, #x "_open" ); \
  lua_pushlightuserdata(L, x ## _open ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushinteger(L, x ## _ZEROBYTES); \
  lua_pushinteger(L, x ## _BOXZEROBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _open , 8); \
  lua_setfield(L,-2, #x "_open" );

#define LS_PUSH_CRYPTO_BOX_BEFORENM(x, y) \
  lua_pushliteral(L, #x "_beforenm" ); \
  lua_pushlightuserdata(L, x ## _beforenm ); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushinteger(L, x ## _BEFORENMBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _beforenm , 5); \
  lua_setfield(L,-2, #x "_beforenm" );

#define LS_PUSH_CRYPTO_BOX_AFTERNM(x, y) \
  lua_pushliteral(L, #x "_afternm" ); \
  lua_pushlightuserdata(L, x ## _afternm ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _BEFORENMBYTES); \
  lua_pushinteger(L, x ## _ZEROBYTES); \
  lua_pushinteger(L, x ## _BOXZEROBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _afternm , 7); \
  lua_setfield(L,-2, #x "_afternm" );

#define LS_PUSH_CRYPTO_BOX_OPEN_AFTERNM(x, y) \
  lua_pushliteral(L, #x "_open_afternm" ); \
  lua_pushlightuserdata(L, x ## _open_afternm ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _BEFORENMBYTES); \
  lua_pushinteger(L, x ## _ZEROBYTES); \
  lua_pushinteger(L, x ## _BOXZEROBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _open_afternm , 7); \
  lua_setfield(L,-2, #x "_open_afternm" );

#define LS_PUSH_CRYPTO_BOX_SEED_KEYPAIR(x, y) \
  lua_pushliteral(L, #x "_seed_keypair" ); \
  lua_pushlightuserdata(L, x ## _seed_keypair); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushinteger(L, x ## _SEEDBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _seed_keypair, 5); \
  lua_setfield(L,-2, #x "_seed_keypair");

#define LS_PUSH_CRYPTO_BOX_EASY(x, y) \
  lua_pushliteral(L, #x "_easy" ); \
  lua_pushlightuserdata(L, x ## _easy ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _easy , 6); \
  lua_setfield(L,-2, #x "_easy" );

#define LS_PUSH_CRYPTO_BOX_OPEN_EASY(x, y) \
  lua_pushliteral(L, #x "_open_easy" ); \
  lua_pushlightuserdata(L, x ## _open_easy ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _open_easy , 6); \
  lua_setfield(L,-2, #x "_open_easy" );

#define LS_PUSH_CRYPTO_BOX_DETACHED(x, y) \
  lua_pushliteral(L, #x "_detached" ); \
  lua_pushlightuserdata(L, x ## _detached ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _detached , 6); \
  lua_setfield(L,-2, #x "_detached" );

#define LS_PUSH_CRYPTO_BOX_OPEN_DETACHED(x, y) \
  lua_pushliteral(L, #x "_open_detached" ); \
  lua_pushlightuserdata(L, x ## _open_detached ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _open_detached , 6); \
  lua_setfield(L,-2, #x "_open_detached" );

#define LS_PUSH_CRYPTO_BOX_EASY_AFTERNM(x, y) \
  lua_pushliteral(L, #x "_easy_afternm" ); \
  lua_pushlightuserdata(L, x ## _easy_afternm ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _BEFORENMBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _easy_afternm , 5); \
  lua_setfield(L,-2, #x "_easy_afternm" );

#define LS_PUSH_CRYPTO_BOX_OPEN_EASY_AFTERNM(x, y) \
  lua_pushliteral(L, #x "_open_easy_afternm" ); \
  lua_pushlightuserdata(L, x ## _open_easy_afternm ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _BEFORENMBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _open_easy_afternm , 5); \
  lua_setfield(L,-2, #x "_open_easy_afternm" );

#define LS_PUSH_CRYPTO_BOX_DETACHED_AFTERNM(x, y) \
  lua_pushliteral(L, #x "_detached_afternm" ); \
  lua_pushlightuserdata(L, x ## _detached_afternm ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _BEFORENMBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _detached_afternm , 5); \
  lua_setfield(L,-2, #x "_detached_afternm" );

#define LS_PUSH_CRYPTO_BOX_OPEN_DETACHED_AFTERNM(x, y) \
  lua_pushliteral(L, #x "_open_detached_afternm" ); \
  lua_pushlightuserdata(L, x ## _open_detached_afternm ); \
  lua_pushinteger(L, x ## _MACBYTES); \
  lua_pushinteger(L, x ## _NONCEBYTES); \
  lua_pushinteger(L, x ## _BEFORENMBYTES); \
  lua_pushcclosure(L, ls_ ## y ## _open_detached_afternm , 5); \
  lua_setfield(L,-2, #x "_open_detached_afternm" );

LS_PUBLIC
int luaopen_luasodium_crypto_box_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L)
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_box_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_BOX_KEYPAIR(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX_OPEN(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX_BEFORENM(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX_AFTERNM(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX_OPEN_AFTERNM(crypto_box,crypto_box);

    LS_PUSH_CRYPTO_BOX_KEYPAIR(crypto_box_curve25519xsalsa20poly1305,crypto_box);
    LS_PUSH_CRYPTO_BOX(crypto_box_curve25519xsalsa20poly1305,crypto_box);
    LS_PUSH_CRYPTO_BOX_OPEN(crypto_box_curve25519xsalsa20poly1305,crypto_box);
    LS_PUSH_CRYPTO_BOX_BEFORENM(crypto_box_curve25519xsalsa20poly1305,crypto_box);
    LS_PUSH_CRYPTO_BOX_AFTERNM(crypto_box_curve25519xsalsa20poly1305,crypto_box);
    LS_PUSH_CRYPTO_BOX_OPEN_AFTERNM(crypto_box_curve25519xsalsa20poly1305,crypto_box);

    LS_PUSH_CRYPTO_BOX_SEED_KEYPAIR(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX_SEED_KEYPAIR(crypto_box_curve25519xsalsa20poly1305,crypto_box);

    LS_PUSH_CRYPTO_BOX_EASY(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX_OPEN_EASY(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX_DETACHED(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX_OPEN_DETACHED(crypto_box,crypto_box);

    LS_PUSH_CRYPTO_BOX_EASY_AFTERNM(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX_OPEN_EASY_AFTERNM(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX_DETACHED_AFTERNM(crypto_box,crypto_box);
    LS_PUSH_CRYPTO_BOX_OPEN_DETACHED_AFTERNM(crypto_box,crypto_box);

    return 1;
}

