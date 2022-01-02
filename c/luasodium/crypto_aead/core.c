#include "../luasodium-c.h"
#include "../internals/ls_lua_equal.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef int (*ls_crypto_aead_encrypt_ptr)(
  unsigned char *,
  unsigned long long *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_aead_decrypt_ptr)(
  unsigned char *,
  unsigned long long *,
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_aead_encrypt_detached_ptr)(
  unsigned char *,
  unsigned char *,
  unsigned long long *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_aead_decrypt_detached_ptr)(
  unsigned char *,
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *);

typedef void (*ls_crypto_aead_keygen_ptr)(
  unsigned char *);

typedef int (*ls_crypto_aead_beforenm_ptr)(
  void *,
  const unsigned char *);

typedef int (*ls_crypto_aead_encrypt_afternm_ptr)(
  unsigned char *,
  unsigned long long *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *,
  const void *);

typedef int (*ls_crypto_aead_decrypt_afternm_ptr)(
  unsigned char *,
  unsigned long long *,
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const void *);

typedef int (*ls_crypto_aead_encrypt_detached_afternm_ptr)(
  unsigned char *,
  unsigned char *,
  unsigned long long *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  const unsigned char *,
  const void *);

typedef int (*ls_crypto_aead_decrypt_detached_afternm_ptr)(
  unsigned char *m,
  unsigned char *nsec,
  const unsigned char *c,
  unsigned long long clen,
  const unsigned char *mac,
  const unsigned char *ad,
  unsigned long long adlen,
  const unsigned char *npub,
  const void *);

typedef int (*ls_crypto_aead_is_available_ptr)(void);

static int
ls_crypto_aead_is_available(lua_State *L) {
    ls_crypto_aead_is_available_ptr f = NULL;

    f = (ls_crypto_aead_is_available_ptr) lua_touserdata(L, lua_upvalueindex(1));

    lua_pushboolean(L,f());
    return 1;
}

static int
ls_crypto_aead_keygen(lua_State *L) {
    unsigned char *k = NULL;

    ls_crypto_aead_keygen_ptr f = NULL;
    size_t KEYBYTES = 0;

    f = (ls_crypto_aead_keygen_ptr) lua_touserdata(L, lua_upvalueindex(1));
    KEYBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(2));

    k = lua_newuserdata(L,KEYBYTES);

    /* LCOV_EXCL_START */
    if(k == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    f(k);

    lua_pushlstring(L,(const char *)k,KEYBYTES);
    sodium_memzero(k,KEYBYTES);
    return 1;
}

static int
ls_crypto_aead_encrypt(lua_State *L) {
    unsigned char *c = NULL;
    unsigned long long clen = 0;

    const char *fname = NULL;
    ls_crypto_aead_encrypt_ptr f = NULL;
    size_t KEYBYTES = 0;
    size_t NPUBBYTES = 0;
    size_t ABYTES = 0;

    const unsigned char *m = NULL;
    const unsigned char *ad = NULL;
    const unsigned char *npub = NULL;
    const unsigned char *k = NULL;
    size_t mlen = 0;
    size_t adlen = 0;
    size_t npublen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_aead_encrypt_ptr)lua_touserdata(L,lua_upvalueindex(2));
    KEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    NPUBBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));
    ABYTES = (size_t)lua_tointeger(L,lua_upvalueindex(5));

    k    = (const unsigned char *)lua_tolstring(L,1,&klen);
    m    = (const unsigned char *)lua_tolstring(L,2,&mlen);
    npub = (const unsigned char *)lua_tolstring(L,3,&npublen);

    if(lua_isstring(L,4)) {
        ad = (const unsigned char *)lua_tolstring(L,4,&adlen);
    }

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key length, expected: %d",
          KEYBYTES);
    }

    if(npublen != NPUBBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NPUBBYTES);
    }

    clen = mlen + ABYTES;
    c = lua_newuserdata(L, clen);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    f(c,&clen,m,(unsigned long long)mlen,
      ad,(unsigned long long)adlen,
      NULL,npub,k);

    lua_pushlstring(L,(const char *)c,clen);
    sodium_memzero(c, mlen + ABYTES);
    (void)fname;
    return 1;
}

static int
ls_crypto_aead_decrypt(lua_State *L) {
    unsigned char *m = NULL;
    unsigned long long mlen = 0;

    const char *fname = NULL;
    ls_crypto_aead_decrypt_ptr f = NULL;
    size_t KEYBYTES = 0;
    size_t NPUBBYTES = 0;
    size_t ABYTES = 0;

    const unsigned char *c = NULL;
    const unsigned char *ad = NULL;
    const unsigned char *npub = NULL;
    const unsigned char *k = NULL;
    size_t clen = 0;
    size_t adlen = 0;
    size_t npublen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_aead_decrypt_ptr)lua_touserdata(L,lua_upvalueindex(2));
    KEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    NPUBBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));
    ABYTES = (size_t)lua_tointeger(L,lua_upvalueindex(5));

    k    = (const unsigned char *)lua_tolstring(L,1,&klen);
    c    = (const unsigned char *)lua_tolstring(L,2,&clen);
    npub = (const unsigned char *)lua_tolstring(L,3,&npublen);

    if(lua_isstring(L,4)) {
        ad = (const unsigned char *)lua_tolstring(L,4,&adlen);
    }

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key length, expected: %d",
          KEYBYTES);
    }

    if(clen < ABYTES) {
        return luaL_error(L,"wrong cipher length, expected at least: %d",
          ABYTES);
    }

    if(npublen != NPUBBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NPUBBYTES);
    }

    mlen = clen - ABYTES;
    m = lua_newuserdata(L, mlen);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    if(f(m,&mlen,NULL,c,(unsigned long long)clen,
      ad,(unsigned long long)adlen,
      npub,k) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }

    lua_pushlstring(L,(const char *)m,mlen);
    sodium_memzero(m, clen - ABYTES);
    return 1;
}

static int
ls_crypto_aead_encrypt_detached(lua_State *L) {
    unsigned char *c = NULL;
    unsigned char *mac = NULL;
    unsigned long long maclen = 0;

    const char *fname = NULL;
    ls_crypto_aead_encrypt_detached_ptr f = NULL;
    size_t KEYBYTES = 0;
    size_t NPUBBYTES = 0;
    size_t ABYTES = 0;

    const unsigned char *m = NULL;
    const unsigned char *ad = NULL;
    const unsigned char *npub = NULL;
    const unsigned char *k = NULL;
    size_t mlen = 0;
    size_t adlen = 0;
    size_t npublen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_aead_encrypt_detached_ptr)lua_touserdata(L,lua_upvalueindex(2));
    KEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    NPUBBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));
    ABYTES = (size_t)lua_tointeger(L,lua_upvalueindex(5));

    k    = (const unsigned char *)lua_tolstring(L,1,&klen);
    m    = (const unsigned char *)lua_tolstring(L,2,&mlen);
    npub = (const unsigned char *)lua_tolstring(L,3,&npublen);

    if(lua_isstring(L,4)) {
        ad = (const unsigned char *)lua_tolstring(L,4,&adlen);
    }

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key length, expected: %d",
          KEYBYTES);
    }

    if(npublen != NPUBBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NPUBBYTES);
    }

    c = lua_newuserdata(L, mlen);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    mac = lua_newuserdata(L, ABYTES);

    /* LCOV_EXCL_START */
    if(mac == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    f(c,mac,&maclen,m,(unsigned long long)mlen,
      ad,(unsigned long long)adlen,
      NULL,npub,k);

    lua_pushlstring(L,(const char *)c,mlen);
    lua_pushlstring(L,(const char *)mac,ABYTES);
    sodium_memzero(c, mlen);
    sodium_memzero(mac, ABYTES);
    (void)fname;
    return 2;
}

static int
ls_crypto_aead_decrypt_detached(lua_State *L) {
    unsigned char *m = NULL;

    const char *fname = NULL;
    ls_crypto_aead_decrypt_detached_ptr f = NULL;
    size_t KEYBYTES = 0;
    size_t NPUBBYTES = 0;
    size_t ABYTES = 0;

    const unsigned char *c = NULL;
    const unsigned char *mac = NULL;
    const unsigned char *ad = NULL;
    const unsigned char *npub = NULL;
    const unsigned char *k = NULL;
    size_t clen = 0;
    size_t maclen = 0;
    size_t adlen = 0;
    size_t npublen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,4)) {
        return luaL_error(L,"requires 4 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_aead_decrypt_detached_ptr)lua_touserdata(L,lua_upvalueindex(2));
    KEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    NPUBBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));
    ABYTES = (size_t)lua_tointeger(L,lua_upvalueindex(5));

    k    = (const unsigned char *)lua_tolstring(L,1,&klen);
    c    = (const unsigned char *)lua_tolstring(L,2,&clen);
    mac  = (const unsigned char *)lua_tolstring(L,3,&maclen);
    npub = (const unsigned char *)lua_tolstring(L,4,&npublen);

    if(lua_isstring(L,5)) {
        ad = (const unsigned char *)lua_tolstring(L,5,&adlen);
    }

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key length, expected: %d",
          KEYBYTES);
    }

    if(maclen != ABYTES) {
        return luaL_error(L,"wrong mac length, expected: %d",
          ABYTES);
    }

    if(npublen != NPUBBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NPUBBYTES);
    }

    m = lua_newuserdata(L, clen);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    if(f(m,NULL,c,(unsigned long long)clen,
      mac, ad,(unsigned long long)adlen,
      npub,k) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }

    lua_pushlstring(L,(const char *)m,clen);
    sodium_memzero(m, clen);
    return 1;
}

static int
ls_crypto_aead_beforenm__gc(lua_State *L) {
    void **state = (void **)lua_touserdata(L,1);
    if(*state != NULL) {
        sodium_free(*state);
        *state = NULL;
    }
    return 0;
}

static int
ls_crypto_aead_beforenm(lua_State *L) {
    void **state = NULL;

    const char *fname = NULL;
    ls_crypto_aead_beforenm_ptr f = NULL;
    size_t STATEBYTES = 0;
    size_t KEYBYTES = 0;

    const unsigned char *k = NULL;
    size_t klen = 0;

    fname = lua_tostring(L, lua_upvalueindex(1));
    f = (ls_crypto_aead_beforenm_ptr) lua_touserdata(L, lua_upvalueindex(2));
    STATEBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(3));
    KEYBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(4));

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    k = (const unsigned char *)lua_tolstring(L,1,&klen);

    if(klen != KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",
          KEYBYTES);
    }

    state = (void **)lua_newuserdata(L, sizeof(void *));

    /* LCOV_EXCL_START */
    if(state == NULL) {
        return luaL_error(L, "out of memory");
    }
    /* LCOV_EXCL_STOP */

    *state = NULL;
    *state = sodium_malloc(STATEBYTES);

    /* LCOV_EXCL_START */
    if(*state == NULL) {
        return luaL_error(L, "out of memory");
    }
    /* LCOV_EXCL_STOP */

    f(*state, k);

    lua_pushvalue(L,lua_upvalueindex(5));
    lua_setmetatable(L,-2);

    (void)fname;

    return 1;
}

static int
ls_crypto_aead_encrypt_afternm(lua_State *L) {
    unsigned char *c = NULL;
    unsigned long long clen = 0;

    const char *fname = NULL;
    ls_crypto_aead_encrypt_afternm_ptr f = NULL;
    size_t NPUBBYTES = 0;
    size_t ABYTES = 0;

    void **ctx = NULL;
    const unsigned char *m = NULL;
    const unsigned char *ad = NULL;
    const unsigned char *npub = NULL;
    size_t mlen = 0;
    size_t adlen = 0;
    size_t npublen = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    /* verify first parameter is a ctx object */
    lua_pushvalue(L, lua_upvalueindex(5));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_aead_encrypt_afternm_ptr)lua_touserdata(L,lua_upvalueindex(2));
    NPUBBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    ABYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));

    ctx  = (void **)lua_touserdata(L,1);
    m    = (const unsigned char *)lua_tolstring(L,2,&mlen);
    npub = (const unsigned char *)lua_tolstring(L,3,&npublen);

    if(lua_isstring(L,4)) {
        ad = (const unsigned char *)lua_tolstring(L,4,&adlen);
    }

    if(npublen != NPUBBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NPUBBYTES);
    }

    clen = mlen + ABYTES;
    c = lua_newuserdata(L, clen);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    f(c,&clen,m,(unsigned long long)mlen,
      ad,(unsigned long long)adlen,
      NULL,npub,*ctx);

    lua_pushlstring(L,(const char *)c,clen);
    sodium_memzero(c, mlen + ABYTES);
    (void)fname;
    return 1;
}

static int
ls_crypto_aead_decrypt_afternm(lua_State *L) {
    unsigned char *m = NULL;
    unsigned long long mlen = 0;

    const char *fname = NULL;
    ls_crypto_aead_decrypt_afternm_ptr f = NULL;
    size_t NPUBBYTES = 0;
    size_t ABYTES = 0;

    void **ctx = NULL;
    const unsigned char *c = NULL;
    const unsigned char *ad = NULL;
    const unsigned char *npub = NULL;
    size_t clen = 0;
    size_t adlen = 0;
    size_t npublen = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    /* verify first parameter is a ctx object */
    lua_pushvalue(L, lua_upvalueindex(5));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_aead_decrypt_afternm_ptr)lua_touserdata(L,lua_upvalueindex(2));
    NPUBBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    ABYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));

    ctx  = (void **)lua_touserdata(L,1);
    c    = (const unsigned char *)lua_tolstring(L,2,&clen);
    npub = (const unsigned char *)lua_tolstring(L,3,&npublen);

    if(lua_isstring(L,4)) {
        ad = (const unsigned char *)lua_tolstring(L,4,&adlen);
    }

    if(clen < ABYTES) {
        return luaL_error(L,"wrong cipher length, expected at least: %d",
          ABYTES);
    }

    if(npublen != NPUBBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NPUBBYTES);
    }

    mlen = clen - ABYTES;
    m = lua_newuserdata(L, mlen);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    if(f(m,&mlen,NULL,c,(unsigned long long)clen,
      ad,(unsigned long long)adlen,
      npub,*ctx) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }

    lua_pushlstring(L,(const char *)m,mlen);
    sodium_memzero(m, clen - ABYTES);
    return 1;
}

static int
ls_crypto_aead_encrypt_detached_afternm(lua_State *L) {
    unsigned char *c = NULL;
    unsigned char *mac = NULL;
    unsigned long long maclen = 0;

    const char *fname = NULL;
    ls_crypto_aead_encrypt_detached_afternm_ptr f = NULL;
    size_t NPUBBYTES = 0;
    size_t ABYTES = 0;

    void **ctx = NULL;
    const unsigned char *m = NULL;
    const unsigned char *ad = NULL;
    const unsigned char *npub = NULL;
    size_t mlen = 0;
    size_t adlen = 0;
    size_t npublen = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    /* verify first parameter is a ctx object */
    lua_pushvalue(L, lua_upvalueindex(5));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_aead_encrypt_detached_afternm_ptr)lua_touserdata(L,lua_upvalueindex(2));
    NPUBBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    ABYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));

    ctx  = (void **)lua_touserdata(L,1);
    m    = (const unsigned char *)lua_tolstring(L,2,&mlen);
    npub = (const unsigned char *)lua_tolstring(L,3,&npublen);

    if(lua_isstring(L,4)) {
        ad = (const unsigned char *)lua_tolstring(L,4,&adlen);
    }

    if(npublen != NPUBBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NPUBBYTES);
    }

    c = lua_newuserdata(L, mlen);

    /* LCOV_EXCL_START */
    if(c == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    mac = lua_newuserdata(L, ABYTES);

    /* LCOV_EXCL_START */
    if(mac == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    f(c,mac,&maclen,m,(unsigned long long)mlen,
      ad,(unsigned long long)adlen,
      NULL,npub,*ctx);

    lua_pushlstring(L,(const char *)c,mlen);
    lua_pushlstring(L,(const char *)mac,ABYTES);
    sodium_memzero(c, mlen);
    sodium_memzero(mac, ABYTES);
    (void)fname;
    return 2;
}

static int
ls_crypto_aead_decrypt_detached_afternm(lua_State *L) {
    unsigned char *m = NULL;

    const char *fname = NULL;
    ls_crypto_aead_decrypt_detached_ptr f = NULL;
    size_t NPUBBYTES = 0;
    size_t ABYTES = 0;

    void **ctx = NULL;
    const unsigned char *c = NULL;
    const unsigned char *mac = NULL;
    const unsigned char *ad = NULL;
    const unsigned char *npub = NULL;
    size_t clen = 0;
    size_t maclen = 0;
    size_t adlen = 0;
    size_t npublen = 0;

    if(lua_isnoneornil(L,4)) {
        return luaL_error(L,"requires 4 parameters");
    }

    /* verify first parameter is a ctx object */
    lua_pushvalue(L, lua_upvalueindex(5));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_aead_decrypt_detached_ptr)lua_touserdata(L,lua_upvalueindex(2));
    NPUBBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    ABYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));

    ctx  = (void **)lua_touserdata(L,1);
    c    = (const unsigned char *)lua_tolstring(L,2,&clen);
    mac  = (const unsigned char *)lua_tolstring(L,3,&maclen);
    npub = (const unsigned char *)lua_tolstring(L,4,&npublen);

    if(lua_isstring(L,5)) {
        ad = (const unsigned char *)lua_tolstring(L,5,&adlen);
    }

    if(maclen != ABYTES) {
        return luaL_error(L,"wrong mac length, expected: %d",
          ABYTES);
    }

    if(npublen != NPUBBYTES) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          NPUBBYTES);
    }

    m = lua_newuserdata(L, clen);

    /* LCOV_EXCL_START */
    if(m == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    if(f(m,NULL,c,(unsigned long long)clen,
      mac, ad,(unsigned long long)adlen,
      npub,*ctx) == -1) {
        lua_pushnil(L);
        lua_pushfstring(L,"%s error",fname);
        return 2;
    }

    lua_pushlstring(L,(const char *)m,clen);
    sodium_memzero(m, clen);
    return 1;
}

static void
ls_crypto_aead_precomp(lua_State *L,
  size_t STATEBYTES,
  size_t KEYBYTES,
  size_t NPUBBYTES,
  size_t ABYTES,
  const char *beforenm_name,
  ls_crypto_aead_beforenm_ptr beforenm_ptr,
  const char *encrypt_afternm_name,
  ls_crypto_aead_encrypt_afternm_ptr encrypt_afternm_ptr,
  const char *decrypt_afternm_name,
  ls_crypto_aead_decrypt_afternm_ptr decrypt_afternm_ptr,
  const char *encrypt_detached_afternm_name,
  ls_crypto_aead_encrypt_detached_afternm_ptr encrypt_detached_afternm_ptr,
  const char *decrypt_detached_afternm_name,
  ls_crypto_aead_decrypt_detached_afternm_ptr decrypt_detached_afternm_ptr) {

    int module_index = 0;
    int metatable_index = 0;

    module_index = lua_gettop(L);

    lua_newtable(L); /* metatable */
    metatable_index = lua_gettop(L);

    lua_pushstring(L,beforenm_name);
    lua_pushlightuserdata(L,beforenm_ptr);
    lua_pushinteger(L,STATEBYTES);
    lua_pushinteger(L,KEYBYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_aead_beforenm,5);
    lua_setfield(L,module_index,beforenm_name);

    lua_pushstring(L,encrypt_afternm_name);
    lua_pushlightuserdata(L,encrypt_afternm_ptr);
    lua_pushinteger(L,NPUBBYTES);
    lua_pushinteger(L,ABYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_aead_encrypt_afternm,5);
    lua_setfield(L,module_index,encrypt_afternm_name);

    lua_pushstring(L,decrypt_afternm_name);
    lua_pushlightuserdata(L,decrypt_afternm_ptr);
    lua_pushinteger(L,NPUBBYTES);
    lua_pushinteger(L,ABYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_aead_decrypt_afternm,5);
    lua_setfield(L,module_index,decrypt_afternm_name);

    lua_pushstring(L,encrypt_detached_afternm_name);
    lua_pushlightuserdata(L,encrypt_detached_afternm_ptr);
    lua_pushinteger(L,NPUBBYTES);
    lua_pushinteger(L,ABYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_aead_encrypt_detached_afternm,5);
    lua_setfield(L,module_index,encrypt_detached_afternm_name);

    lua_pushstring(L,decrypt_detached_afternm_name);
    lua_pushlightuserdata(L,decrypt_detached_afternm_ptr);
    lua_pushinteger(L,NPUBBYTES);
    lua_pushinteger(L,ABYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_aead_decrypt_detached_afternm,5);
    lua_setfield(L,module_index,decrypt_detached_afternm_name);

    lua_pushinteger(L,STATEBYTES);
    lua_pushcclosure(L,ls_crypto_aead_beforenm__gc,1);
    lua_setfield(L,metatable_index,"__gc");

    lua_newtable(L);
    lua_getfield(L,module_index,encrypt_afternm_name);
    lua_setfield(L,-2,"encrypt");
    lua_getfield(L,module_index,decrypt_afternm_name);
    lua_setfield(L,-2,"decrypt");
    lua_getfield(L,module_index,encrypt_detached_afternm_name);
    lua_setfield(L,-2,"encrypt_detached");
    lua_getfield(L,module_index,decrypt_detached_afternm_name);
    lua_setfield(L,-2,"decrypt_detached");
    lua_setfield(L,-2,"__index");
    lua_pop(L,1);
}

#define LS_CRYPTO_AEAD_IS_AVAILABLE(x) \
  lua_pushlightuserdata(L, crypto_aead_ ## x ## _is_available); \
  lua_pushcclosure(L, ls_crypto_aead_is_available, 1); \
  lua_setfield(L,-2, "crypto_aead_" #x "_is_available")

#define LS_CRYPTO_AEAD_KEYGEN(x) \
  lua_pushlightuserdata(L, crypto_aead_ ## x ## _keygen); \
  lua_pushinteger(L, crypto_aead_ ## x ## _KEYBYTES); \
  lua_pushcclosure(L, ls_crypto_aead_keygen, 2); \
  lua_setfield(L,-2, "crypto_aead_" #x "_keygen")

#define LS_CRYPTO_AEAD_ENCRYPT(x) \
  lua_pushliteral(L, "crypto_aead_" #x "_encrypt"); \
  lua_pushlightuserdata(L, crypto_aead_ ## x ## _encrypt); \
  lua_pushinteger(L, crypto_aead_ ## x ## _KEYBYTES); \
  lua_pushinteger(L, crypto_aead_ ## x ## _NPUBBYTES); \
  lua_pushinteger(L, crypto_aead_ ## x ## _ABYTES); \
  lua_pushcclosure(L, ls_crypto_aead_encrypt, 5); \
  lua_setfield(L,-2, "crypto_aead_" #x "_encrypt")

#define LS_CRYPTO_AEAD_DECRYPT(x) \
  lua_pushliteral(L, "crypto_aead_" #x "_decrypt"); \
  lua_pushlightuserdata(L, crypto_aead_ ## x ## _decrypt); \
  lua_pushinteger(L, crypto_aead_ ## x ## _KEYBYTES); \
  lua_pushinteger(L, crypto_aead_ ## x ## _NPUBBYTES); \
  lua_pushinteger(L, crypto_aead_ ## x ## _ABYTES); \
  lua_pushcclosure(L, ls_crypto_aead_decrypt, 5); \
  lua_setfield(L,-2, "crypto_aead_" #x "_decrypt")

#define LS_CRYPTO_AEAD_ENCRYPT_DETACHED(x) \
  lua_pushliteral(L, "crypto_aead_" #x "_encrypt_detached"); \
  lua_pushlightuserdata(L, crypto_aead_ ## x ## _encrypt_detached); \
  lua_pushinteger(L, crypto_aead_ ## x ## _KEYBYTES); \
  lua_pushinteger(L, crypto_aead_ ## x ## _NPUBBYTES); \
  lua_pushinteger(L, crypto_aead_ ## x ## _ABYTES); \
  lua_pushcclosure(L, ls_crypto_aead_encrypt_detached, 5); \
  lua_setfield(L,-2, "crypto_aead_" #x "_encrypt_detached")

#define LS_CRYPTO_AEAD_DECRYPT_DETACHED(x) \
  lua_pushliteral(L, "crypto_aead_" #x "_decrypt_detached"); \
  lua_pushlightuserdata(L, crypto_aead_ ## x ## _decrypt_detached); \
  lua_pushinteger(L, crypto_aead_ ## x ## _KEYBYTES); \
  lua_pushinteger(L, crypto_aead_ ## x ## _NPUBBYTES); \
  lua_pushinteger(L, crypto_aead_ ## x ## _ABYTES); \
  lua_pushcclosure(L, ls_crypto_aead_decrypt_detached, 5); \
  lua_setfield(L,-2, "crypto_aead_" #x "_decrypt_detached")

#define LS_CRYPTO_AEAD_PRECOMP(x) \
  ls_crypto_aead_precomp(L, \
    sizeof(crypto_aead_ ## x ## _state), \
    crypto_aead_ ## x ## _KEYBYTES, \
    crypto_aead_ ## x ## _NPUBBYTES, \
    crypto_aead_ ## x ## _ABYTES, \
    "crypto_aead_" #x "_beforenm", \
    (ls_crypto_aead_beforenm_ptr) crypto_aead_ ## x ## _beforenm, \
    "crypto_aead_" #x "_encrypt_afternm", \
    (ls_crypto_aead_encrypt_afternm_ptr) crypto_aead_ ## x ## _encrypt_afternm, \
    "crypto_aead_" #x "_decrypt_afternm", \
    (ls_crypto_aead_decrypt_afternm_ptr) crypto_aead_ ## x ## _decrypt_afternm, \
    "crypto_aead_" #x "_encrypt_detached_afternm", \
    (ls_crypto_aead_encrypt_detached_afternm_ptr) crypto_aead_ ## x ## _encrypt_detached_afternm, \
    "crypto_aead_" #x "_decrypt_detached_afternm", \
    (ls_crypto_aead_decrypt_detached_afternm_ptr) crypto_aead_ ## x ## _decrypt_detached_afternm)

LS_PUBLIC
int luaopen_luasodium_crypto_aead_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_aead_constants,lua_gettop(L));

    LS_CRYPTO_AEAD_IS_AVAILABLE(aes256gcm);

    LS_CRYPTO_AEAD_KEYGEN(chacha20poly1305);
    LS_CRYPTO_AEAD_KEYGEN(chacha20poly1305_ietf);
    LS_CRYPTO_AEAD_KEYGEN(xchacha20poly1305_ietf);
    LS_CRYPTO_AEAD_KEYGEN(aes256gcm);

    LS_CRYPTO_AEAD_ENCRYPT(chacha20poly1305);
    LS_CRYPTO_AEAD_ENCRYPT(chacha20poly1305_ietf);
    LS_CRYPTO_AEAD_ENCRYPT(xchacha20poly1305_ietf);
    LS_CRYPTO_AEAD_ENCRYPT(aes256gcm);

    LS_CRYPTO_AEAD_DECRYPT(chacha20poly1305);
    LS_CRYPTO_AEAD_DECRYPT(chacha20poly1305_ietf);
    LS_CRYPTO_AEAD_DECRYPT(xchacha20poly1305_ietf);
    LS_CRYPTO_AEAD_DECRYPT(aes256gcm);

    LS_CRYPTO_AEAD_ENCRYPT_DETACHED(chacha20poly1305);
    LS_CRYPTO_AEAD_ENCRYPT_DETACHED(chacha20poly1305_ietf);
    LS_CRYPTO_AEAD_ENCRYPT_DETACHED(xchacha20poly1305_ietf);
    LS_CRYPTO_AEAD_ENCRYPT_DETACHED(aes256gcm);

    LS_CRYPTO_AEAD_DECRYPT_DETACHED(chacha20poly1305);
    LS_CRYPTO_AEAD_DECRYPT_DETACHED(chacha20poly1305_ietf);
    LS_CRYPTO_AEAD_DECRYPT_DETACHED(xchacha20poly1305_ietf);
    LS_CRYPTO_AEAD_DECRYPT_DETACHED(aes256gcm);

    LS_CRYPTO_AEAD_PRECOMP(aes256gcm);

    return 1;
}

