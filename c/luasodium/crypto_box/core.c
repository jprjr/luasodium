#include "../luasodium-c.h"
#include "constants.h"

#define str(x) #x

typedef int (*keypair_func)(unsigned char *, unsigned char *);

typedef int (*seed_keypair_func)(unsigned char *, unsigned char *,
                   const unsigned char *);

typedef int (*crypto_box_func)(unsigned char *c, const unsigned char *m,
                 unsigned long long mlen, const unsigned char *n,
                 const unsigned char *pk, const unsigned char *sk);

typedef int (*crypto_box_detached_func)(unsigned char *c, unsigned char *mac,
                          const unsigned char *m,
                          unsigned long long mlen,
                          const unsigned char *n,
                          const unsigned char *pk,
                          const unsigned char *sk);

typedef int (*crypto_box_open_detached_func)(unsigned char *m,
                               const unsigned char *c,
                               const unsigned char *mac,
                               unsigned long long clen,
                               const unsigned char *n,
                               const unsigned char *pk,
                               const unsigned char *sk);

typedef int (*crypto_box_beforenm_func)(unsigned char *k, const unsigned char *pk,
                          const unsigned char *sk);

typedef int (*crypto_box_easy_afternm_func)(unsigned char *c, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *n,
                              const unsigned char *k);

typedef int (*crypto_box_detached_afternm_func)(unsigned char *c, unsigned char *mac,
                                  const unsigned char *m, unsigned long long mlen,
                                  const unsigned char *n, const unsigned char *k);

typedef int (*crypto_box_open_detached_afternm_func)(unsigned char *m, const unsigned char *c,
                                       const unsigned char *mac,
                                       unsigned long long clen, const unsigned char *n,
                                       const unsigned char *k);

struct keypair_func_def_s {
    const char *name;
    keypair_func func;
    size_t pksize;
    size_t sksize;
};

struct seed_keypair_func_def_s {
    const char *name;
    seed_keypair_func func;
    size_t pksize;
    size_t sksize;
    size_t seedsize;
};

struct crypto_box_func_def_s {
    const char *name;
    crypto_box_func func;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
    size_t inputzerobytes;
    size_t outputzerobytes;
};

struct crypto_box_open_func_def_s {
    const char *name;
    crypto_box_func func;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
    size_t inputzerobytes;
    size_t outputzeroerobytes;
};

struct crypto_box_easy_func_def_s {
    const char *name;
    crypto_box_func func;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
};

struct crypto_box_open_easy_func_def_s {
    const char *name;
    crypto_box_func func;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
};

struct crypto_box_detached_func_def_s {
    const char *name;
    crypto_box_detached_func func;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
};

struct crypto_box_open_detached_func_def_s {
    const char *name;
    crypto_box_open_detached_func func;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
};

struct crypto_box_beforenm_func_def_s {
    const char *name;
    crypto_box_beforenm_func func;
    size_t ksize;
    size_t pksize;
    size_t sksize;
};

struct crypto_box_easy_afternm_func_def_s {
    const char *name;
    crypto_box_easy_afternm_func func;
    size_t noncesize;
    size_t macsize;
    size_t ksize;
};

struct crypto_box_open_easy_afternm_func_def_s {
    const char *name;
    crypto_box_easy_afternm_func func;
    size_t noncesize;
    size_t macsize;
    size_t ksize;
};

struct crypto_box_detached_afternm_func_def_s {
    const char *name;
    crypto_box_detached_afternm_func func;
    size_t noncesize;
    size_t macsize;
    size_t ksize;
};

struct crypto_box_open_detached_afternm_func_def_s {
    const char *name;
    crypto_box_open_detached_afternm_func func;
    size_t noncesize;
    size_t macsize;
    size_t ksize;
};

typedef struct keypair_func_def_s keypair_func_def;
typedef struct seed_keypair_func_def_s seed_keypair_func_def;
typedef struct crypto_box_func_def_s crypto_box_func_def;
typedef struct crypto_box_open_func_def_s crypto_box_open_func_def;
typedef struct crypto_box_easy_func_def_s crypto_box_easy_func_def;
typedef struct crypto_box_open_easy_func_def_s crypto_box_open_easy_func_def;
typedef struct crypto_box_detached_func_def_s crypto_box_detached_func_def;
typedef struct crypto_box_open_detached_func_def_s crypto_box_open_detached_func_def;

typedef struct crypto_box_beforenm_func_def_s crypto_box_beforenm_func_def;

typedef struct crypto_box_easy_afternm_func_def_s crypto_box_easy_afternm_func_def;
typedef struct crypto_box_open_easy_afternm_func_def_s crypto_box_open_easy_afternm_func_def;
typedef struct crypto_box_detached_afternm_func_def_s crypto_box_detached_afternm_func_def;
typedef struct crypto_box_open_detached_afternm_func_def_s crypto_box_open_detached_afternm_func_def;

static const keypair_func_def keypair_funcs[] = {
    {
        str(crypto_box_keypair),
        crypto_box_keypair,
        crypto_box_PUBLICKEYBYTES,
        crypto_box_SECRETKEYBYTES,
    },
    { NULL }
};

static const seed_keypair_func_def seed_keypair_funcs[] = {
    {
        str(crypto_box_seed_keypair),
        crypto_box_seed_keypair,
        crypto_box_PUBLICKEYBYTES,
        crypto_box_SECRETKEYBYTES,
        crypto_box_SEEDBYTES,
    },
    { NULL }
};

static const crypto_box_func_def crypto_box_funcs[] = {
    {
        str(crypto_box),
        crypto_box,
        crypto_box_NONCEBYTES,
        crypto_box_MACBYTES,
        crypto_box_PUBLICKEYBYTES,
        crypto_box_SECRETKEYBYTES,
        crypto_box_BOXZEROBYTES,
        crypto_box_ZEROBYTES,
    },
    { NULL }
};

static const crypto_box_open_func_def crypto_box_open_funcs[] = {
    {
        str(crypto_box_open),
        crypto_box_open,
        crypto_box_NONCEBYTES,
        crypto_box_MACBYTES,
        crypto_box_PUBLICKEYBYTES,
        crypto_box_SECRETKEYBYTES,
        crypto_box_ZEROBYTES,
        crypto_box_BOXZEROBYTES,
    },
    { NULL }
};

static const crypto_box_easy_func_def crypto_box_easy_funcs[] = {
    {
        str(crypto_box_easy),
        crypto_box_easy,
        crypto_box_NONCEBYTES,
        crypto_box_MACBYTES,
        crypto_box_PUBLICKEYBYTES,
        crypto_box_SECRETKEYBYTES,
    },
    { NULL }
};

static const crypto_box_open_easy_func_def crypto_box_open_easy_funcs[] = {
    {
        str(crypto_box_open_easy),
        crypto_box_open_easy,
        crypto_box_NONCEBYTES,
        crypto_box_MACBYTES,
        crypto_box_PUBLICKEYBYTES,
        crypto_box_SECRETKEYBYTES,
    },
    { NULL }
};

static const crypto_box_detached_func_def crypto_box_detached_funcs[] = {
    {
        str(crypto_box_detached),
        crypto_box_detached,
        crypto_box_NONCEBYTES,
        crypto_box_MACBYTES,
        crypto_box_PUBLICKEYBYTES,
        crypto_box_SECRETKEYBYTES,
    },
    { NULL }
};

static const crypto_box_open_detached_func_def crypto_box_open_detached_funcs[] = {
    {
        str(crypto_box_open_detached),
        crypto_box_open_detached,
        crypto_box_NONCEBYTES,
        crypto_box_MACBYTES,
        crypto_box_PUBLICKEYBYTES,
        crypto_box_SECRETKEYBYTES,
    },
    { NULL }
};

static const crypto_box_beforenm_func_def crypto_box_beforenm_funcs[] = {
    {
        str(crypto_box_beforenm),
        crypto_box_beforenm,
        crypto_box_BEFORENMBYTES,
        crypto_box_PUBLICKEYBYTES,
        crypto_box_SECRETKEYBYTES,
    },
    { NULL }
};

static const crypto_box_easy_afternm_func_def crypto_box_easy_afternm_funcs[] = {
    {
        str(crypto_box_easy_afternm),
        crypto_box_easy_afternm,
        crypto_box_NONCEBYTES,
        crypto_box_MACBYTES,
        crypto_box_BEFORENMBYTES,
    },
    { NULL }
};

static const crypto_box_open_easy_afternm_func_def crypto_box_open_easy_afternm_funcs[] = {
    {
        str(crypto_box_open_easy_afternm),
        crypto_box_open_easy_afternm,
        crypto_box_NONCEBYTES,
        crypto_box_MACBYTES,
        crypto_box_BEFORENMBYTES,
    },
    { NULL }
};

static const crypto_box_detached_afternm_func_def crypto_box_detached_afternm_funcs[] = {
    {
        str(crypto_box_detached_afternm),
        crypto_box_detached_afternm,
        crypto_box_NONCEBYTES,
        crypto_box_MACBYTES,
        crypto_box_BEFORENMBYTES,
    },
    { NULL }
};

static const crypto_box_open_detached_afternm_func_def crypto_box_open_detached_afternm_funcs[] = {
    {
        str(crypto_box_open_detached_afternm),
        crypto_box_open_detached_afternm,
        crypto_box_NONCEBYTES,
        crypto_box_MACBYTES,
        crypto_box_BEFORENMBYTES,
    },
    { NULL }
};

static int
lua_crypto_box_keypair(lua_State *L) {
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;

    const char *fname = NULL;
    keypair_func func = NULL;
    size_t pksize = 0;
    size_t sksize = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    func  = (keypair_func) lua_touserdata(L, lua_upvalueindex(2));
    pksize = lua_tointeger(L,lua_upvalueindex(3));
    sksize = lua_tointeger(L,lua_upvalueindex(4));

    pk = lua_newuserdata(L,pksize);
    if(pk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }

    sk = lua_newuserdata(L,sksize);
    if(sk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }

    lua_pop(L,2);

    if(func(pk,sk) == -1) {
        lua_pushliteral(L,"crypto_box_keypair error");
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)pk,pksize);
    lua_pushlstring(L,(const char *)sk,sksize);

    sodium_memzero(pk,pksize);
    sodium_memzero(sk,sksize);

    return 2;
}

static int
lua_crypto_box_seed_keypair(lua_State *L) {
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;
    const unsigned char *seed = NULL;
    size_t seed_len = 0;

    const char *fname = NULL;
    seed_keypair_func func = NULL;
    size_t pksize = 0;
    size_t sksize = 0;
    size_t seedsize = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    func  = (seed_keypair_func) lua_touserdata(L, lua_upvalueindex(2));
    pksize = lua_tointeger(L,lua_upvalueindex(3));
    sksize = lua_tointeger(L,lua_upvalueindex(4));
    seedsize = lua_tointeger(L,lua_upvalueindex(5));

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"requires 1 argument");
        return lua_error(L);
    }

    seed = (const unsigned char *)lua_tolstring(L,1,&seed_len);

    if(seed_len != seedsize) {
        return luaL_error(L,"wrong seed length, expected: %d",
          seedsize);
    }

    pk = lua_newuserdata(L,pksize);
    if(pk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    sk = lua_newuserdata(L,sksize);
    if(sk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(func(pk,sk,seed) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    lua_pushlstring(L,(const char *)pk,pksize);
    lua_pushlstring(L,(const char *)sk,sksize);

    sodium_memzero(pk,pksize);
    sodium_memzero(sk,sksize);

    return 2;
}

static int
lua_crypto_box_easy(lua_State *L) {
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
    crypto_box_func func = NULL;
    size_t noncesize = 0;
    size_t macsize = 0;
    size_t pksize = 0;
    size_t sksize = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    func  = (crypto_box_func) lua_touserdata(L, lua_upvalueindex(2));
    noncesize = lua_tointeger(L,lua_upvalueindex(3));
    macsize = lua_tointeger(L,lua_upvalueindex(4));
    pksize = lua_tointeger(L,lua_upvalueindex(5));
    sksize = lua_tointeger(L,lua_upvalueindex(6));

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(nlen != noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          noncesize);
    }

    if(pklen != pksize) {
        return luaL_error(L,"wrong public key length, expected: %d",
          pksize);
    }

    if(sklen != sksize) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          sksize);
    }

    clen = mlen + macsize;

    c = lua_newuserdata(L,clen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(func(c,m,mlen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error", fname);
    }

    lua_pushlstring(L,(const char *)c,clen);
    sodium_memzero(c,clen);
    return 1;
}

static int
lua_crypto_box_open_easy(lua_State *L) {
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
    crypto_box_func func = NULL;
    size_t noncesize = 0;
    size_t macsize = 0;
    size_t pksize = 0;
    size_t sksize = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    func  = (crypto_box_func) lua_touserdata(L, lua_upvalueindex(2));
    noncesize = lua_tointeger(L,lua_upvalueindex(3));
    macsize = lua_tointeger(L,lua_upvalueindex(4));
    pksize = lua_tointeger(L,lua_upvalueindex(5));
    sksize = lua_tointeger(L,lua_upvalueindex(6));

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    c  = (const unsigned char *)lua_tolstring(L,1,&clen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(clen < macsize) {
        return luaL_error(L,"wrong cipher length, expected at least: %d",
          macsize);
    }

    if(nlen != noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          noncesize);
    }

    if(pklen != pksize) {
        return luaL_error(L,"wrong public key length, expected: %d",
          pksize);
    }

    if(sklen != sksize) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          sksize);
    }

    mlen = clen - macsize;
    if(mlen == 0) {
        lua_pushliteral(L,"");
        return 1;
    }

    m = lua_newuserdata(L,mlen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(func(m,c,clen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)m,mlen);
    sodium_memzero(m,mlen);
    return 1;
}

static int
lua_crypto_box_detached(lua_State *L) {
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
    crypto_box_detached_func func = NULL;
    size_t noncesize = 0;
    size_t macsize = 0;
    size_t pksize = 0;
    size_t sksize = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    func  = (crypto_box_detached_func) lua_touserdata(L, lua_upvalueindex(2));
    noncesize = lua_tointeger(L,lua_upvalueindex(3));
    macsize = lua_tointeger(L,lua_upvalueindex(4));
    pksize = lua_tointeger(L,lua_upvalueindex(5));
    sksize = lua_tointeger(L,lua_upvalueindex(6));

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(nlen != noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          noncesize);
    }

    if(pklen != pksize) {
        return luaL_error(L,"wrong public key length, expected: %d",
          pksize);
    }

    if(sklen != sksize) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          sksize);
    }

    c = lua_newuserdata(L,mlen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    mac = lua_newuserdata(L,macsize);
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(func(c,mac,m,mlen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)c,mlen);
    lua_pushlstring(L,(const char *)mac,macsize);

    sodium_memzero(c,mlen);
    sodium_memzero(mac,macsize);
    return 2;
}

static int
lua_crypto_box_open_detached(lua_State *L) {
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
    crypto_box_open_detached_func func = NULL;
    size_t noncesize = 0;
    size_t macsize = 0;
    size_t pksize = 0;
    size_t sksize = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    func  = (crypto_box_open_detached_func) lua_touserdata(L, lua_upvalueindex(2));
    noncesize = lua_tointeger(L,lua_upvalueindex(3));
    macsize = lua_tointeger(L,lua_upvalueindex(4));
    pksize = lua_tointeger(L,lua_upvalueindex(5));
    sksize = lua_tointeger(L,lua_upvalueindex(6));

    if(lua_isnoneornil(L,5)) {
        lua_pushliteral(L,"requires 5 arguments");
        return lua_error(L);
    }

    c   = (const unsigned char *)lua_tolstring(L,1,&clen);
    mac = (const unsigned char *)lua_tolstring(L,2,&maclen);
    n   = (const unsigned char *)lua_tolstring(L,3,&nlen);
    pk  = (const unsigned char *)lua_tolstring(L,4,&pklen);
    sk  = (const unsigned char *)lua_tolstring(L,5,&sklen);

    if(maclen != macsize) {
        return luaL_error(L,"wrong mac length, expected: %d",
          macsize);
    }

    if(nlen != noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          noncesize);
    }

    if(pklen != pksize) {
        return luaL_error(L,"wrong public key length, expected: %d",
          pksize);
    }

    if(sklen != sksize) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          sksize);
    }

    if(clen == 0) {
        lua_pushliteral(L,"");
        return 1;
    }

    m = lua_newuserdata(L,clen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(func(m,c,mac,clen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)m,clen);

    sodium_memzero(m,clen);

    return 1;
}

static int
lua_crypto_box_beforenm(lua_State *L) {
    unsigned char *k = NULL;
    const unsigned char *pk = NULL;
    const unsigned char *sk = NULL;

    size_t pklen = 0;
    size_t sklen = 0;

    const char *fname = NULL;
    crypto_box_beforenm_func func = NULL;
    size_t ksize = 0;
    size_t pksize = 0;
    size_t sksize = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    func  = (crypto_box_beforenm_func) lua_touserdata(L, lua_upvalueindex(2));
    ksize = lua_tointeger(L,lua_upvalueindex(3));
    pksize = lua_tointeger(L,lua_upvalueindex(4));
    sksize = lua_tointeger(L,lua_upvalueindex(5));

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    pk  = (const unsigned char *)lua_tolstring(L,1,&pklen);
    sk  = (const unsigned char *)lua_tolstring(L,2,&sklen);

    if(pklen != pksize) {
        return luaL_error(L,"wrong public key length, expected: %d",
          pksize);
    }

    if(sklen != sksize) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          sksize);
    }

    k = lua_newuserdata(L,ksize);
    if(k == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }

    if(func(k,pk,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)k,ksize);
    sodium_memzero(k,ksize);
    return 1;
}

static int
lua_crypto_box_easy_afternm(lua_State *L) {
    unsigned char *c = NULL;
    const unsigned char *m = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;
    size_t clen = 0;
    size_t mlen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    const char *fname = NULL;
    crypto_box_easy_afternm_func func = NULL;
    size_t noncesize = 0;
    size_t macsize = 0;
    size_t ksize = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    func  = (crypto_box_easy_afternm_func) lua_touserdata(L, lua_upvalueindex(2));
    noncesize = lua_tointeger(L,lua_upvalueindex(3));
    macsize = lua_tointeger(L,lua_upvalueindex(4));
    ksize = lua_tointeger(L,lua_upvalueindex(5));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          noncesize);
    }

    if(klen != ksize) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          ksize);
    }

    clen = mlen + macsize;

    c = lua_newuserdata(L,clen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(func(c,m,mlen,n,k) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)c,clen);
    sodium_memzero(c,clen);
    return 1;
}

static int
lua_crypto_box_open_easy_afternm(lua_State *L) {
    unsigned char *m = NULL;
    const unsigned char *c = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;
    size_t mlen = 0;
    size_t clen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    const char *fname = NULL;
    crypto_box_easy_afternm_func func = NULL;
    size_t noncesize = 0;
    size_t macsize = 0;
    size_t ksize = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    func  = (crypto_box_easy_afternm_func) lua_touserdata(L, lua_upvalueindex(2));
    noncesize = lua_tointeger(L,lua_upvalueindex(3));
    macsize = lua_tointeger(L,lua_upvalueindex(4));
    ksize = lua_tointeger(L,lua_upvalueindex(5));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    c  = (const unsigned char *)lua_tolstring(L,1,&clen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(clen < macsize) {
        return luaL_error(L,"wrong cipher length, expected at least: %d",
          macsize);
    }

    if(nlen != noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          noncesize);
    }

    if(klen != ksize) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          ksize);
    }

    mlen = clen - macsize;
    if(mlen == 0) {
        lua_pushliteral(L,"");
        return 1;
    }

    m = lua_newuserdata(L,mlen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(func(m,c,clen,n,k) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)m,mlen);
    sodium_memzero(m,mlen);
    return 1;
}

static int
lua_crypto_box_detached_afternm(lua_State *L) {
    unsigned char *c = NULL;
    unsigned char *mac = NULL;
    const unsigned char *m = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;
    size_t mlen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    const char *fname = NULL;
    crypto_box_detached_afternm_func func = NULL;
    size_t noncesize = 0;
    size_t macsize = 0;
    size_t ksize = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    func  = (crypto_box_detached_afternm_func) lua_touserdata(L, lua_upvalueindex(2));
    noncesize = lua_tointeger(L,lua_upvalueindex(3));
    macsize = lua_tointeger(L,lua_upvalueindex(4));
    ksize = lua_tointeger(L,lua_upvalueindex(5));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          noncesize);
    }

    if(klen != ksize) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          ksize);
    }

    c = lua_newuserdata(L,mlen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    mac = lua_newuserdata(L,macsize);
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(func(c,mac,m,mlen,n,k) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)c,mlen);
    lua_pushlstring(L,(const char *)mac,macsize);

    sodium_memzero(c,mlen);
    sodium_memzero(mac,macsize);
    return 2;
}

static int
lua_crypto_box_open_detached_afternm(lua_State *L) {
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
    crypto_box_open_detached_afternm_func func = NULL;
    size_t noncesize = 0;
    size_t macsize = 0;
    size_t ksize = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    func  = (crypto_box_open_detached_afternm_func) lua_touserdata(L, lua_upvalueindex(2));
    noncesize = lua_tointeger(L,lua_upvalueindex(3));
    macsize = lua_tointeger(L,lua_upvalueindex(4));
    ksize = lua_tointeger(L,lua_upvalueindex(5));

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    c   = (const unsigned char *)lua_tolstring(L,1,&clen);
    mac = (const unsigned char *)lua_tolstring(L,2,&maclen);
    n   = (const unsigned char *)lua_tolstring(L,3,&nlen);
    k   = (const unsigned char *)lua_tolstring(L,4,&klen);

    if(maclen != macsize) {
        return luaL_error(L,"wrong mac length, expected: %d",
          macsize);
    }

    if(nlen != noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          noncesize);
    }

    if(klen != ksize) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          ksize);
    }

    if(clen == 0) {
        lua_pushliteral(L,"");
        return 1;
    }

    m = lua_newuserdata(L,clen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(func(m,c,mac,clen,n,k) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)m,clen);
    return 1;
}

static const struct luaL_Reg luasodium_box[] = {
    { NULL, NULL },
};

static void
push_crypto_box_keygen_closures(lua_State *L) {
    const keypair_func_def *f = keypair_funcs;
    for(; f->name != NULL; f++) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->func);
        lua_pushinteger(L,f->pksize);
        lua_pushinteger(L,f->sksize);
        lua_pushcclosure(L,lua_crypto_box_keypair,4);
        lua_setfield(L,-2,f->name);
    }
}

static void
push_crypto_box_seed_keygen_closures(lua_State *L) {
    const seed_keypair_func_def *f = seed_keypair_funcs;
    for(; f->name != NULL; f++) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->func);
        lua_pushinteger(L,f->pksize);
        lua_pushinteger(L,f->sksize);
        lua_pushinteger(L,f->seedsize);
        lua_pushcclosure(L,lua_crypto_box_seed_keypair,5);
        lua_setfield(L,-2,f->name);
    }
}

static void
push_crypto_box_easy_closures(lua_State *L) {
    const crypto_box_easy_func_def *f = crypto_box_easy_funcs;
    for(; f->name != NULL; f++) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->func);
        lua_pushinteger(L,f->noncesize);
        lua_pushinteger(L,f->macsize);
        lua_pushinteger(L,f->pksize);
        lua_pushinteger(L,f->sksize);
        lua_pushcclosure(L,lua_crypto_box_easy,6);
        lua_setfield(L,-2,f->name);
    }
}

static void
push_crypto_box_detached_closures(lua_State *L) {
    const crypto_box_detached_func_def *f = crypto_box_detached_funcs;
    for(; f->name != NULL; f++) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->func);
        lua_pushinteger(L,f->noncesize);
        lua_pushinteger(L,f->macsize);
        lua_pushinteger(L,f->pksize);
        lua_pushinteger(L,f->sksize);
        lua_pushcclosure(L,lua_crypto_box_detached,6);
        lua_setfield(L,-2,f->name);
    }
}

static void
push_crypto_box_open_easy_closures(lua_State *L) {
    const crypto_box_open_easy_func_def *f = crypto_box_open_easy_funcs;
    for(; f->name != NULL; f++) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->func);
        lua_pushinteger(L,f->noncesize);
        lua_pushinteger(L,f->macsize);
        lua_pushinteger(L,f->pksize);
        lua_pushinteger(L,f->sksize);
        lua_pushcclosure(L,lua_crypto_box_open_easy,6);
        lua_setfield(L,-2,f->name);
    }
}

static void
push_crypto_box_open_detached_closures(lua_State *L) {
    const crypto_box_open_detached_func_def *f = crypto_box_open_detached_funcs;
    for(; f->name != NULL; f++) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->func);
        lua_pushinteger(L,f->noncesize);
        lua_pushinteger(L,f->macsize);
        lua_pushinteger(L,f->pksize);
        lua_pushinteger(L,f->sksize);
        lua_pushcclosure(L,lua_crypto_box_open_detached,6);
        lua_setfield(L,-2,f->name);
    }
}

static void
push_crypto_box_beforenm_closures(lua_State *L) {
    const crypto_box_beforenm_func_def *f = crypto_box_beforenm_funcs;
    for(; f->name != NULL; f++) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->func);
        lua_pushinteger(L,f->ksize);
        lua_pushinteger(L,f->pksize);
        lua_pushinteger(L,f->sksize);
        lua_pushcclosure(L,lua_crypto_box_beforenm,5);
        lua_setfield(L,-2,f->name);
    }
}

static void
push_crypto_box_easy_afternm_closures(lua_State *L) {
    const crypto_box_easy_afternm_func_def *f = crypto_box_easy_afternm_funcs;
    for(; f->name != NULL; f++) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->func);
        lua_pushinteger(L,f->noncesize);
        lua_pushinteger(L,f->macsize);
        lua_pushinteger(L,f->ksize);
        lua_pushcclosure(L,lua_crypto_box_easy_afternm,5);
        lua_setfield(L,-2,f->name);
    }
}

static void
push_crypto_box_open_easy_afternm_closures(lua_State *L) {
    const crypto_box_open_easy_afternm_func_def *f = crypto_box_open_easy_afternm_funcs;
    for(; f->name != NULL; f++) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->func);
        lua_pushinteger(L,f->noncesize);
        lua_pushinteger(L,f->macsize);
        lua_pushinteger(L,f->ksize);
        lua_pushcclosure(L,lua_crypto_box_open_easy_afternm,5);
        lua_setfield(L,-2,f->name);
    }
}

static void
push_crypto_box_detached_afternm_closures(lua_State *L) {
    const crypto_box_detached_afternm_func_def *f = crypto_box_detached_afternm_funcs;
    for(; f->name != NULL; f++) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->func);
        lua_pushinteger(L,f->noncesize);
        lua_pushinteger(L,f->macsize);
        lua_pushinteger(L,f->ksize);
        lua_pushcclosure(L,lua_crypto_box_detached_afternm,5);
        lua_setfield(L,-2,f->name);
    }
}

static void
push_crypto_box_open_detached_afternm_closures(lua_State *L) {
    const crypto_box_open_detached_afternm_func_def *f = crypto_box_open_detached_afternm_funcs;
    for(; f->name != NULL; f++) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->func);
        lua_pushinteger(L,f->noncesize);
        lua_pushinteger(L,f->macsize);
        lua_pushinteger(L,f->ksize);
        lua_pushcclosure(L,lua_crypto_box_open_detached_afternm,5);
        lua_setfield(L,-2,f->name);
    }
}

int luaopen_luasodium_crypto_box_core(lua_State *L) {
    LUASODIUM_INIT(L)
    lua_newtable(L);

    luaL_setfuncs(L,luasodium_box,0);
    luasodium_set_constants(L,luasodium_box_constants);

    push_crypto_box_keygen_closures(L);
    push_crypto_box_seed_keygen_closures(L);
    push_crypto_box_easy_closures(L);
    push_crypto_box_open_easy_closures(L);
    push_crypto_box_detached_closures(L);
    push_crypto_box_open_detached_closures(L);
    push_crypto_box_beforenm_closures(L);
    push_crypto_box_easy_afternm_closures(L);
    push_crypto_box_open_easy_afternm_closures(L);
    push_crypto_box_detached_afternm_closures(L);
    push_crypto_box_open_detached_afternm_closures(L);

    return 1;
}
