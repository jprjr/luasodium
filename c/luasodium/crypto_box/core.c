#include "../luasodium-c.h"
#include "constants.h"
#include "functions.h"


static int
lua_crypto_box_keypair(lua_State *L) {
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;

    const ls_crypto_box_keypair_func_def *def = NULL;
    def = (const ls_crypto_box_keypair_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    pk = lua_newuserdata(L,def->pksize);
    if(pk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }

    sk = lua_newuserdata(L,def->sksize);
    if(sk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }

    lua_pop(L,2);

    if(def->func(pk,sk) == -1) {
        lua_pushliteral(L,"crypto_box_keypair error");
        return luaL_error(L,"%s error",def->name);
    }

    lua_pushlstring(L,(const char *)pk,def->pksize);
    lua_pushlstring(L,(const char *)sk,def->sksize);

    sodium_memzero(pk,def->pksize);
    sodium_memzero(sk,def->sksize);

    return 2;
}

static int
lua_crypto_box_seed_keypair(lua_State *L) {
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;
    const unsigned char *seed = NULL;
    size_t seed_len = 0;

    const ls_crypto_box_seed_keypair_func_def *def = NULL;
    def = (const ls_crypto_box_seed_keypair_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"requires 1 argument");
        return lua_error(L);
    }

    seed = (const unsigned char *)lua_tolstring(L,1,&seed_len);

    if(seed_len != def->seedsize) {
        return luaL_error(L,"wrong seed length, expected: %d",
          def->seedsize);
    }

    pk = lua_newuserdata(L,def->pksize);
    if(pk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    sk = lua_newuserdata(L,def->sksize);
    if(sk == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(def->func(pk,sk,seed) == -1) {
        return luaL_error(L,"%s error",def->name);
    }
    lua_pushlstring(L,(const char *)pk,def->pksize);
    lua_pushlstring(L,(const char *)sk,def->sksize);

    sodium_memzero(pk,def->pksize);
    sodium_memzero(sk,def->sksize);

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

    const ls_crypto_box_easy_func_def *def = NULL;
    def = (const ls_crypto_box_easy_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(nlen != def->noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          def->noncesize);
    }

    if(pklen != def->pksize) {
        return luaL_error(L,"wrong public key length, expected: %d",
          def->pksize);
    }

    if(sklen != def->sksize) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          def->sksize);
    }

    clen = mlen + def->macsize;

    c = lua_newuserdata(L,clen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(def->func(c,m,mlen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error", def->name);
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

    const ls_crypto_box_open_easy_func_def *def = NULL;
    def = (const ls_crypto_box_open_easy_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    c  = (const unsigned char *)lua_tolstring(L,1,&clen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(clen <= def->macsize) {
        return luaL_error(L,"wrong cipher length, expected at least: %d",
          def->macsize);
    }

    if(nlen != def->noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          def->noncesize);
    }

    if(pklen != def->pksize) {
        return luaL_error(L,"wrong public key length, expected: %d",
          def->pksize);
    }

    if(sklen != def->sksize) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          def->sksize);
    }

    mlen = clen - def->macsize;

    m = lua_newuserdata(L,mlen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(def->func(m,c,clen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error",def->name);
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

    const ls_crypto_box_detached_func_def *def = NULL;
    def = (const ls_crypto_box_detached_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    pk = (const unsigned char *)lua_tolstring(L,3,&pklen);
    sk = (const unsigned char *)lua_tolstring(L,4,&sklen);

    if(nlen != def->noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          def->noncesize);
    }

    if(pklen != def->pksize) {
        return luaL_error(L,"wrong public key length, expected: %d",
          def->pksize);
    }

    if(sklen != def->sksize) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          def->sksize);
    }

    c = lua_newuserdata(L,mlen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    mac = lua_newuserdata(L,def->macsize);
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(def->func(c,mac,m,mlen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error", def->name);
    }

    lua_pushlstring(L,(const char *)c,mlen);
    lua_pushlstring(L,(const char *)mac,def->macsize);

    sodium_memzero(c,mlen);
    sodium_memzero(mac,def->macsize);
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

    const ls_crypto_box_open_detached_func_def *def = NULL;
    def = (const ls_crypto_box_open_detached_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,5)) {
        lua_pushliteral(L,"requires 5 arguments");
        return lua_error(L);
    }

    c   = (const unsigned char *)lua_tolstring(L,1,&clen);
    mac = (const unsigned char *)lua_tolstring(L,2,&maclen);
    n   = (const unsigned char *)lua_tolstring(L,3,&nlen);
    pk  = (const unsigned char *)lua_tolstring(L,4,&pklen);
    sk  = (const unsigned char *)lua_tolstring(L,5,&sklen);

    if(maclen != def->macsize) {
        return luaL_error(L,"wrong mac length, expected: %d",
          def->macsize);
    }

    if(nlen != def->noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          def->noncesize);
    }

    if(pklen != def->pksize) {
        return luaL_error(L,"wrong public key length, expected: %d",
          def->pksize);
    }

    if(sklen != def->sksize) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          def->sksize);
    }

    m = lua_newuserdata(L,clen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(def->func(m,c,mac,clen,n,pk,sk) == -1) {
        return luaL_error(L,"%s error", def->name);
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

    const ls_crypto_box_beforenm_func_def *def = NULL;
    def = (const ls_crypto_box_beforenm_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    pk  = (const unsigned char *)lua_tolstring(L,1,&pklen);
    sk  = (const unsigned char *)lua_tolstring(L,2,&sklen);

    if(pklen != def->pksize) {
        return luaL_error(L,"wrong public key length, expected: %d",
          def->pksize);
    }

    if(sklen != def->sksize) {
        return luaL_error(L,"wrong secret key length, expected: %d",
          def->sksize);
    }

    k = lua_newuserdata(L,def->ksize);
    if(k == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }

    if(def->func(k,pk,sk) == -1) {
        return luaL_error(L,"%s error", def->name);
    }

    lua_pushlstring(L,(const char *)k,def->ksize);
    sodium_memzero(k,def->ksize);
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

    const ls_crypto_box_easy_afternm_func_def *def = NULL;
    def = (const ls_crypto_box_easy_afternm_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != def->noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          def->noncesize);
    }

    if(klen != def->ksize) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          def->ksize);
    }

    clen = mlen + def->macsize;

    c = lua_newuserdata(L,clen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(def->func(c,m,mlen,n,k) == -1) {
        return luaL_error(L,"%s error", def->name);
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

    const ls_crypto_box_open_easy_afternm_func_def *def = NULL;
    def = (const ls_crypto_box_open_easy_afternm_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    c  = (const unsigned char *)lua_tolstring(L,1,&clen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(clen <= def->macsize) {
        return luaL_error(L,"wrong cipher length, expected at least: %d",
          def->macsize);
    }

    if(nlen != def->noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          def->noncesize);
    }

    if(klen != def->ksize) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          def->ksize);
    }

    mlen = clen - def->macsize;

    m = lua_newuserdata(L,mlen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(def->func(m,c,clen,n,k) == -1) {
        return luaL_error(L,"%s error", def->name);
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

    const ls_crypto_box_detached_afternm_func_def *def = NULL;
    def = (const ls_crypto_box_detached_afternm_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n  = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k  = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != def->noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          def->noncesize);
    }

    if(klen != def->ksize) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          def->ksize);
    }

    c = lua_newuserdata(L,mlen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    mac = lua_newuserdata(L,def->macsize);
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(def->func(c,mac,m,mlen,n,k) == -1) {
        return luaL_error(L,"%s error", def->name);
    }

    lua_pushlstring(L,(const char *)c,mlen);
    lua_pushlstring(L,(const char *)mac,def->macsize);

    sodium_memzero(c,mlen);
    sodium_memzero(mac,def->macsize);
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

    const ls_crypto_box_open_detached_afternm_func_def *def = NULL;
    def = (const ls_crypto_box_open_detached_afternm_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 arguments");
        return lua_error(L);
    }

    c   = (const unsigned char *)lua_tolstring(L,1,&clen);
    mac = (const unsigned char *)lua_tolstring(L,2,&maclen);
    n   = (const unsigned char *)lua_tolstring(L,3,&nlen);
    k   = (const unsigned char *)lua_tolstring(L,4,&klen);

    if(maclen != def->macsize) {
        return luaL_error(L,"wrong mac length, expected: %d",
          def->macsize);
    }

    if(nlen != def->noncesize) {
        return luaL_error(L,"wrong nonce length, expected: %d",
          def->noncesize);
    }

    if(klen != def->ksize) {
        return luaL_error(L,"wrong shared key length, expected: %d",
          def->ksize);
    }

    m = lua_newuserdata(L,clen);
    if(m == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(def->func(m,c,mac,clen,n,k) == -1) {
        return luaL_error(L,"%s error", def->name);
    }

    lua_pushlstring(L,(const char *)m,clen);
    return 1;
}

static const ls_crypto_box_keypair_func_def * const ls_crypto_box_keypair_funcs[] = {
    &ls_crypto_box_keypair_func,
    NULL,
};

static const ls_crypto_box_seed_keypair_func_def * const ls_crypto_box_seed_keypair_funcs[] = {
    &ls_crypto_box_seed_keypair_func,
    NULL,
};

static const ls_crypto_box_func_def * const ls_crypto_box_funcs[] = {
    &ls_crypto_box_func,
    NULL,
};

static const ls_crypto_box_open_func_def * const ls_crypto_box_open_funcs[] = {
    &ls_crypto_box_open_func,
    NULL,
};

static const ls_crypto_box_easy_func_def * const ls_crypto_box_easy_funcs[] = {
    &ls_crypto_box_easy_func,
    NULL,
};

static const ls_crypto_box_open_easy_func_def * const ls_crypto_box_open_easy_funcs[] = {
    &ls_crypto_box_open_easy_func,
    NULL,
};

static const ls_crypto_box_detached_func_def * const ls_crypto_box_detached_funcs[] = {
    &ls_crypto_box_detached_func,
    NULL,
};

static const ls_crypto_box_open_detached_func_def * const ls_crypto_box_open_detached_funcs[] = {
    &ls_crypto_box_open_detached_func,
    NULL,
};

static const ls_crypto_box_beforenm_func_def * const ls_crypto_box_beforenm_funcs[] = {
    &ls_crypto_box_beforenm_func,
    NULL,
};

static const ls_crypto_box_easy_afternm_func_def * const ls_crypto_box_easy_afternm_funcs[] = {
    &ls_crypto_box_easy_afternm_func,
    NULL,
};

static const ls_crypto_box_open_easy_afternm_func_def * const ls_crypto_box_open_easy_afternm_funcs[] = {
    &ls_crypto_box_open_easy_afternm_func,
    NULL,
};

static const ls_crypto_box_detached_afternm_func_def * const ls_crypto_box_detached_afternm_funcs[] = {
    &ls_crypto_box_detached_afternm_func,
    NULL,
};

static const ls_crypto_box_open_detached_afternm_func_def * const ls_crypto_box_open_detached_afternm_funcs[] = {
    &ls_crypto_box_open_detached_afternm_func,
    NULL,
};

static void
ls_push_crypto_box_keygen_closures(lua_State *L) {
    const ls_crypto_box_keypair_func_def * const *f = ls_crypto_box_keypair_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_box_keypair,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_box_seed_keygen_closures(lua_State *L) {
    const ls_crypto_box_seed_keypair_func_def * const *f = ls_crypto_box_seed_keypair_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_box_seed_keypair,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_box_easy_closures(lua_State *L) {
    const ls_crypto_box_easy_func_def * const *f = ls_crypto_box_easy_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_box_easy,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_box_detached_closures(lua_State *L) {
    const ls_crypto_box_detached_func_def * const *f = ls_crypto_box_detached_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_box_detached,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_box_open_easy_closures(lua_State *L) {
    const ls_crypto_box_open_easy_func_def * const *f = ls_crypto_box_open_easy_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_box_open_easy,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_box_open_detached_closures(lua_State *L) {
    const ls_crypto_box_open_detached_func_def * const *f = ls_crypto_box_open_detached_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_box_open_detached,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_box_beforenm_closures(lua_State *L) {
    const ls_crypto_box_beforenm_func_def * const *f = ls_crypto_box_beforenm_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_box_beforenm,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_box_easy_afternm_closures(lua_State *L) {
    const ls_crypto_box_easy_afternm_func_def * const *f = ls_crypto_box_easy_afternm_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_box_easy_afternm,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_box_open_easy_afternm_closures(lua_State *L) {
    const ls_crypto_box_open_easy_afternm_func_def * const *f = ls_crypto_box_open_easy_afternm_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_box_open_easy_afternm,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_box_detached_afternm_closures(lua_State *L) {
    const ls_crypto_box_detached_afternm_func_def * const *f = ls_crypto_box_detached_afternm_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_box_detached_afternm,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_box_open_detached_afternm_closures(lua_State *L) {
    const ls_crypto_box_open_detached_afternm_func_def * const *f = ls_crypto_box_open_detached_afternm_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_box_open_detached_afternm,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

int luaopen_luasodium_crypto_box_core(lua_State *L) {
    LUASODIUM_INIT(L)
    lua_newtable(L);

    luasodium_set_constants(L,ls_crypto_box_constants);

    ls_push_crypto_box_keygen_closures(L);
    ls_push_crypto_box_seed_keygen_closures(L);
    ls_push_crypto_box_easy_closures(L);
    ls_push_crypto_box_open_easy_closures(L);
    ls_push_crypto_box_detached_closures(L);
    ls_push_crypto_box_open_detached_closures(L);
    ls_push_crypto_box_beforenm_closures(L);
    ls_push_crypto_box_easy_afternm_closures(L);
    ls_push_crypto_box_open_easy_afternm_closures(L);
    ls_push_crypto_box_detached_afternm_closures(L);
    ls_push_crypto_box_open_detached_afternm_closures(L);

    return 1;
}
