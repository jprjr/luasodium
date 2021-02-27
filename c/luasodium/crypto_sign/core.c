#include "../luasodium-c.h"
#include "../internals/ls_lua_equal.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef int (*ls_crypto_sign_keypair_ptr)(
  unsigned char *,
  unsigned char *);

typedef int (*ls_crypto_sign_seed_keypair_ptr)(
  unsigned char *,
  unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_sign_ptr)(
  unsigned char *,
  unsigned long long *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *);

typedef int (*ls_crypto_sign_open_ptr)(
  unsigned char *,
  unsigned long long *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *);

typedef int (*ls_crypto_sign_detached_ptr)(
  unsigned char *,
  unsigned long long *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *);

typedef int (*ls_crypto_sign_verify_detached_ptr)(
  const unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *);

typedef int (*ls_crypto_sign_init_ptr)(
  void *);

typedef int (*ls_crypto_sign_update_ptr)(
  void *,
  const unsigned char *,
  unsigned long long);

typedef int (*ls_crypto_sign_final_create_ptr)(
  void *,
  unsigned char *,
  unsigned long long *,
  const unsigned char *);

typedef int (*ls_crypto_sign_final_verify_ptr)(
  void *,
  const unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_sign_sk_to_seed_ptr)(
  unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_sign_sk_to_pk_ptr)(
  unsigned char *,
  const unsigned char *);

static int
ls_crypto_sign_keypair(lua_State *L) {
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;

    const char *fname = NULL;
    ls_crypto_sign_keypair_ptr f = NULL;
    size_t PUBLICKEYBYTES = 0;
    size_t SECRETKEYBYTES = 0;

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_sign_keypair_ptr)lua_touserdata(L,lua_upvalueindex(2));
    PUBLICKEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    SECRETKEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));

    pk = (unsigned char *)lua_newuserdata(L,PUBLICKEYBYTES);
    
    /* LCOV_EXCL_START */
    if(pk == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    sk = (unsigned char *)lua_newuserdata(L,SECRETKEYBYTES);
    
    /* LCOV_EXCL_START */
    if(sk == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

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
ls_crypto_sign_seed_keypair(lua_State *L) {
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;
    const unsigned char *seed = NULL;
    size_t seedlen = 0;

    const char *fname = NULL;
    ls_crypto_sign_seed_keypair_ptr f = NULL;
    size_t PUBLICKEYBYTES = 0;
    size_t SECRETKEYBYTES = 0;
    size_t SEEDBYTES = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_sign_seed_keypair_ptr)lua_touserdata(L,lua_upvalueindex(2));
    PUBLICKEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    SECRETKEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));
    SEEDBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(5));

    seed = (const unsigned char *)lua_tolstring(L,1,&seedlen);

    if(seedlen != SEEDBYTES) {
        return luaL_error(L,"wrong seed size, expected: %d",
          SEEDBYTES);
    }

    pk = (unsigned char *)lua_newuserdata(L,PUBLICKEYBYTES);
    
    /* LCOV_EXCL_START */
    if(pk == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    sk = (unsigned char *)lua_newuserdata(L,SECRETKEYBYTES);
    
    /* LCOV_EXCL_START */
    if(sk == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

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
ls_crypto_sign(lua_State *L) {
    unsigned char *sm = NULL;
    const unsigned char *m = NULL;
    const unsigned char *sk = NULL;
    unsigned long long smlen;
    size_t smlen_a = 0;
    size_t mlen = 0;
    size_t sklen = 0;

    const char *fname = NULL;
    ls_crypto_sign_ptr f = NULL;
    size_t SECRETKEYBYTES = 0;
    size_t BYTES = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_sign_ptr)lua_touserdata(L,lua_upvalueindex(2));
    SECRETKEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    BYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    sk = (const unsigned char *)lua_tolstring(L,2,&sklen);

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",
          SECRETKEYBYTES);
    }

    smlen_a = mlen + BYTES;

    sm = lua_newuserdata(L,smlen_a);

    /* LCOV_EXCL_START */
    if(sm == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(sm,&smlen,m,mlen,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

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

    ls_crypto_sign_open_ptr f = NULL;
    size_t PUBLICKEYBYTES = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    f = (ls_crypto_sign_open_ptr)lua_touserdata(L,lua_upvalueindex(1));
    PUBLICKEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(2));

    sm = (const unsigned char *)lua_tolstring(L,1,&smlen);
    pk = (const unsigned char *)lua_tolstring(L,2,&pklen);

    if(pklen != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",
          PUBLICKEYBYTES);
    }

    /* LCOV_EXCL_START */
    m = lua_newuserdata(L,smlen);
    if(sm == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    if(f(m,&mlen,sm,smlen,pk) == 0) {
        lua_pushlstring(L,(const char *)m,mlen);
        r = 1;
    }
    sodium_memzero(m,smlen);
    return r;
}

static int
ls_crypto_sign_detached(lua_State *L) {
    unsigned char *sig = NULL; /*[crypto_sign_BYTES]; */
    const unsigned char *m = NULL;
    const unsigned char *sk = NULL;
    unsigned long long siglen;
    size_t mlen = 0;
    size_t sklen = 0;

    const char *fname = NULL;
    ls_crypto_sign_detached_ptr f = NULL;
    size_t SECRETKEYBYTES = 0;
    size_t BYTES = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_sign_detached_ptr)lua_touserdata(L,lua_upvalueindex(2));
    SECRETKEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    BYTES = (size_t)lua_tointeger(L,lua_upvalueindex(4));

    m  = (const unsigned char *)lua_tolstring(L,1,&mlen);
    sk = (const unsigned char *)lua_tolstring(L,2,&sklen);

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",
          SECRETKEYBYTES);
    }

    sig = (unsigned char *)lua_newuserdata(L,BYTES);

    /* LCOV_EXCL_START */
    if(sig == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(sig,&siglen,m,mlen,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)sig,siglen);
    sodium_memzero(sig,BYTES);
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

    ls_crypto_sign_verify_detached_ptr f = NULL;
    size_t PUBLICKEYBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    f = (ls_crypto_sign_verify_detached_ptr)lua_touserdata(L,lua_upvalueindex(1));
    PUBLICKEYBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(2));

    sig = (const unsigned char *)lua_tolstring(L,1,&siglen);
    m   = (const unsigned char *)lua_tolstring(L,2,&mlen);
    pk  = (const unsigned char *)lua_tolstring(L,3,&pklen);

    if(pklen != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",
          PUBLICKEYBYTES);
    }

    lua_pushboolean(L,f(sig,m,mlen,pk) == 0);

    return 1;
}

static int
ls_crypto_sign_init(lua_State *L) {
    void *state = NULL;

    const char *fname = NULL;
    ls_crypto_sign_init_ptr f = NULL;
    size_t STATEBYTES = 0;

    fname = lua_tostring(L, lua_upvalueindex(1));
    f = (ls_crypto_sign_init_ptr) lua_touserdata(L, lua_upvalueindex(2));
    STATEBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(3));

    state = lua_newuserdata(L, STATEBYTES);

    /* LCOV_EXCL_START */
    if(state == NULL) {
        return luaL_error(L, "out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(state) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushvalue(L,lua_upvalueindex(4));
    lua_setmetatable(L,-2);

    return 1;
}

static int
ls_crypto_sign_update(lua_State *L) {
    void *state = NULL;
    const unsigned char *m   = NULL;
    size_t mlen = 0;

    ls_crypto_sign_update_ptr f = NULL;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(2));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    f = (ls_crypto_sign_update_ptr) lua_touserdata(L, lua_upvalueindex(1));

    state = lua_touserdata(L,1);
    m   = (const unsigned char *)lua_tolstring(L,2,&mlen);

    lua_pushboolean(L,f(
      state,m,mlen) != -1);
    return 1;
}

static int
ls_crypto_sign_final_create(lua_State *L) {
    void *state = NULL;
    unsigned char *sig = NULL;
    const unsigned char *sk   = NULL;
    unsigned long long siglen = 0;
    size_t sklen = 0;

    const char *fname = NULL;
    ls_crypto_sign_final_create_ptr f = NULL;
    size_t SECRETKEYBYTES = 0;
    size_t BYTES = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(5));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    fname = lua_tostring(L, lua_upvalueindex(1));
    f = (ls_crypto_sign_final_create_ptr) lua_touserdata(L, lua_upvalueindex(2));
    SECRETKEYBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(3));
    BYTES = (size_t) lua_tointeger(L, lua_upvalueindex(4));

    state = lua_touserdata(L,1);
    sk  = (const unsigned char *)lua_tolstring(L,2,&sklen);

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",
          SECRETKEYBYTES);
    }

    sig = (unsigned char *)lua_newuserdata(L, BYTES);

    /* LCOV_EXCL_START */
    if(sig == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(state,sig,&siglen,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)sig,siglen);
    sodium_memzero(sig,BYTES);
    return 1;
}

static int
ls_crypto_sign_final_verify(lua_State *L) {
    void *state  = NULL;
    const unsigned char *sig  = NULL;
    const unsigned char *pk   = NULL;
    size_t siglen = 0;
    size_t pklen = 0;

    ls_crypto_sign_final_verify_ptr f = NULL;
    size_t PUBLICKEYBYTES = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    /* verify this is a state object */
    lua_pushvalue(L,lua_upvalueindex(3));
    lua_getmetatable(L,1);

    if(!ls_lua_equal(L,-2,-1)) {
        return luaL_error(L,"invalid userdata");
    }
    lua_pop(L,2);

    f = (ls_crypto_sign_final_verify_ptr) lua_touserdata(L, lua_upvalueindex(1));
    PUBLICKEYBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(2));

    state = lua_touserdata(L,1);
    sig = (const unsigned char *)lua_tolstring(L,2,&siglen);
    pk  = (const unsigned char *)lua_tolstring(L,3,&pklen);

    if(pklen != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong public key size, expected: %d",
          PUBLICKEYBYTES);
    }

    lua_pushboolean(L,f(state,sig,pk) == 0);
    return 1;
}

static int
ls_crypto_sign_sk_to_seed(lua_State *L) {
    unsigned char *seed = NULL;
    const unsigned char *sk = NULL;
    size_t sklen = 0;

    const char *fname = NULL;
    ls_crypto_sign_sk_to_seed_ptr f = NULL;
    size_t SECRETKEYBYTES = 0;
    size_t SEEDBYTES = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    fname = lua_tostring(L, lua_upvalueindex(1));
    f = (ls_crypto_sign_sk_to_seed_ptr) lua_touserdata(L, lua_upvalueindex(2));
    SECRETKEYBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(3));
    SEEDBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(4));

    sk  = (const unsigned char *)lua_tolstring(L,1,&sklen);

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",
          SECRETKEYBYTES);
    }

    seed = (unsigned char *)lua_newuserdata(L, SEEDBYTES);

    /* LCOV_EXCL_START */
    if(seed == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(seed,sk) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)seed,SEEDBYTES);
    sodium_memzero(seed,SEEDBYTES);
    return 1;
}

static int
ls_crypto_sign_sk_to_pk(lua_State *L) {
    unsigned char *pk = NULL;
    const unsigned char *sk = NULL;
    size_t sklen = 0;

    const char *fname = NULL;
    ls_crypto_sign_sk_to_pk_ptr f = NULL;
    size_t SECRETKEYBYTES = 0;
    size_t PUBLICKEYBYTES = 0;

    if(lua_isnoneornil(L,1)) {
        return luaL_error(L,"requires 1 parameter");
    }

    fname = lua_tostring(L, lua_upvalueindex(1));
    f = (ls_crypto_sign_sk_to_pk_ptr) lua_touserdata(L, lua_upvalueindex(2));
    SECRETKEYBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(3));
    PUBLICKEYBYTES = (size_t) lua_tointeger(L, lua_upvalueindex(4));

    sk  = (const unsigned char *)lua_tolstring(L,1,&sklen);

    if(sklen != SECRETKEYBYTES) {
        return luaL_error(L,"wrong secret key size, expected: %d",
          SECRETKEYBYTES);
    }

    pk = (unsigned char *)lua_newuserdata(L, PUBLICKEYBYTES);

    /* LCOV_EXCL_START */
    if(pk == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(f(pk,sk) == -1) {
        return luaL_error(L,"%s error", fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)pk,PUBLICKEYBYTES);
    sodium_memzero(pk,PUBLICKEYBYTES);
    return 1;
}

static int
ls_crypto_sign_state__gc(lua_State *L) {
    void *state = lua_touserdata(L,1);
    sodium_memzero(state,(size_t)lua_tointeger(L, lua_upvalueindex(1)));
    return 0;
}

static void
ls_crypto_sign_state_setup(lua_State *L,
  size_t STATEBYTES,
  size_t PUBLICKEYBYTES,
  size_t SECRETKEYBYTES,
  size_t BYTES,
  const char *initname,
  ls_crypto_sign_init_ptr init_ptr,
  const char *updatename,
  ls_crypto_sign_update_ptr update_ptr,
  const char *final_createname,
  ls_crypto_sign_final_create_ptr final_create_ptr,
  const char *final_verifyname,
  ls_crypto_sign_final_verify_ptr final_verify_ptr) {

    int module_index = 0;
    int metatable_index = 0;

    module_index = lua_gettop(L);

    /* create the metatable */
    lua_newtable(L);
    metatable_index = lua_gettop(L);

    lua_pushstring(L,initname);
    lua_pushlightuserdata(L,init_ptr);
    lua_pushinteger(L,STATEBYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L,ls_crypto_sign_init,4);
    lua_setfield(L,module_index,initname);

    lua_pushinteger(L, STATEBYTES);
    lua_pushcclosure(L, ls_crypto_sign_state__gc,1);
    lua_setfield(L,metatable_index,"__gc");

    lua_pushlightuserdata(L,update_ptr);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L, ls_crypto_sign_update, 2);
    lua_setfield(L, module_index, updatename);

    lua_pushstring(L, final_createname);
    lua_pushlightuserdata(L,final_create_ptr);
    lua_pushinteger(L,SECRETKEYBYTES);
    lua_pushinteger(L,BYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L, ls_crypto_sign_final_create, 5);
    lua_setfield(L, module_index, final_createname);

    lua_pushlightuserdata(L,final_verify_ptr);
    lua_pushinteger(L,PUBLICKEYBYTES);
    lua_pushvalue(L,metatable_index);
    lua_pushcclosure(L, ls_crypto_sign_final_verify, 3);
    lua_setfield(L, module_index, final_verifyname);

    lua_newtable(L);
    lua_getfield(L,module_index,updatename);
    lua_setfield(L,-2,"update");
    lua_getfield(L,module_index,final_createname);
    lua_setfield(L,-2,"final_create");
    lua_getfield(L,module_index,final_verifyname);
    lua_setfield(L,-2,"final_verify");
    lua_setfield(L,-2,"__index");
    lua_pop(L,1);

}

#define LS_PUSH_CRYPTO_SIGN_KEYPAIR(x) \
  lua_pushliteral(L, #x "_keypair" ); \
  lua_pushlightuserdata(L, x ## _keypair); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushcclosure(L, ls_crypto_sign_keypair, 4); \
  lua_setfield(L,-2, #x "_keypair");

#define LS_PUSH_CRYPTO_SIGN_SEED_KEYPAIR(x) \
  lua_pushliteral(L, #x "_seed_keypair" ); \
  lua_pushlightuserdata(L, x ## _seed_keypair); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushinteger(L, x ## _SEEDBYTES); \
  lua_pushcclosure(L, ls_crypto_sign_seed_keypair, 5); \
  lua_setfield(L,-2, #x "_seed_keypair");

#define LS_PUSH_CRYPTO_SIGN(x) \
  lua_pushliteral(L, #x ); \
  lua_pushlightuserdata(L, x ); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushinteger(L, x ## _BYTES); \
  lua_pushcclosure(L, ls_crypto_sign , 4); \
  lua_setfield(L,-2, #x );

#define LS_PUSH_CRYPTO_SIGN_OPEN(x) \
  lua_pushlightuserdata(L, x ## _open ); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushcclosure(L, ls_crypto_sign_open , 2); \
  lua_setfield(L,-2, #x "_open" );

#define LS_PUSH_CRYPTO_SIGN_DETACHED(x) \
  lua_pushliteral(L, #x "_detached" ); \
  lua_pushlightuserdata(L, x ## _detached ); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushinteger(L, x ## _BYTES); \
  lua_pushcclosure(L, ls_crypto_sign_detached , 4); \
  lua_setfield(L,-2, #x "_detached" );

#define LS_PUSH_CRYPTO_SIGN_VERIFY_DETACHED(x) \
  lua_pushlightuserdata(L, x ## _verify_detached ); \
  lua_pushinteger(L, x ## _PUBLICKEYBYTES); \
  lua_pushcclosure(L, ls_crypto_sign_verify_detached , 2); \
  lua_setfield(L,-2, #x "_verify_detached" );

#define LS_PUSH_CRYPTO_SIGN_SK_TO_SEED(x) \
  lua_pushliteral(L, #x "_sk_to_seed" ); \
  lua_pushlightuserdata(L, x ## _sk_to_seed ); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushinteger(L, x ## _SEEDBYTES); \
  lua_pushcclosure(L, ls_crypto_sign_sk_to_seed , 4); \
  lua_setfield(L,-2, #x "_sk_to_seed" );

#define LS_PUSH_CRYPTO_SIGN_SK_TO_PK(x) \
  lua_pushliteral(L, #x "_sk_to_pk" ); \
  lua_pushlightuserdata(L, x ## _sk_to_pk ); \
  lua_pushinteger(L, x ## _SECRETKEYBYTES); \
  lua_pushinteger(L, x ## _SEEDBYTES); \
  lua_pushcclosure(L, ls_crypto_sign_sk_to_pk , 4); \
  lua_setfield(L,-2, #x "_sk_to_pk" );

#define LS_CRYPTO_SIGN_STATE_SETUP(x) \
    ls_crypto_sign_state_setup(L, \
      x ## _statebytes(), \
      x ## _PUBLICKEYBYTES, \
      x ## _SECRETKEYBYTES, \
      x ## _BYTES, \
      #x "_init", \
      (ls_crypto_sign_init_ptr) x ## _init, \
      #x "_update", \
      (ls_crypto_sign_update_ptr) x ## _update, \
      #x "_final_create", \
      (ls_crypto_sign_final_create_ptr) x ##_final_create, \
      #x "_final_verify", \
      (ls_crypto_sign_final_verify_ptr) x ## _final_verify);

LS_PUBLIC
int luaopen_luasodium_crypto_sign_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_sign_constants,lua_gettop(L));

    LS_PUSH_CRYPTO_SIGN_KEYPAIR(crypto_sign);
    LS_PUSH_CRYPTO_SIGN_SEED_KEYPAIR(crypto_sign);
    LS_PUSH_CRYPTO_SIGN(crypto_sign);
    LS_PUSH_CRYPTO_SIGN_OPEN(crypto_sign);
    LS_PUSH_CRYPTO_SIGN_DETACHED(crypto_sign);
    LS_PUSH_CRYPTO_SIGN_VERIFY_DETACHED(crypto_sign);

    LS_CRYPTO_SIGN_STATE_SETUP(crypto_sign);

    LS_PUSH_CRYPTO_SIGN_KEYPAIR(crypto_sign_ed25519);
    LS_PUSH_CRYPTO_SIGN_SEED_KEYPAIR(crypto_sign_ed25519);
    LS_PUSH_CRYPTO_SIGN(crypto_sign_ed25519);
    LS_PUSH_CRYPTO_SIGN_OPEN(crypto_sign_ed25519);
    LS_PUSH_CRYPTO_SIGN_DETACHED(crypto_sign_ed25519);
    LS_PUSH_CRYPTO_SIGN_VERIFY_DETACHED(crypto_sign_ed25519);
    LS_PUSH_CRYPTO_SIGN_SK_TO_SEED(crypto_sign_ed25519);
    LS_PUSH_CRYPTO_SIGN_SK_TO_PK(crypto_sign_ed25519);

    ls_crypto_sign_state_setup(L,
      crypto_sign_ed25519ph_statebytes(),
      crypto_sign_ed25519_PUBLICKEYBYTES,
      crypto_sign_ed25519_SECRETKEYBYTES,
      crypto_sign_ed25519_BYTES,
      "crypto_sign_ed25519ph_init",
      (ls_crypto_sign_init_ptr) crypto_sign_ed25519ph_init,
      "crypto_sign_ed25519ph_update",
      (ls_crypto_sign_update_ptr) crypto_sign_ed25519ph_update,
      "crypto_sign_ed25519ph_final_create",
      (ls_crypto_sign_final_create_ptr) crypto_sign_ed25519ph_final_create,
      "crypto_sign_ed25519ph_final_verify",
      (ls_crypto_sign_final_verify_ptr) crypto_sign_ed25519ph_final_verify);

    return 1;
}
