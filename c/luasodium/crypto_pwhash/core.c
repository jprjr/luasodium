#include "../luasodium-c.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

typedef int (*ls_crypto_pwhash_ptr)(
  unsigned char * const,
  unsigned long long,
  const char * const,
  unsigned long long,
  const unsigned char * const,
  unsigned long long,
  size_t,
  int);

typedef int (*ls_crypto_pwhash_str_ptr)(
  char *,
  const char * const,
  unsigned long long,
  unsigned long long,
  size_t);

typedef int (*ls_crypto_pwhash_str_verify_ptr)(
  const char *,
  const char * const,
  unsigned long long);

typedef int (*ls_crypto_pwhash_str_needs_rehash_ptr)(
  const char *,
  unsigned long long,
  size_t);

/* crypto_pwhash(length, passwd, salt, opslimit, memlimit [, alg]) */
static int
ls_crypto_pwhash(lua_State *L) {
    unsigned char *out = NULL;
    const char *passwd = NULL;
    const unsigned char *salt = NULL;

    size_t outlen = 0;
    size_t passwdlen = 0;
    size_t saltlen = 0;
    size_t opslimit = 0;
    size_t memlimit = 0;
    int alg = 0;

    const char *fname = NULL;
    ls_crypto_pwhash_ptr f = NULL;
    size_t BYTES_MIN = 0;
    size_t BYTES_MAX = 0;
    size_t OPSLIMIT_MIN = 0;
    size_t OPSLIMIT_MAX = 0;
    size_t MEMLIMIT_MIN = 0;
    size_t MEMLIMIT_MAX = 0;
    size_t PASSWD_MIN = 0;
    size_t PASSWD_MAX = 0;
    size_t SALTBYTES = 0;

    if(lua_isnoneornil(L,5)) {
        return luaL_error(L,"requires 5 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_pwhash_ptr)lua_touserdata(L,lua_upvalueindex(2));
    BYTES_MIN = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    BYTES_MAX = (size_t)lua_tointeger(L,lua_upvalueindex(4));
    OPSLIMIT_MIN = (size_t)lua_tointeger(L,lua_upvalueindex(5));
    OPSLIMIT_MAX = (size_t)lua_tointeger(L,lua_upvalueindex(6));
    MEMLIMIT_MIN = (size_t)lua_tointeger(L,lua_upvalueindex(7));
    MEMLIMIT_MAX = (size_t)lua_tointeger(L,lua_upvalueindex(8));
    PASSWD_MIN = (size_t)lua_tointeger(L,lua_upvalueindex(9));
    PASSWD_MAX = (size_t)lua_tointeger(L,lua_upvalueindex(10));
    SALTBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(11));
    alg = (int)lua_tointeger(L,lua_upvalueindex(12));

    outlen = (size_t)lua_tointeger(L,1);
    if(outlen < BYTES_MIN || outlen > BYTES_MAX) {
        return luaL_error(L,"incorrect outlen, must be between %d and %d",
          BYTES_MIN, BYTES_MAX);
    }

    passwd = lua_tolstring(L,2,&passwdlen);

    /* PASSWD_MIN == 0, not going to test > PASSWD_MAX */
    /* LCOV_EXCL_START */
    if(passwdlen < PASSWD_MIN || passwdlen > PASSWD_MAX) {
        return luaL_error(L,"incorrect passwdlen, must be between %d and %d",
          PASSWD_MIN, PASSWD_MAX);
    }
    /* LCOV_EXCL_STOP */

    salt = (const unsigned char *)lua_tolstring(L,3,&saltlen);

    if(saltlen != SALTBYTES) {
        return luaL_error(L,"incorrect salt length, must be: %d",
          SALTBYTES);
    }

    opslimit = (size_t) lua_tointeger(L,4);
    if(opslimit < OPSLIMIT_MIN || opslimit > OPSLIMIT_MAX) {
        return luaL_error(L,"incorrect ops limit, must be between %d and %d",
          OPSLIMIT_MIN, OPSLIMIT_MAX);
    }

    memlimit = (size_t) lua_tointeger(L,5);
    if(memlimit < MEMLIMIT_MIN || memlimit > MEMLIMIT_MAX) {
        return luaL_error(L,"incorrect mem limit, must be between %d and %d",
          MEMLIMIT_MIN, MEMLIMIT_MAX);
    }

    if(!lua_isnoneornil(L,6)) {
        alg = (int)lua_tointeger(L,6);
    }

    out = lua_newuserdata(L,outlen);

    /* LCOV_EXCL_START */
    if(out == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    if(f(out,outlen,passwd,passwdlen,salt,opslimit,memlimit,alg) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)out,outlen);
    sodium_memzero(out,outlen);
    return 1;
}

static int
ls_crypto_pwhash_str(lua_State *L) {
    char *out = NULL;
    const char *passwd = NULL;

    size_t passwdlen = 0;
    size_t opslimit = 0;
    size_t memlimit = 0;

    const char *fname = NULL;
    ls_crypto_pwhash_str_ptr f = NULL;
    size_t STRBYTES = 0;
    size_t OPSLIMIT_MIN = 0;
    size_t OPSLIMIT_MAX = 0;
    size_t MEMLIMIT_MIN = 0;
    size_t MEMLIMIT_MAX = 0;
    size_t PASSWD_MIN = 0;
    size_t PASSWD_MAX = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    fname = lua_tostring(L,lua_upvalueindex(1));
    f = (ls_crypto_pwhash_str_ptr) lua_touserdata(L,lua_upvalueindex(2));
    STRBYTES = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    OPSLIMIT_MIN = (size_t)lua_tointeger(L,lua_upvalueindex(4));
    OPSLIMIT_MAX = (size_t)lua_tointeger(L,lua_upvalueindex(5));
    MEMLIMIT_MIN = (size_t)lua_tointeger(L,lua_upvalueindex(6));
    MEMLIMIT_MAX = (size_t)lua_tointeger(L,lua_upvalueindex(7));
    PASSWD_MIN = (size_t)lua_tointeger(L,lua_upvalueindex(8));
    PASSWD_MAX = (size_t)lua_tointeger(L,lua_upvalueindex(9));

    passwd = lua_tolstring(L,1,&passwdlen);

    /* TODO see if we need to verify passwdlen, see
     * https://github.com/jedisct1/libsodium-doc/issues/124 */
    /* LCOV_EXCL_START */
    if(passwdlen < PASSWD_MIN || passwdlen > PASSWD_MAX) {
        return luaL_error(L,"incorrect passwdlen, must be between %d and %d",
          PASSWD_MIN, PASSWD_MAX);
    }
    /* LCOV_EXCL_STOP */

    opslimit = (size_t) lua_tointeger(L,2);
    if(opslimit < OPSLIMIT_MIN || opslimit > OPSLIMIT_MAX) {
        return luaL_error(L,"incorrect ops limit, must be between %d and %d",
          OPSLIMIT_MIN, OPSLIMIT_MAX);
    }

    memlimit = (size_t) lua_tointeger(L,3);
    if(memlimit < MEMLIMIT_MIN || memlimit > MEMLIMIT_MAX) {
        return luaL_error(L,"incorrect mem limit, must be between %d and %d",
          MEMLIMIT_MIN, MEMLIMIT_MAX);
    }

    out = lua_newuserdata(L,STRBYTES);

    /* LCOV_EXCL_START */
    if(out == NULL) {
        return luaL_error(L,"out of memory");
    }
    /* LCOV_EXCL_STOP */
    lua_pop(L,1);

    /* it shouldn't be possible to pass a bad ops/memlimit here */
    /* LCOV_EXCL_START */
    if(f(out,passwd,passwdlen,opslimit,memlimit) == -1) {
        return luaL_error(L,"%s error",fname);
    }
    /* LCOV_EXCL_STOP */

    lua_pushstring(L,out);
    sodium_memzero(out,STRBYTES);
    return 1;
}

static int
ls_crypto_pwhash_str_verify(lua_State *L) {
    const char *str = NULL;
    const char *passwd = NULL;

    size_t passwdlen = 0;

    ls_crypto_pwhash_str_verify_ptr f = NULL;
    size_t PASSWD_MIN = 0;
    size_t PASSWD_MAX = 0;

    if(lua_isnoneornil(L,2)) {
        return luaL_error(L,"requires 2 parameters");
    }

    f = (ls_crypto_pwhash_str_verify_ptr) lua_touserdata(L,lua_upvalueindex(1));
    PASSWD_MIN = (size_t)lua_tointeger(L,lua_upvalueindex(2));
    PASSWD_MAX = (size_t)lua_tointeger(L,lua_upvalueindex(3));

    str = lua_tostring(L,1);
    passwd = lua_tolstring(L,2,&passwdlen);

    /* LCOV_EXCL_START */
    if(passwdlen < PASSWD_MIN || passwdlen > PASSWD_MAX) {
        return luaL_error(L,"incorrect passwdlen, must be between %d and %d",
          PASSWD_MIN, PASSWD_MAX);
    }
    /* LCOV_EXCL_STOP */

    lua_pushboolean(L,
      f(str,passwd,passwdlen) == 0);
    return 1;
}

static int
ls_crypto_pwhash_str_needs_rehash(lua_State *L) {
    const char *str = NULL;

    size_t opslimit = 0;
    size_t memlimit = 0;

    ls_crypto_pwhash_str_needs_rehash_ptr f = NULL;
    size_t OPSLIMIT_MIN = 0;
    size_t OPSLIMIT_MAX = 0;
    size_t MEMLIMIT_MIN = 0;
    size_t MEMLIMIT_MAX = 0;

    if(lua_isnoneornil(L,3)) {
        return luaL_error(L,"requires 3 parameters");
    }

    f = (ls_crypto_pwhash_str_needs_rehash_ptr) lua_touserdata(L, lua_upvalueindex(1));

    OPSLIMIT_MIN = (size_t)lua_tointeger(L,lua_upvalueindex(2));
    OPSLIMIT_MAX = (size_t)lua_tointeger(L,lua_upvalueindex(3));
    MEMLIMIT_MIN = (size_t)lua_tointeger(L,lua_upvalueindex(4));
    MEMLIMIT_MAX = (size_t)lua_tointeger(L,lua_upvalueindex(5));

    str = lua_tostring(L,1);

    opslimit = (size_t) lua_tointeger(L,2);
    if(opslimit < OPSLIMIT_MIN || opslimit > OPSLIMIT_MAX) {
        return luaL_error(L,"incorrect ops limit, must be between %d and %d",
          OPSLIMIT_MIN, OPSLIMIT_MAX);
    }

    memlimit = (size_t) lua_tointeger(L,3);
    if(memlimit < MEMLIMIT_MIN || memlimit > MEMLIMIT_MAX) {
        return luaL_error(L,"incorrect mem limit, must be between %d and %d",
          MEMLIMIT_MIN, MEMLIMIT_MAX);
    }

    lua_pushboolean(L,
      f(str,opslimit,memlimit) != 0);

    return 1;
}

#define LS_CRYPTO_PWHASH(x,alg) \
  lua_pushliteral(L, #x); \
  lua_pushlightuserdata(L, x); \
  lua_pushinteger(L, x ## _BYTES_MIN); \
  lua_pushinteger(L, x ## _BYTES_MAX); \
  lua_pushinteger(L, x ## _OPSLIMIT_MIN); \
  lua_pushinteger(L, x ## _OPSLIMIT_MAX); \
  lua_pushinteger(L, x ## _MEMLIMIT_MIN); \
  lua_pushinteger(L, x ## _MEMLIMIT_MAX); \
  lua_pushinteger(L, x ## _PASSWD_MIN); \
  lua_pushinteger(L, x ## _PASSWD_MAX); \
  lua_pushinteger(L, x ## _SALTBYTES); \
  lua_pushinteger(L, x ## _ALG_ ## alg); \
  lua_pushcclosure(L, ls_crypto_pwhash, 12); \
  lua_setfield(L, -2, #x )

#define LS_CRYPTO_PWHASH_STR(x) \
  lua_pushliteral(L, #x "_str"); \
  lua_pushlightuserdata(L, x ## _str); \
  lua_pushinteger(L, x ## _STRBYTES); \
  lua_pushinteger(L, x ## _OPSLIMIT_MIN); \
  lua_pushinteger(L, x ## _OPSLIMIT_MAX); \
  lua_pushinteger(L, x ## _MEMLIMIT_MIN); \
  lua_pushinteger(L, x ## _MEMLIMIT_MAX); \
  lua_pushinteger(L, x ## _PASSWD_MIN); \
  lua_pushinteger(L, x ## _PASSWD_MAX); \
  lua_pushcclosure(L, ls_crypto_pwhash_str, 9); \
  lua_setfield(L, -2, #x "_str" )

#define LS_CRYPTO_PWHASH_STR_VERIFY(x) \
  lua_pushlightuserdata(L, x ## _str_verify); \
  lua_pushinteger(L, x ## _PASSWD_MIN); \
  lua_pushinteger(L, x ## _PASSWD_MAX); \
  lua_pushcclosure(L, ls_crypto_pwhash_str_verify, 3); \
  lua_setfield(L, -2, #x "_str_verify" )

#define LS_CRYPTO_PWHASH_STR_NEEDS_REHASH(x) \
  lua_pushlightuserdata(L, x ## _str_needs_rehash); \
  lua_pushinteger(L, x ## _OPSLIMIT_MIN); \
  lua_pushinteger(L, x ## _OPSLIMIT_MAX); \
  lua_pushinteger(L, x ## _MEMLIMIT_MIN); \
  lua_pushinteger(L, x ## _MEMLIMIT_MAX); \
  lua_pushcclosure(L, ls_crypto_pwhash_str_needs_rehash, 5); \
  lua_setfield(L, -2, #x "_str_needs_rehash" )

LS_PUBLIC
int luaopen_luasodium_crypto_pwhash_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L);
    /* LCOV_EXCL_STOP */

    lua_newtable(L);
    ls_lua_set_constants(L,ls_crypto_pwhash_constants,lua_gettop(L));

    /* string constants */
    lua_pushliteral(L,crypto_pwhash_STRPREFIX);
    lua_setfield(L,-2,"crypto_pwhash_STRPREFIX");

    lua_pushliteral(L,crypto_pwhash_argon2i_STRPREFIX);
    lua_setfield(L,-2,"crypto_pwhash_argon2i_STRPREFIX");

    lua_pushliteral(L,crypto_pwhash_argon2id_STRPREFIX);
    lua_setfield(L,-2,"crypto_pwhash_argon2id_STRPREFIX");

    LS_CRYPTO_PWHASH(crypto_pwhash,DEFAULT);
    LS_CRYPTO_PWHASH_STR(crypto_pwhash);
    LS_CRYPTO_PWHASH_STR_VERIFY(crypto_pwhash);
    LS_CRYPTO_PWHASH_STR_NEEDS_REHASH(crypto_pwhash);

    LS_CRYPTO_PWHASH(crypto_pwhash_argon2i,ARGON2I13);
    LS_CRYPTO_PWHASH_STR(crypto_pwhash_argon2i);
    LS_CRYPTO_PWHASH_STR_VERIFY(crypto_pwhash_argon2i);
    LS_CRYPTO_PWHASH_STR_NEEDS_REHASH(crypto_pwhash_argon2i);

    LS_CRYPTO_PWHASH(crypto_pwhash_argon2id,ARGON2ID13);
    LS_CRYPTO_PWHASH_STR(crypto_pwhash_argon2id);
    LS_CRYPTO_PWHASH_STR_VERIFY(crypto_pwhash_argon2id);
    LS_CRYPTO_PWHASH_STR_NEEDS_REHASH(crypto_pwhash_argon2id);

    return 1;
}
