#include "../luasodium-c.h"
#include "../internals/ls_lua_set_functions.h"

#include <string.h>

static int
ls_sodium_init(lua_State *L) {
    /* LCOV_EXCL_START */
    if(sodium_init() == -1) {
        lua_pushliteral(L,"sodium_init error");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */
    lua_pushboolean(L,1);
    return 1;
}

static int
ls_sodium_memcmp(lua_State *L) {
    const char *b1 = NULL;
    const char *b2 = NULL;
    size_t len = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 arguments");
        return lua_error(L);
    }

    b1 = lua_tolstring(L,1,NULL);
    b2 = lua_tolstring(L,2,NULL);
    len = lua_tointeger(L,3);

    lua_pushboolean(L,sodium_memcmp(
      b1,
      b2,
      len) == 0);
    return 1;
}

/* luasodium.bin2hex(bin) */
static int
ls_sodium_bin2hex(lua_State *L) {
    const char *bin = NULL;
    char *hex = NULL;
    size_t bin_len = 0;
    size_t hex_len = 0;

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"requires 1 argument");
        return lua_error(L);
    }

    bin = lua_tolstring(L,1,&bin_len);
    hex_len = (bin_len * 2);
    hex = lua_newuserdata(L,hex_len + 1);

    /* LCOV_EXCL_START */
    if(hex == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    sodium_bin2hex(hex,hex_len+1,(const unsigned char *)bin,bin_len);
    lua_pushstring(L,hex);
    sodium_memzero(hex,hex_len + 1);
    return 1;
}

/* luasodium.hex2bin(hex, [ignore]) */
static int
ls_sodium_hex2bin(lua_State *L) {
    const char *hex = NULL;
    const char *hex_end = NULL;
    const char *ignore = NULL;
    unsigned char *bin = NULL;
    int r = 1;

    size_t hex_len = 0;
    size_t bin_len = 0;
    size_t out_bin_len = 0;

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"requires 1 argument");
        return lua_error(L);
    }

    hex = lua_tolstring(L,1,&hex_len);

    bin_len = hex_len / 2;
    if(hex_len % 2 != 0) {
        bin_len++;
    }

    if(lua_isstring(L,2)) {
        ignore = lua_tostring(L,2);
    }

    bin = lua_newuserdata(L,bin_len);

    /* LCOV_EXCL_START */
    if(bin == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(sodium_hex2bin(
        bin,bin_len,
        hex,hex_len,
        ignore, &out_bin_len,
        &hex_end) != 0) {
        lua_pushnil(L);
        lua_pushliteral(L,"error in hex2bin");
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)bin,out_bin_len);
    if(hex_end < hex + hex_len) {
        lua_pushlstring(L,hex_end,(hex + hex_len) - hex_end);
        r = 2;
    }
    sodium_memzero(bin,bin_len);
    return r;
}

/* luasodium.bin2base64(bin, variant) */
static int
ls_sodium_bin2base64(lua_State *L) {
    const char *bin = NULL;
    char *b64 = NULL;
    size_t bin_len = 0;
    size_t b64_len = 0;
    lua_Integer variant = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 argument");
        return lua_error(L);
    }

    bin = lua_tolstring(L,1,&bin_len);
    variant = lua_tointeger(L,2);

    switch(variant) {
        case sodium_base64_VARIANT_ORIGINAL: break;
        case sodium_base64_VARIANT_ORIGINAL_NO_PADDING: break;
        case sodium_base64_VARIANT_URLSAFE: break;
        case sodium_base64_VARIANT_URLSAFE_NO_PADDING: break;
        default: {
            lua_pushliteral(L,"unknown base64 variant");
            return lua_error(L);
        }
    }

    b64_len = sodium_base64_encoded_len(bin_len,(const int)variant);
    b64 = lua_newuserdata(L,b64_len);

    /* LCOV_EXCL_START */
    if(b64 == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    sodium_bin2base64(b64,b64_len,
      (const unsigned char *)bin, bin_len,
      (const int)variant);
    lua_pushstring(L,b64);
    sodium_memzero(b64,b64_len);
    return 1;
}

/* luasodium.base642bin(base64, variant, [ignore]) */
static int
ls_sodium_base642bin(lua_State *L) {
    const char *base64 = NULL;
    const char *base64_end = NULL;
    const char *ignore = NULL;
    unsigned char *bin = NULL;
    lua_Integer variant = 0;
    int r = 1;

    size_t base64_len;
    size_t bin_len;
    size_t out_bin_len;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    base64 = lua_tolstring(L,1,&base64_len);
    variant = lua_tointeger(L,2);

    switch(variant) {
        case sodium_base64_VARIANT_ORIGINAL: break;
        case sodium_base64_VARIANT_ORIGINAL_NO_PADDING: break;
        case sodium_base64_VARIANT_URLSAFE: break;
        case sodium_base64_VARIANT_URLSAFE_NO_PADDING: break;
        default: {
            lua_pushliteral(L,"unknown base64 variant");
            return lua_error(L);
        }
    }

    /* this is technicallly too many bytes but whatever */
    bin_len = base64_len;

    if(lua_isstring(L,3)) {
        ignore = lua_tostring(L,3);
    }

    bin = lua_newuserdata(L,bin_len);

    /* LCOV_EXCL_START */
    if(bin == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    /* LCOV_EXCL_START */
    if(sodium_base642bin(
        bin,bin_len,
        base64,base64_len,
        ignore, &out_bin_len,
        &base64_end,(const int)variant) != 0) {
        lua_pushnil(L);
        lua_pushliteral(L,"error in base642bin");
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)bin,out_bin_len);
    if(base64_end < base64 + base64_len) {
        lua_pushlstring(L,base64_end,(base64 + base64_len) - base64_end);
        r = 2;
    }
    sodium_memzero(bin,bin_len);
    return r;
}

static int
ls_sodium_increment(lua_State *L) {
    const char *n = NULL;
    char *r = NULL;
    size_t nlen = 0;

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"requires 1 argument");
        return lua_error(L);
    }

    n = lua_tolstring(L,1,&nlen);
    r = lua_newuserdata(L,nlen);

    /* LCOV_EXCL_START */
    if(r == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    memcpy(r,n,nlen);

    sodium_increment((unsigned char *)r,nlen);
    lua_pushlstring(L,r,nlen);
    sodium_memzero(r,nlen);
    return 1;
}

static int
ls_sodium_add(lua_State *L) {
    const char *a = NULL;
    const char *b = NULL;
    char *r = NULL;
    size_t alen = 0;
    size_t blen = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    a = lua_tolstring(L,1,&alen);
    b = lua_tolstring(L,2,&blen);

    if(alen != blen) {
        lua_pushliteral(L,"mismatched data sizes");
        return lua_error(L);
    }

    r = lua_newuserdata(L,alen);

    /* LCOV_EXCL_START */
    if(r == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    memcpy(r,a,alen);
    sodium_add((unsigned char *)r,(const unsigned char *)b,alen);
    lua_pushlstring(L,r,alen);
    sodium_memzero(r,alen);
    return 1;
}

static int
ls_sodium_sub(lua_State *L) {
    const char *a = NULL;
    const char *b = NULL;
    char *r = NULL;
    size_t alen = 0;
    size_t blen = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    a = lua_tolstring(L,1,&alen);
    b = lua_tolstring(L,2,&blen);

    if(alen != blen) {
        lua_pushliteral(L,"mismatched data sizes");
        return lua_error(L);
    }

    r = lua_newuserdata(L,alen);

    /* LCOV_EXCL_START */
    if(r == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    memcpy(r,a,alen);
    sodium_sub((unsigned char *)r,(const unsigned char *)b,alen);
    lua_pushlstring(L,r,alen);
    sodium_memzero(r,alen);
    return 1;
}

static int
ls_sodium_compare(lua_State *L) {
    const char *a = NULL;
    const char *b = NULL;
    size_t alen = 0;
    size_t blen = 0;

    a = lua_tolstring(L,1,&alen);
    b = lua_tolstring(L,2,&blen);

    if(alen != blen) {
        lua_pushliteral(L,"mismatched data sizes");
        return lua_error(L);
    }

    lua_pushinteger(L,sodium_compare((const void *)a,(const void *)b,alen));
    return 1;
}

static int
ls_sodium_is_zero(lua_State *L) {
    const char *n = NULL;
    size_t nlen = 0;

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"requires 1 argument");
        return lua_error(L);
    }

    n = lua_tolstring(L,1,&nlen);
    lua_pushboolean(L,sodium_is_zero((const unsigned char *)n,nlen) == 1);
    return 1;
}

static int
ls_sodium_pad(lua_State *L) {
    const char *n = NULL;
    char *r = NULL;
    size_t nlen = 0;
    size_t blocksize = 0;
    size_t rounded = 0;
    size_t outlen = 0;
    size_t rem = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    n = lua_tolstring(L,1,&nlen);
    blocksize = lua_tointeger(L,2);

    rem = nlen % blocksize;
    rounded = nlen + (blocksize - rem);

    r = lua_newuserdata(L,rounded);

    /* LCOV_EXCL_START */
    if(r == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    memcpy(r,n,nlen);

    /* LCOV_EXCL_START */
    if(sodium_pad(&outlen,(unsigned char *)r,
        nlen,blocksize,rounded) != 0) {
        sodium_memzero(r,rounded);
        lua_pushnil(L);
        lua_pushliteral(L,"sodium_pad error");
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,r,outlen);
    sodium_memzero(r,rounded);
    return 1;
}

static int
ls_sodium_unpad(lua_State *L) {
    const char *n = NULL;
    size_t nlen = 0;
    size_t blocksize = 0;
    size_t outlen = 0;

    if(lua_isnoneornil(L,2)) {
        lua_pushliteral(L,"requires 2 arguments");
        return lua_error(L);
    }

    n = lua_tolstring(L,1,&nlen);
    blocksize = lua_tointeger(L,2);

    if(sodium_unpad(&outlen,(const unsigned char *)n,
        nlen,blocksize) != 0) {
        lua_pushnil(L);
        lua_pushliteral(L,"sodium_unpad error");
        return 2;
    }

    lua_pushlstring(L,n,outlen);
    return 1;
}

static const struct luaL_Reg ls_utils_functions[] = {
    LS_LUA_FUNC(sodium_init),
    LS_LUA_FUNC(sodium_memcmp),
    LS_LUA_FUNC(sodium_bin2hex),
    LS_LUA_FUNC(sodium_hex2bin),
    LS_LUA_FUNC(sodium_bin2base64),
    LS_LUA_FUNC(sodium_base642bin),
    LS_LUA_FUNC(sodium_increment),
    LS_LUA_FUNC(sodium_add),
    LS_LUA_FUNC(sodium_sub),
    LS_LUA_FUNC(sodium_compare),
    LS_LUA_FUNC(sodium_is_zero),
    LS_LUA_FUNC(sodium_pad),
    LS_LUA_FUNC(sodium_unpad),
    { NULL, NULL },
};

LS_PUBLIC
int
luaopen_luasodium_utils_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L)
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    lua_pushinteger(L,sodium_base64_VARIANT_ORIGINAL);
    lua_setfield(L,-2,"sodium_base64_VARIANT_ORIGINAL");
    lua_pushinteger(L,sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    lua_setfield(L,-2,"sodium_base64_VARIANT_ORIGINAL_NO_PADDING");
    lua_pushinteger(L,sodium_base64_VARIANT_URLSAFE);
    lua_setfield(L,-2,"sodium_base64_VARIANT_URLSAFE");
    lua_pushinteger(L,sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    lua_setfield(L,-2,"sodium_base64_VARIANT_URLSAFE_NO_PADDING");
    ls_lua_set_functions(L,ls_utils_functions,0);

    return 1;
}
