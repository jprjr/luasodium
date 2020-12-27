#include <sodium.h>
#include <lua.h>
#include <lauxlib.h>

#include <string.h>
#include <assert.h>

#include "luasodium.luah"

#ifdef DEBUG
#include <stdio.h>
#endif

typedef void * ffi_pointer_t;

#if !defined(luaL_newlibtable) \
  && (!defined LUA_VERSION_NUM || LUA_VERSION_NUM==501)
static void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup) {
  luaL_checkstack(L, nup+1, "too many upvalues");
  for (; l->name != NULL; l++) {  /* fill the table with given functions */
    int i;
    lua_pushstring(L, l->name);
    for (i = 0; i < nup; i++)  /* copy upvalues to the top */
      lua_pushvalue(L, -(nup+1));
    lua_pushcclosure(L, l->func, nup);  /* closure with those upvalues */
    lua_settable(L, -(nup + 3));
  }
  lua_pop(L, nup);  /* remove upvalues */
}
#endif


static int
luasodium_init(lua_State *L) {
    if(sodium_init() == -1) {
        lua_pushliteral(L,"sodium_init error");
        return lua_error(L);
    }
    lua_pushboolean(L,1);
    return 1;
}

static int
luasodium_memcmp(lua_State *L) {
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
luasodium_bin2hex(lua_State *L) {
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
    if(hex == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);
    sodium_bin2hex(hex,hex_len+1,(const unsigned char *)bin,bin_len);
    lua_pushstring(L,hex);
    return 1;
}

/* luasodium.hex2bin(hex, [ignore]) */
static int
luasodium_hex2bin(lua_State *L) {
    const char *hex = NULL;
    const char *hex_end = NULL;
    const char *ignore = NULL;
    unsigned char *bin = NULL;

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
    if(bin == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(sodium_hex2bin(
        bin,bin_len,
        hex,hex_len,
        ignore, &out_bin_len,
        &hex_end) != 0) {
        lua_pushliteral(L,"error in hex2bin");
        return lua_error(L);
    }

    lua_pushlstring(L,(const char *)bin,out_bin_len);
    if(hex_end < hex + hex_len) {
        lua_pushlstring(L,hex_end,(hex + hex_len) - hex_end);
        return 2;
    }
    return 1;
}

/* luasodium.bin2base64(bin, variant) */
static int
luasodium_bin2base64(lua_State *L) {
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

    b64_len = sodium_base64_encoded_len(bin_len,variant);
    b64 = lua_newuserdata(L,b64_len);
    if(b64 == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    sodium_bin2base64(b64,b64_len,
      (const unsigned char *)bin, bin_len,
      variant);
    lua_pushstring(L,b64);
    return 1;
}

/* luasodium.base642bin(base64, variant, [ignore]) */
static int
luasodium_base642bin(lua_State *L) {
    const char *base64 = NULL;
    const char *base64_end = NULL;
    const char *ignore = NULL;
    unsigned char *bin = NULL;
    lua_Integer variant = 0;

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
        ignore = lua_tostring(L,4);
    }

    bin = lua_newuserdata(L,bin_len);
    if(bin == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(sodium_base642bin(
        bin,bin_len,
        base64,base64_len,
        ignore, &out_bin_len,
        &base64_end,variant) != 0) {
        lua_pushliteral(L,"error in base642bin");
        return lua_error(L);
    }

    lua_pushlstring(L,(const char *)bin,out_bin_len);
    if(base64_end < base64 + base64_len) {
        lua_pushlstring(L,base64_end,(base64 + base64_len) - base64_end);
        return 2;
    }
    return 1;
}

static int
luasodium_increment(lua_State *L) {
    const char *n = NULL;
    char *r = NULL;
    size_t nlen = 0;

    n = lua_tolstring(L,1,&nlen);
    r = lua_newuserdata(L,nlen);
    if(r == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    memcpy(r,n,nlen);

    sodium_increment((unsigned char *)r,nlen);
    lua_pushlstring(L,r,nlen);
    return 1;
}

static int
luasodium_add(lua_State *L) {
    const char *a = NULL;
    const char *b = NULL;
    char *r = NULL;
    size_t alen = 0;
    size_t blen = 0;

    a = lua_tolstring(L,1,&alen);
    b = lua_tolstring(L,2,&blen);

    if(alen != blen) {
        lua_pushliteral(L,"mismatched data sizes");
        return lua_error(L);
    }

    r = lua_newuserdata(L,alen);
    if(r == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    memcpy(r,a,alen);
    sodium_add((unsigned char *)r,(const unsigned char *)b,alen);
    lua_pushlstring(L,r,alen);
    return 1;
}

static int
luasodium_sub(lua_State *L) {
    const char *a = NULL;
    const char *b = NULL;
    char *r = NULL;
    size_t alen = 0;
    size_t blen = 0;

    a = lua_tolstring(L,1,&alen);
    b = lua_tolstring(L,2,&blen);

    if(alen != blen) {
        lua_pushliteral(L,"mismatched data sizes");
        return lua_error(L);
    }

    r = lua_newuserdata(L,alen);
    if(r == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    memcpy(r,a,alen);
    sodium_sub((unsigned char *)r,(const unsigned char *)b,alen);
    lua_pushlstring(L,r,alen);
    return 1;
}

static int
luasodium_compare(lua_State *L) {
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
luasodium_is_zero(lua_State *L) {
    const char *n = NULL;
    size_t nlen = 0;

    if(lua_isnoneornil(L,1)) {
        lua_pushliteral(L,"1 argument");
        return lua_error(L);
    }

    n = lua_tolstring(L,1,&nlen);
    lua_pushboolean(L,sodium_is_zero((const unsigned char *)n,nlen) == 1);
    return 1;
}

static int
luasodium_pad(lua_State *L) {
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
    if(r == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);
    memcpy(r,n,nlen);

    if(sodium_pad(&outlen,(unsigned char *)r,
        nlen,blocksize,rounded) != 0) {
        lua_pushliteral(L,"sodium_pad error");
        return lua_error(L);
    }
    lua_pushlstring(L,r,outlen);
    return 1;
}

static int
luasodium_unpad(lua_State *L) {
    const char *n = NULL;
    size_t nlen = 0;
    size_t blocksize = 0;
    size_t outlen = 0;

    n = lua_tolstring(L,1,&nlen);
    blocksize = lua_tointeger(L,2);

    if(sodium_unpad(&outlen,(const unsigned char *)n,
        nlen,blocksize) != 0) {
        lua_pushliteral(L,"sodium_unpad error");
        return lua_error(L);
    }
    lua_pushlstring(L,n,outlen);
    return 1;
}

static const struct luaL_Reg luasodium_methods[] = {
    { "init", luasodium_init },
    { "memcmp", luasodium_memcmp },
    { "bin2hex", luasodium_bin2hex },
    { "hex2bin", luasodium_hex2bin },
    { "bin2base64", luasodium_bin2base64 },
    { "base642bin", luasodium_base642bin },
    { "increment", luasodium_increment },
    { "add", luasodium_add },
    { "sub", luasodium_sub },
    { "compare", luasodium_compare },
    { "is_zero", luasodium_is_zero },
    { "pad", luasodium_pad },
    { "unpad", luasodium_unpad },
    { NULL, NULL },
};

static const ffi_pointer_t ffi_pointers[] = {
    sodium_init,
    sodium_memcmp,
    sodium_bin2hex,
    sodium_hex2bin,
    sodium_bin2base64,
    sodium_base642bin,
    sodium_increment,
    sodium_add,
    sodium_sub,
    sodium_compare,
    sodium_is_zero,
    sodium_pad,
    sodium_unpad,
    sodium_base64_encoded_len,
    NULL
};


int
luaopen_luasodium(lua_State *L) {
    unsigned int i = 0;
    const ffi_pointer_t *p = ffi_pointers;
    int top = lua_gettop(L);

    /* try loading ffi version */
    if(luaL_loadbuffer(L,luasodium_ffi,luasodium_ffi_length - 1,"luasodium-ffi.lua") == 0) {
        while(*p != NULL) {
          lua_pushlightuserdata(L,*p);
          p++;
          i++;
        }
        assert(i == 14);
        lua_pushinteger(L,sodium_base64_VARIANT_ORIGINAL);
        lua_pushinteger(L,sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
        lua_pushinteger(L,sodium_base64_VARIANT_URLSAFE);
        lua_pushinteger(L,sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        i += 4;
        if(lua_pcall(L,i,1,0) == 0) {
            return 1;
        }
#ifdef DEBUG
        else {
            fprintf(stderr,"sodium_ffi error: %s\n",lua_tostring(L,-1));
            fflush(stderr);
        }
#endif
    }

    /* load traditional C API */
    lua_settop(L,top);
    lua_newtable(L);

    luaL_setfuncs(L,luasodium_methods,0);

    lua_pushinteger(L,sodium_base64_VARIANT_ORIGINAL);
    lua_setfield(L,-2,"base64_VARIANT_ORIGINAL");
    lua_pushinteger(L,sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    lua_setfield(L,-2,"base64_VARIANT_ORIGINAL_NO_PADDING");
    lua_pushinteger(L,sodium_base64_VARIANT_URLSAFE);
    lua_setfield(L,-2,"base64_VARIANT_URLSAFE");
    lua_pushinteger(L,sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    lua_setfield(L,-2,"base64_VARIANT_URLSAFE_NO_PADDING");

    return 1;
}
