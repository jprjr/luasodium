#include "../luasodium-c.h"
#include "constants.h"
#include "types.h"

#include <stdlib.h>
#include <string.h>

/* crypto_secretbox, crypto_secretbox_xsalsa20poly1305, etc */
static int
luasodium_secretbox_closure(lua_State *L) {
    unsigned char *output      = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    unsigned char *tmp_input   = NULL;

    size_t outputlen = 0;
    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    const char *fname          = NULL;
    secretbox_func f          = NULL;
    size_t noncebytes         = 0;
    size_t keybytes           = 0;
    size_t inputzerobytes     = 0;
    size_t outputzerobytes    = 0;
    int    macbytes           = 0;

    fname            = lua_tostring(L,lua_upvalueindex(1));
    f                = (secretbox_func) lua_touserdata(L, lua_upvalueindex(2));
    noncebytes       = lua_tointeger(L,lua_upvalueindex(3));
    keybytes         = lua_tointeger(L,lua_upvalueindex(4));
    inputzerobytes   = lua_tointeger(L,lua_upvalueindex(5));
    outputzerobytes  = lua_tointeger(L,lua_upvalueindex(6));
    macbytes         = lua_tointeger(L,lua_upvalueindex(7));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != noncebytes) {
        return luaL_error(L,"wrong nonce size, expected: %d",noncebytes);
    }

    if(keylen != keybytes) {
        return luaL_error(L,"wrong key size, expected: %d",keybytes);
    }

    if( ((int)inputlen) + macbytes < 0) {
        return luaL_error(L,"wrong input size, expected at least: %d",macbytes > 0 ? macbytes : -macbytes);
    }

    outputlen = (size_t)(((int)inputlen) + macbytes);

    tmp_input = (unsigned char *)lua_newuserdata(L,inputlen + inputzerobytes);
    if(tmp_input == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    output = (unsigned char *)lua_newuserdata(L,outputlen + outputzerobytes);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    sodium_memzero(tmp_input,inputzerobytes);
    sodium_memzero(output,outputzerobytes);

    memcpy(&tmp_input[inputzerobytes],input,inputlen);

    if(f(output,tmp_input,inputlen+inputzerobytes,nonce,key) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)&output[outputzerobytes],outputlen);
    sodium_memzero(tmp_input,inputlen + inputzerobytes);
    sodium_memzero(output,outputlen + outputzerobytes);
    return 1;
}

/* crypto_secretbox, crypto_secretbox_xsalsa20poly1305, etc */
static int
luasodium_secretbox_easy_closure(lua_State *L) {
    unsigned char *output      = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    size_t outputlen = 0;
    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    const char *fname          = NULL;
    secretbox_easy_func f          = NULL;
    size_t noncebytes         = 0;
    size_t keybytes           = 0;
    int    macbytes           = 0;

    fname            = lua_tostring(L,lua_upvalueindex(1));
    f                = (secretbox_easy_func) lua_touserdata(L, lua_upvalueindex(2));
    noncebytes       = lua_tointeger(L,lua_upvalueindex(3));
    keybytes         = lua_tointeger(L,lua_upvalueindex(4));
    macbytes         = lua_tointeger(L,lua_upvalueindex(5));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != noncebytes) {
        return luaL_error(L,"wrong nonce size, expected: %d",noncebytes);
    }

    if(keylen != keybytes) {
        return luaL_error(L,"wrong key size, expected: %d",keybytes);
    }

    if( ((int)inputlen) + macbytes < 0) {
        return luaL_error(L,"wrong input size, expected at least: %d",macbytes > 0 ? macbytes : -macbytes);
    }

    outputlen = (size_t)(((int)inputlen) + macbytes);

    output = (unsigned char *)lua_newuserdata(L,outputlen);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(f(output,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)output,outputlen);
    sodium_memzero(output,outputlen);
    return 1;
}

/* crypto_secretbox_detached(message, nonce, key) */
static int
luasodium_secretbox_detached_closure(lua_State *L) {
    unsigned char *output = NULL;
    unsigned char *mac = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key = NULL;

    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    const char *fname          = NULL;
    secretbox_detached_func f  = NULL;
    size_t noncebytes          = 0;
    size_t keybytes            = 0;
    size_t macbytes            = 0;

    fname            = lua_tostring(L,lua_upvalueindex(1));
    f                = (secretbox_detached_func) lua_touserdata(L, lua_upvalueindex(2));
    noncebytes       = lua_tointeger(L,lua_upvalueindex(3));
    keybytes         = lua_tointeger(L,lua_upvalueindex(4));
    macbytes         = lua_tointeger(L,lua_upvalueindex(5));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != noncebytes) {
        return luaL_error(L,"wrong nonce size, expected: %d",noncebytes);
    }

    if(keylen != keybytes) {
        return luaL_error(L,"wrong key size, expected: %d",keybytes);
    }

    output = lua_newuserdata(L,inputlen);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    mac = lua_newuserdata(L,macbytes);
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(f(output,mac,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)output,inputlen);
    lua_pushlstring(L,(const char *)mac,macbytes);

    sodium_memzero(output,inputlen);
    sodium_memzero(mac,macbytes);
    return 2;
}

/* crypto_secretbox_open_detached(cipher, mac, nonce, key) */
static int
luasodium_secretbox_open_detached_closure(lua_State *L) {
    unsigned char *output = NULL;
    const unsigned char *input = NULL;
    const unsigned char *mac = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key = NULL;

    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;
    size_t maclen = 0;

    const char *fname          = NULL;
    secretbox_open_detached_func f  = NULL;
    size_t noncebytes          = 0;
    size_t keybytes            = 0;
    size_t macbytes            = 0;

    fname            = lua_tostring(L,lua_upvalueindex(1));
    f                = (secretbox_open_detached_func) lua_touserdata(L, lua_upvalueindex(2));
    noncebytes       = lua_tointeger(L,lua_upvalueindex(3));
    keybytes         = lua_tointeger(L,lua_upvalueindex(4));
    macbytes         = lua_tointeger(L,lua_upvalueindex(5));

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    mac   = (const unsigned char *)lua_tolstring(L,2,&maclen);
    nonce = (const unsigned char *)lua_tolstring(L,3,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,4,&keylen);

    if(maclen != macbytes) {
        return luaL_error(L,"wrong mac size, expected: %d",macbytes);
    }

    if(noncelen != noncebytes) {
        return luaL_error(L,"wrong nonce size, expected: %d",noncebytes);
    }

    if(keylen != keybytes) {
        return luaL_error(L,"wrong key size, expected: %d",keybytes);
    }

    output = lua_newuserdata(L,inputlen);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }

    lua_pop(L,1);

    if(f(output,input,mac,inputlen,nonce,key) == -1) {
        return luaL_error(L,"%s error",fname);
    }

    lua_pushlstring(L,(const char *)output,inputlen);
    sodium_memzero(output,inputlen);
    return 1;
}

/* crypto_secretbox_keygen() */
static int
luasodium_secretbox_keygen_closure(lua_State *L) {
    unsigned char *k = NULL;

    secretbox_keygen_func f = NULL;
    size_t size = 0;

    f    = (secretbox_keygen_func) lua_touserdata(L, lua_upvalueindex(2));
    size =  lua_tointeger(L,lua_upvalueindex(3));

    k = lua_newuserdata(L,size);
    if(k == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);
    f(k);
    lua_pushlstring(L,(const char *)k,size);
    sodium_memzero(k,size);
    return 1;
}

static const struct luaL_Reg luasodium_secretbox[] = {
    { NULL, NULL },
};

static void
push_secretbox_closures(lua_State *L) {
    const secretbox_func_def *f = secretbox_funcs;
    while(f->secretbox != NULL) {
        lua_pushstring(L,f->secretbox_name);
        lua_pushlightuserdata(L,f->secretbox);
        lua_pushinteger(L,f->noncebytes);
        lua_pushinteger(L,f->keybytes);
        lua_pushinteger(L,f->zerobytes);
        lua_pushinteger(L,f->boxzerobytes);
        lua_pushinteger(L,f->macbytes);
        lua_pushcclosure(L, luasodium_secretbox_closure, 7);
        lua_setfield(L,-2,f->secretbox_name);

        lua_pushstring(L,f->open_name);
        lua_pushlightuserdata(L,f->open);
        lua_pushinteger(L,f->noncebytes);
        lua_pushinteger(L,f->keybytes);
        lua_pushinteger(L,f->boxzerobytes);
        lua_pushinteger(L,f->zerobytes);
        lua_pushinteger(L,((int)f->macbytes) * -1);
        lua_pushcclosure(L, luasodium_secretbox_closure, 7);
        lua_setfield(L,-2,f->open_name);
        f++;
    }
}

static void
push_secretbox_easy_closures(lua_State *L) {
    const secretbox_easy_func_def *f = secretbox_easy_funcs;
    while(f->secretbox != NULL) {
        lua_pushstring(L,f->secretbox_name);
        lua_pushlightuserdata(L,f->secretbox);
        lua_pushinteger(L,f->noncebytes);
        lua_pushinteger(L,f->keybytes);
        lua_pushinteger(L,f->macbytes);
        lua_pushcclosure(L, luasodium_secretbox_easy_closure, 5);
        lua_setfield(L,-2,f->secretbox_name);

        lua_pushstring(L,f->open_name);
        lua_pushlightuserdata(L,f->open);
        lua_pushinteger(L,f->noncebytes);
        lua_pushinteger(L,f->keybytes);
        lua_pushinteger(L,((int)f->macbytes) * -1);
        lua_pushcclosure(L, luasodium_secretbox_easy_closure, 5);
        lua_setfield(L,-2,f->open_name);
        f++;
    }
}

static void
push_secretbox_detached_closures(lua_State *L) {
    const secretbox_detached_func_def *f = secretbox_detached_funcs;
    while(f->secretbox != NULL) {
        lua_pushstring(L,f->secretbox_name);
        lua_pushlightuserdata(L,f->secretbox);
        lua_pushinteger(L,f->noncebytes);
        lua_pushinteger(L,f->keybytes);
        lua_pushinteger(L,f->macbytes);
        lua_pushcclosure(L, luasodium_secretbox_detached_closure, 5);
        lua_setfield(L,-2,f->secretbox_name);

        lua_pushstring(L,f->open_name);
        lua_pushlightuserdata(L,f->open);
        lua_pushinteger(L,f->noncebytes);
        lua_pushinteger(L,f->keybytes);
        lua_pushinteger(L,f->macbytes);
        lua_pushcclosure(L, luasodium_secretbox_open_detached_closure, 5);
        lua_setfield(L,-2,f->open_name);
        f++;
    }
}

static void
push_secretbox_keygen_closures(lua_State *L) {
    const secretbox_keygen_func_def *f = secretbox_keygen_funcs;
    while(f->keygen != NULL) {
        lua_pushstring(L,f->name);
        lua_pushlightuserdata(L,f->keygen);
        lua_pushinteger(L,f->size);
        lua_pushcclosure(L, luasodium_secretbox_keygen_closure, 3);
        lua_setfield(L,-2,f->name);
        f++;
    }
}

int
luaopen_luasodium_crypto_secretbox_core(lua_State *L) {
    LUASODIUM_INIT(L)
    lua_newtable(L);

    luaL_setfuncs(L,luasodium_secretbox,0);
    luasodium_set_constants(L,luasodium_secretbox_constants);

    push_secretbox_closures(L);
    push_secretbox_easy_closures(L);
    push_secretbox_detached_closures(L);
    push_secretbox_keygen_closures(L);

    return 1;
}
