#include "../luasodium-c.h"
#include "constants.h"
#include "functions.h"

#include <stdlib.h>
#include <string.h>

/* crypto_secretbox_keygen() */
static int
lua_crypto_secretbox_keygen(lua_State *L) {
    unsigned char *k = NULL;

    const ls_crypto_secretbox_keygen_func_def *def = NULL;
    def = (const ls_crypto_secretbox_keygen_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    k = lua_newuserdata(L,def->keysize);
    if(k == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);
    def->func(k);
    lua_pushlstring(L,(const char *)k,def->keysize);
    sodium_memzero(k,def->keysize);
    return 1;
}


/* crypto_secretbox, crypto_secretbox_xsalsa20poly1305, etc */
static int
lua_crypto_secretbox(lua_State *L) {
    unsigned char *output      = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    unsigned char *tmp_input   = NULL;

    size_t outputlen = 0;
    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    const ls_crypto_secretbox_func_def *def = NULL;
    def = (const ls_crypto_secretbox_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != def->noncesize) {
        return luaL_error(L,"wrong nonce size, expected: %d",def->noncesize);
    }

    if(keylen != def->keysize) {
        return luaL_error(L,"wrong key size, expected: %d",def->keysize);
    }

    outputlen = inputlen + def->macsize;

    tmp_input = (unsigned char *)lua_newuserdata(L,inputlen + def->zerosize);
    if(tmp_input == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    output = (unsigned char *)lua_newuserdata(L,outputlen + def->boxzerosize);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    sodium_memzero(tmp_input,def->zerosize);
    sodium_memzero(output,def->boxzerosize);

    memcpy(&tmp_input[def->zerosize],input,inputlen);

    if(def->func(output,tmp_input,inputlen+def->zerosize,nonce,key) == -1) {
        return luaL_error(L,"%s error",def->name);
    }

    lua_pushlstring(L,(const char *)&output[def->boxzerosize],outputlen);
    sodium_memzero(tmp_input,inputlen + def->zerosize);
    sodium_memzero(output,outputlen + def->boxzerosize);
    return 1;
}

/* crypto_secretbox_open, crypto_secretbox_xsalsa20poly1305_open, etc */
static int
lua_crypto_secretbox_open(lua_State *L) {
    unsigned char *output      = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    unsigned char *tmp_input   = NULL;

    size_t outputlen = 0;
    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    const ls_crypto_secretbox_open_func_def *def = NULL;
    def = (const ls_crypto_secretbox_open_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(inputlen <= def->macsize) {
        return luaL_error(L,"wront mac size, expected at least: %d",def->macsize);
    }

    if(noncelen != def->noncesize) {
        return luaL_error(L,"wrong nonce size, expected: %d",def->noncesize);
    }

    if(keylen != def->keysize) {
        return luaL_error(L,"wrong key size, expected: %d",def->keysize);
    }

    outputlen = inputlen - def->macsize;

    tmp_input = (unsigned char *)lua_newuserdata(L,inputlen + def->boxzerosize);
    if(tmp_input == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    output = (unsigned char *)lua_newuserdata(L,outputlen + def->zerosize);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    sodium_memzero(tmp_input,def->boxzerosize);
    sodium_memzero(output,def->zerosize);

    memcpy(&tmp_input[def->boxzerosize],input,inputlen);

    if(def->func(output,tmp_input,inputlen+def->boxzerosize,nonce,key) == -1) {
        return luaL_error(L,"%s error",def->name);
    }

    lua_pushlstring(L,(const char *)&output[def->zerosize],outputlen);
    sodium_memzero(tmp_input,inputlen + def->boxzerosize);
    sodium_memzero(output,outputlen + def->zerosize);
    return 1;
}

/* crypto_secretbox, crypto_secretbox_xsalsa20poly1305, etc */
static int
lua_crypto_secretbox_easy(lua_State *L) {
    unsigned char *output      = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    size_t outputlen = 0;
    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    const ls_crypto_secretbox_open_func_def *def = NULL;
    def = (const ls_crypto_secretbox_open_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != def->noncesize) {
        return luaL_error(L,"wrong nonce size, expected: %d",def->noncesize);
    }

    if(keylen != def->keysize) {
        return luaL_error(L,"wrong key size, expected: %d",def->keysize);
    }

    outputlen = inputlen + def->macsize;

    output = (unsigned char *)lua_newuserdata(L,outputlen);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(def->func(output,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"%s error",def->name);
    }

    lua_pushlstring(L,(const char *)output,outputlen);
    sodium_memzero(output,outputlen);
    return 1;
}

/* crypto_secretbox, crypto_secretbox_xsalsa20poly1305, etc */
static int
lua_crypto_secretbox_open_easy(lua_State *L) {
    unsigned char *output      = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key   = NULL;

    size_t outputlen = 0;
    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    const ls_crypto_secretbox_open_easy_func_def *def = NULL;
    def = (const ls_crypto_secretbox_open_easy_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(inputlen <= def->macsize) {
        return luaL_error(L,"wrong mac size, expected at least: %d",def->macsize);
    }

    if(noncelen != def->noncesize) {
        return luaL_error(L,"wrong nonce size, expected: %d",def->noncesize);
    }

    if(keylen != def->keysize) {
        return luaL_error(L,"wrong key size, expected: %d",def->keysize);
    }

    outputlen = inputlen - def->macsize;

    output = (unsigned char *)lua_newuserdata(L,outputlen);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(def->func(output,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"%s error",def->name);
    }

    lua_pushlstring(L,(const char *)output,outputlen);
    sodium_memzero(output,outputlen);
    return 1;
}

/* crypto_secretbox_detached(message, nonce, key) */
static int
lua_crypto_secretbox_detached(lua_State *L) {
    unsigned char *output = NULL;
    unsigned char *mac = NULL;
    const unsigned char *input = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key = NULL;

    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;

    const ls_crypto_secretbox_detached_func_def *def = NULL;
    def = (const ls_crypto_secretbox_detached_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    nonce = (const unsigned char *)lua_tolstring(L,2,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,3,&keylen);

    if(noncelen != def->noncesize) {
        return luaL_error(L,"wrong nonce size, expected: %d",def->noncesize);
    }

    if(keylen != def->keysize) {
        return luaL_error(L,"wrong key size, expected: %d",def->keysize);
    }

    output = lua_newuserdata(L,inputlen);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    mac = lua_newuserdata(L,def->macsize);
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(def->func(output,mac,input,inputlen,nonce,key) == -1) {
        return luaL_error(L,"%s error",def->name);
    }

    lua_pushlstring(L,(const char *)output,inputlen);
    lua_pushlstring(L,(const char *)mac,def->macsize);

    sodium_memzero(output,inputlen);
    sodium_memzero(mac,def->macsize);
    return 2;
}

/* crypto_secretbox_open_detached(cipher, mac, nonce, key) */
static int
lua_crypto_secretbox_open_detached(lua_State *L) {
    unsigned char *output = NULL;
    const unsigned char *input = NULL;
    const unsigned char *mac = NULL;
    const unsigned char *nonce = NULL;
    const unsigned char *key = NULL;

    size_t inputlen = 0;
    size_t noncelen = 0;
    size_t keylen = 0;
    size_t maclen = 0;

    const ls_crypto_secretbox_open_detached_func_def *def = NULL;
    def = (const ls_crypto_secretbox_open_detached_func_def *) lua_touserdata(L,lua_upvalueindex(1));

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 4 parameters");
        return lua_error(L);
    }

    input = (const unsigned char *)lua_tolstring(L,1,&inputlen);
    mac   = (const unsigned char *)lua_tolstring(L,2,&maclen);
    nonce = (const unsigned char *)lua_tolstring(L,3,&noncelen);
    key   = (const unsigned char *)lua_tolstring(L,4,&keylen);

    if(maclen != def->macsize) {
        return luaL_error(L,"wrong mac size, expected: %d",def->macsize);
    }

    if(noncelen != def->noncesize) {
        return luaL_error(L,"wrong nonce size, expected: %d",def->noncesize);
    }

    if(keylen != def->keysize) {
        return luaL_error(L,"wrong key size, expected: %d",def->keysize);
    }

    output = lua_newuserdata(L,inputlen);
    if(output == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }

    lua_pop(L,1);

    if(def->func(output,input,mac,inputlen,nonce,key) == -1) {
        return luaL_error(L,"%s error",def->name);
    }

    lua_pushlstring(L,(const char *)output,inputlen);
    sodium_memzero(output,inputlen);
    return 1;
}

static const ls_crypto_secretbox_keygen_func_def * const ls_crypto_secretbox_keygen_funcs[] = {
    &ls_crypto_secretbox_keygen_func,
    &ls_crypto_secretbox_xsalsa20poly1305_keygen_func,
    NULL,
};

static const ls_crypto_secretbox_func_def * const ls_crypto_secretbox_funcs[] = {
    &ls_crypto_secretbox_func,
    &ls_crypto_secretbox_xsalsa20poly1305_func,
    NULL,
};

static const ls_crypto_secretbox_open_func_def * const ls_crypto_secretbox_open_funcs[] = {
    &ls_crypto_secretbox_open_func,
    &ls_crypto_secretbox_xsalsa20poly1305_open_func,
    NULL,
};

static const ls_crypto_secretbox_easy_func_def * const ls_crypto_secretbox_easy_funcs[] = {
    &ls_crypto_secretbox_easy_func,
    &ls_crypto_secretbox_xchacha20poly1305_easy_func,
    NULL,
};

static const ls_crypto_secretbox_open_easy_func_def * const ls_crypto_secretbox_open_easy_funcs[] = {
    &ls_crypto_secretbox_open_easy_func,
    &ls_crypto_secretbox_xchacha20poly1305_open_easy_func,
    NULL,
};

static const ls_crypto_secretbox_detached_func_def * const ls_crypto_secretbox_detached_funcs[] = {
    &ls_crypto_secretbox_detached_func,
    &ls_crypto_secretbox_xchacha20poly1305_detached_func,
    NULL,
};

static const ls_crypto_secretbox_open_detached_func_def * const ls_crypto_secretbox_open_detached_funcs[] = {
    &ls_crypto_secretbox_open_detached_func,
    &ls_crypto_secretbox_xchacha20poly1305_open_detached_func,
    NULL,
};

static void
ls_push_crypto_secretbox_keygen_closures(lua_State *L) {
    const ls_crypto_secretbox_keygen_func_def * const *f = ls_crypto_secretbox_keygen_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_secretbox_keygen,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_secretbox_closures(lua_State *L) {
    const ls_crypto_secretbox_func_def * const *f = ls_crypto_secretbox_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_secretbox,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_secretbox_open_closures(lua_State *L) {
    const ls_crypto_secretbox_open_func_def * const *f = ls_crypto_secretbox_open_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_secretbox_open,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_secretbox_easy_closures(lua_State *L) {
    const ls_crypto_secretbox_easy_func_def * const *f = ls_crypto_secretbox_easy_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_secretbox_easy,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_secretbox_open_easy_closures(lua_State *L) {
    const ls_crypto_secretbox_open_easy_func_def * const *f = ls_crypto_secretbox_open_easy_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_secretbox_open_easy,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_secretbox_detached_closures(lua_State *L) {
    const ls_crypto_secretbox_detached_func_def * const *f = ls_crypto_secretbox_detached_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_secretbox_detached,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

static void
ls_push_crypto_secretbox_open_detached_closures(lua_State *L) {
    const ls_crypto_secretbox_open_detached_func_def * const *f = ls_crypto_secretbox_open_detached_funcs;
    for(; f[0] != NULL; f++) {
        lua_pushlightuserdata(L,(void *)f[0]);
        lua_pushcclosure(L,lua_crypto_secretbox_open_detached,1);
        lua_setfield(L,-2,f[0]->name);
    }
}

int
luaopen_luasodium_crypto_secretbox_core(lua_State *L) {
    LUASODIUM_INIT(L)
    lua_newtable(L);
    luasodium_set_constants(L,ls_crypto_secretbox_constants);

    ls_push_crypto_secretbox_closures(L);
    ls_push_crypto_secretbox_open_closures(L);
    ls_push_crypto_secretbox_easy_closures(L);
    ls_push_crypto_secretbox_open_easy_closures(L);
    ls_push_crypto_secretbox_detached_closures(L);
    ls_push_crypto_secretbox_open_detached_closures(L);
    ls_push_crypto_secretbox_keygen_closures(L);

    return 1;
}
