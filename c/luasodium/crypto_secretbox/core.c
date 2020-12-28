#include "../luasodium-c.h"
#include "constants.h"

/* crypto_secretbox_easy(message, nonce, key) */
static int
luasodium_secretbox_easy(lua_State *L) {
    unsigned char *c = NULL;
    const unsigned char *m = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;

    size_t clen = 0;
    size_t mlen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != crypto_secretbox_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_secretbox_NONCEBYTES);
    }

    if(klen != crypto_secretbox_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_secretbox_KEYBYTES);
    }

    clen = mlen + crypto_secretbox_MACBYTES;

    c = lua_newuserdata(L,clen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);

    if(crypto_secretbox_easy(c,m,mlen,n,k) == -1) {
        lua_pushliteral(L,"crypto_secretbox_easy error");
        return lua_error(L);
    }

    lua_pushlstring(L,(const char *)c,clen);
    return 1;
}

/* crypto_secretbox_open_easy(cipher, nonce, key) */
static int
luasodium_secretbox_open_easy(lua_State *L) {
    unsigned char *m = NULL;
    const unsigned char *c = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;

    size_t mlen = 0;
    size_t clen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    c = (const unsigned char *)lua_tolstring(L,1,&clen);
    n = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(clen < crypto_secretbox_MACBYTES) {
        return luaL_error(L,"wrong cipher size, expected at least: %d",crypto_secretbox_MACBYTES);
    }

    if(nlen != crypto_secretbox_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_secretbox_NONCEBYTES);
    }

    if(klen != crypto_secretbox_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_secretbox_KEYBYTES);
    }

    mlen = clen - crypto_secretbox_MACBYTES;

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

    if(crypto_secretbox_open_easy(m,c,clen,n,k) == -1) {
        lua_pushliteral(L,"crypto_secretbox_open_easy error");
        return lua_error(L);
    }

    lua_pushlstring(L,(const char *)m,mlen);
    return 1;
}

/* crypto_secretbox_detached(message, nonce, key) */
static int
luasodium_secretbox_detached(lua_State *L) {
    unsigned char *c = NULL;
    unsigned char *mac = NULL;
    const unsigned char *m = NULL;
    const unsigned char *n = NULL;
    const unsigned char *k = NULL;

    size_t mlen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,3)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    m = (const unsigned char *)lua_tolstring(L,1,&mlen);
    n = (const unsigned char *)lua_tolstring(L,2,&nlen);
    k = (const unsigned char *)lua_tolstring(L,3,&klen);

    if(nlen != crypto_secretbox_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_secretbox_NONCEBYTES);
    }

    if(klen != crypto_secretbox_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_secretbox_KEYBYTES);
    }

    c = lua_newuserdata(L,mlen);
    if(c == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    mac = lua_newuserdata(L,crypto_secretbox_MACBYTES);
    if(mac == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,2);

    if(crypto_secretbox_detached(c,mac,m,mlen,n,k) == -1) {
        lua_pushliteral(L,"crypto_secretbox_detached error");
        return lua_error(L);
    }

    lua_pushlstring(L,(const char *)c,mlen);
    lua_pushlstring(L,(const char *)mac,crypto_secretbox_MACBYTES);
    return 2;
}

/* crypto_secretbox_open_detached(cipher, mac, nonce, key) */
static int
luasodium_secretbox_open_detached(lua_State *L) {
    unsigned char *m = NULL;
    const unsigned char *c   = NULL;
    const unsigned char *mac = NULL;
    const unsigned char *n   = NULL;
    const unsigned char *k   = NULL;

    size_t clen = 0;
    size_t maclen = 0;
    size_t nlen = 0;
    size_t klen = 0;

    if(lua_isnoneornil(L,4)) {
        lua_pushliteral(L,"requires 3 parameters");
        return lua_error(L);
    }

    c = (const unsigned char *)lua_tolstring(L,1,&clen);
    mac = (const unsigned char *)lua_tolstring(L,2,&maclen);
    n = (const unsigned char *)lua_tolstring(L,3,&nlen);
    k = (const unsigned char *)lua_tolstring(L,4,&klen);

    if(maclen != crypto_secretbox_MACBYTES) {
        return luaL_error(L,"wrong mac size, expected: %d",crypto_secretbox_MACBYTES);
    }

    if(nlen != crypto_secretbox_NONCEBYTES) {
        return luaL_error(L,"wrong nonce size, expected: %d",crypto_secretbox_NONCEBYTES);
    }

    if(klen != crypto_secretbox_KEYBYTES) {
        return luaL_error(L,"wrong key size, expected: %d",crypto_secretbox_KEYBYTES);
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

    if(crypto_secretbox_open_detached(m,c,mac,clen,n,k) == -1) {
        lua_pushliteral(L,"crypto_secretbox_open_detached error");
        return lua_error(L);
    }

    lua_pushlstring(L,(const char *)m,clen);
    return 1;
}

/* crypto_secretbox_keygen() */
static int
luasodium_secretbox_keygen(lua_State *L) {
    unsigned char *k = lua_newuserdata(L,crypto_secretbox_KEYBYTES);
    if(k == NULL) {
        lua_pushliteral(L,"out of memory");
        return lua_error(L);
    }
    lua_pop(L,1);
    crypto_secretbox_keygen(k);
    lua_pushlstring(L,(const char *)k,crypto_secretbox_KEYBYTES);
    return 1;
}

static const struct luaL_Reg luasodium_secretbox[] = {
    { "easy", luasodium_secretbox_easy },
    { "open_easy", luasodium_secretbox_open_easy },
    { "detached", luasodium_secretbox_detached },
    { "open_detached", luasodium_secretbox_open_detached },
    { "keygen", luasodium_secretbox_keygen },
    { NULL, NULL },
};

int
luaopen_luasodium_crypto_secretbox_core(lua_State *L) {
    lua_newtable(L);

    luaL_setfuncs(L,luasodium_secretbox,0);
    luasodium_set_constants(L,luasodium_secretbox_constants);

    return 1;
}
