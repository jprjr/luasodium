#define PASTE(a,b) a ## b
#define FUNC(b) PASTE(ls_,b)
#define STR(b) #b

static int
FUNC(KEYPAIR) (lua_State *L) {
    unsigned char pk[PUBLICKEYBYTES];
    unsigned char sk[SECRETKEYBYTES];

    /* LCOV_EXCL_START */
    if(KEYPAIR(pk,sk) == -1) {
        lua_pushnil(L);
        lua_pushliteral(L,STR(KEYPAIR) " error");
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)pk,PUBLICKEYBYTES);
    lua_pushlstring(L,(const char *)sk,SECRETKEYBYTES);
    sodium_memzero(pk,PUBLICKEYBYTES);
    sodium_memzero(sk,SECRETKEYBYTES);
    return 2;
}

static int
FUNC(SEED_KEYPAIR) (lua_State *L) {
    unsigned char pk[PUBLICKEYBYTES];
    unsigned char sk[SECRETKEYBYTES];
    const unsigned char *seed = NULL;
    size_t len = 0;

    seed = (const unsigned char *)lua_tolstring(L,1,&len);

    if(len != SEEDBYTES) {
        return luaL_error(L,"wrong seed length, expected %d", SEEDBYTES);
    }

    /* LCOV_EXCL_START */
    if(SEED_KEYPAIR(pk,sk,seed) == -1) {
        lua_pushnil(L);
        lua_pushliteral(L,STR(SEED_KEYPAIR) " error");
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)pk,PUBLICKEYBYTES);
    lua_pushlstring(L,(const char *)sk,SECRETKEYBYTES);
    sodium_memzero(pk,PUBLICKEYBYTES);
    sodium_memzero(sk,SECRETKEYBYTES);
    return 2;
}

static int
FUNC(CLIENT_SESSION_KEYS) (lua_State *L) {
    unsigned char rx[SESSIONKEYBYTES];
    unsigned char tx[SESSIONKEYBYTES];

    const unsigned char *client_pk = NULL;
    const unsigned char *client_sk = NULL;
    const unsigned char *server_pk = NULL;
    size_t client_pk_len = 0;
    size_t client_sk_len = 0;
    size_t server_pk_len = 0;

    client_pk = (const unsigned char *)lua_tolstring(L,1,&client_pk_len);
    client_sk = (const unsigned char *)lua_tolstring(L,2,&client_sk_len);
    server_pk = (const unsigned char *)lua_tolstring(L,3,&server_pk_len);

    if(client_pk_len != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong client public key length, expected %d", PUBLICKEYBYTES);
    }
    if(client_sk_len != SECRETKEYBYTES) {
        return luaL_error(L,"wrong client secret key length, expected %d", PUBLICKEYBYTES);
    }
    if(server_pk_len != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong server public key length, expected %d", PUBLICKEYBYTES);
    }

    /* LCOV_EXCL_START */
    if(CLIENT_SESSION_KEYS(rx,tx,client_pk,client_sk,server_pk) == -1) {
        lua_pushnil(L);
        lua_pushliteral(L,STR(CLIENT_SESSION_KEYS) " error");
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)rx,SESSIONKEYBYTES);
    lua_pushlstring(L,(const char *)tx,SESSIONKEYBYTES);
    sodium_memzero(rx,SESSIONKEYBYTES);
    sodium_memzero(tx,SESSIONKEYBYTES);
    return 2;
}

static int
FUNC(SERVER_SESSION_KEYS) (lua_State *L) {
    unsigned char rx[SESSIONKEYBYTES];
    unsigned char tx[SESSIONKEYBYTES];

    const unsigned char *server_pk = NULL;
    const unsigned char *server_sk = NULL;
    const unsigned char *client_pk = NULL;
    size_t server_pk_len = 0;
    size_t server_sk_len = 0;
    size_t client_pk_len = 0;

    server_pk = (const unsigned char *)lua_tolstring(L,1,&server_pk_len);
    server_sk = (const unsigned char *)lua_tolstring(L,2,&server_sk_len);
    client_pk = (const unsigned char *)lua_tolstring(L,3,&client_pk_len);

    if(server_pk_len != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong server public key length, expected %d", PUBLICKEYBYTES);
    }
    if(server_sk_len != SECRETKEYBYTES) {
        return luaL_error(L,"wrong server secret key length, expected %d", PUBLICKEYBYTES);
    }
    if(client_pk_len != PUBLICKEYBYTES) {
        return luaL_error(L,"wrong client public key length, expected %d", PUBLICKEYBYTES);
    }

    /* LCOV_EXCL_START */
    if(SERVER_SESSION_KEYS(rx,tx,server_pk,server_sk,client_pk) == -1) {
        lua_pushnil(L);
        lua_pushliteral(L,STR(SERVER_SESSION_KEYS) " error");
        return 2;
    }
    /* LCOV_EXCL_STOP */

    lua_pushlstring(L,(const char *)rx,SESSIONKEYBYTES);
    lua_pushlstring(L,(const char *)tx,SESSIONKEYBYTES);
    sodium_memzero(rx,SESSIONKEYBYTES);
    sodium_memzero(tx,SESSIONKEYBYTES);
    return 2;
}
