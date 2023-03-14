#include "../luasodium-c.h"
#include "../internals/ls_lua_set_constants.h"
#include "constants.h"

#include <stdlib.h>
#include <string.h>

typedef int (*ls_crypto_kx_keypair_ptr)(
  unsigned char *,
  unsigned char *);

typedef int (*ls_crypto_kx_seed_keypair_ptr)(
  unsigned char *,
  unsigned char *,
  const unsigned char *);

typedef int (*ls_crypto_kx_session_keys_ptr)(
  unsigned char *,
  unsigned char *,
  const unsigned char *,
  const unsigned char *,
  const unsigned char *);

/* in other modules we use closures, I want to try just
 * generating functions via C macro instead */

#define KEYPAIR crypto_kx_keypair
#define SEED_KEYPAIR crypto_kx_seed_keypair
#define CLIENT_SESSION_KEYS crypto_kx_client_session_keys
#define SERVER_SESSION_KEYS crypto_kx_server_session_keys
#define PUBLICKEYBYTES crypto_kx_PUBLICKEYBYTES
#define SECRETKEYBYTES crypto_kx_SECRETKEYBYTES
#define SESSIONKEYBYTES crypto_kx_SESSIONKEYBYTES
#define SEEDBYTES crypto_kx_SEEDBYTES

#include "impl.h"

LS_PUBLIC
int
luaopen_luasodium_crypto_kx_core(lua_State *L) {
    /* LCOV_EXCL_START */
    LUASODIUM_INIT(L)
    /* LCOV_EXCL_STOP */
    lua_newtable(L);

    ls_lua_set_constants(L,ls_crypto_kx_constants,lua_gettop(L));

    lua_pushcclosure(L,ls_crypto_kx_keypair,0);
    lua_setfield(L,-2,"crypto_kx_keypair");

    lua_pushcclosure(L,ls_crypto_kx_seed_keypair,0);
    lua_setfield(L,-2,"crypto_kx_seed_keypair");

    lua_pushcclosure(L,ls_crypto_kx_client_session_keys,0);
    lua_setfield(L,-2,"crypto_kx_client_session_keys");

    lua_pushcclosure(L,ls_crypto_kx_server_session_keys,0);
    lua_setfield(L,-2,"crypto_kx_server_session_keys");

    return 1;
}
