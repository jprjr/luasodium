#include "crypto_auth/core.h"
#include "crypto_box/core.h"
#include "crypto_hash/core.h"
#include "crypto_scalarmult/core.h"
#include "crypto_secretbox/core.h"
#include "crypto_sign/core.h"
#include "crypto_stream/core.h"
#include "crypto_verify/core.h"
#include "randombytes/core.h"
#include "utils/core.h"
#include "version/core.h"

int
luaopen_luasodium_core(lua_State *L) {
    LUASODIUM_INIT(L);
    lua_newtable(L);

    ls_crypto_auth_core_setup(L);
    ls_crypto_box_core_setup(L);
    ls_crypto_hash_core_setup(L);
    ls_crypto_scalarmult_core_setup(L);
    ls_crypto_secretbox_core_setup(L);
    ls_crypto_sign_core_setup(L);
    ls_crypto_stream_core_setup(L);
    ls_crypto_verify_core_setup(L);
    ls_randombytes_core_setup(L);
    ls_utils_core_setup(L);
    ls_version_core_setup(L);

    return 1;
}
