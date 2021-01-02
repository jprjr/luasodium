#include "../luasodium-ffi.h"
#include "../ffi-function-loader.h"
#include "../ffi-default-signatures.h"
#include "constants.h"
#include "ffi-signatures.h"
#include "ffi-implementation.h"

static const luasodium_function_t ls_crypto_box_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_box_keypair),
    LS_FUNC(crypto_box_seed_keypair),
    LS_FUNC(crypto_box),
    LS_FUNC(crypto_box_open),
    LS_FUNC(crypto_box_easy),
    LS_FUNC(crypto_box_open_easy),
    LS_FUNC(crypto_box_detached),
    LS_FUNC(crypto_box_open_detached),
    LS_FUNC(crypto_box_beforenm),
    LS_FUNC(crypto_box_easy_afternm),
    LS_FUNC(crypto_box_open_easy_afternm),
    LS_FUNC(crypto_box_detached_afternm),
    LS_FUNC(crypto_box_open_detached_afternm),
    LS_FUNC(crypto_box_afternm),
    LS_FUNC(crypto_box_open_afternm),
    { NULL }
};

