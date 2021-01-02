#include "../luasodium-ffi.h"
#include "../ffi-function-loader.h"
#include "../ffi-default-signatures.h"
#include "constants.h"
#include "ffi-signatures.h"
#include "ffi-implementation.h"

static const luasodium_function_t ls_crypto_hash_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_hash),
    LS_FUNC(crypto_hash_sha256),
    LS_FUNC(crypto_hash_sha256_init),
    LS_FUNC(crypto_hash_sha256_update),
    LS_FUNC(crypto_hash_sha256_final),
    LS_FUNC(crypto_hash_sha512),
    LS_FUNC(crypto_hash_sha512_init),
    LS_FUNC(crypto_hash_sha512_update),
    LS_FUNC(crypto_hash_sha512_final),
    { NULL }
};


