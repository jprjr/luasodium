#include "../luasodium-ffi.h"
#include "../ffi-function-loader.h"
#include "../ffi-default-signatures.h"
#include "constants.h"
#include "ffi-signatures.h"
#include "ffi-implementation.h"

static const luasodium_function_t ls_crypto_sign_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(malloc),
    LS_FUNC(free),
    LS_FUNC(crypto_sign_keypair),
    LS_FUNC(crypto_sign_seed_keypair),
    LS_FUNC(crypto_sign),
    LS_FUNC(crypto_sign_open),
    LS_FUNC(crypto_sign_detached),
    LS_FUNC(crypto_sign_verify_detached),
    LS_FUNC(crypto_sign_init),
    LS_FUNC(crypto_sign_update),
    LS_FUNC(crypto_sign_final_create),
    LS_FUNC(crypto_sign_final_verify),
    LS_FUNC(crypto_sign_ed25519_sk_to_seed),
    LS_FUNC(crypto_sign_ed25519_sk_to_pk),
    LS_FUNC(crypto_sign_statebytes),
    { NULL }
};
