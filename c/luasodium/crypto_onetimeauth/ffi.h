#include "../luasodium-ffi.h"
#include "../ffi-function-loader.h"
#include "../ffi-default-signatures.h"
#include "constants.h"
#include "ffi-signatures.h"
#include "ffi-implementation.h"

static const luasodium_function_t ls_crypto_onetimeauth_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(malloc),
    LS_FUNC(free),
    LS_FUNC(crypto_onetimeauth),
    LS_FUNC(crypto_onetimeauth_verify),
    LS_FUNC(crypto_onetimeauth_keygen),
    LS_FUNC(crypto_onetimeauth_init),
    LS_FUNC(crypto_onetimeauth_update),
    LS_FUNC(crypto_onetimeauth_final),
    LS_FUNC(crypto_onetimeauth_statebytes),
    { NULL }
};



