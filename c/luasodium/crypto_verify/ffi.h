#include "../luasodium-ffi.h"
#include "../ffi-function-loader.h"
#include "../ffi-default-signatures.h"
#include "constants.h"
#include "ffi-signatures.h"
#include "ffi-implementation.h"

static const luasodium_function_t ls_crypto_verify_functions[] = {
    LS_FUNC(crypto_verify_16),
    LS_FUNC(crypto_verify_32),
    { NULL }
};



