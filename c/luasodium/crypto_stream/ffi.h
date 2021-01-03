#include "../luasodium-ffi.h"
#include "../ffi-function-loader.h"
#include "../ffi-default-signatures.h"
#include "constants.h"
#include "ffi-signatures.h"
#include "ffi-implementation.h"

static const luasodium_function_t ls_crypto_stream_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_stream),
    LS_FUNC(crypto_stream_xor),
    LS_FUNC(crypto_stream_keygen),
    { NULL }
};



