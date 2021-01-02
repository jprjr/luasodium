#include "../luasodium-ffi.h"
#include "../ffi-function-loader.h"
#include "../ffi-default-signatures.h"
#include "constants.h"
#include "ffi-signatures.h"
#include "ffi-implementation.h"

static const luasodium_function_t ls_randombytes_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(randombytes_random),
    LS_FUNC(randombytes_uniform),
    LS_FUNC(randombytes_buf),
    LS_FUNC(randombytes_buf_deterministic),
    LS_FUNC(randombytes_close),
    LS_FUNC(randombytes_stir),
    { NULL, NULL },
};

