#include "../luasodium-ffi.h"
#include "../ffi-function-loader.h"
#include "../ffi-default-signatures.h"
#include "constants.h"
#include "ffi-signatures.h"
#include "ffi-implementation.h"

static const luasodium_function_t ls_utils_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(sodium_memcmp),
    LS_FUNC(sodium_bin2hex),
    LS_FUNC(sodium_hex2bin),
    LS_FUNC(sodium_bin2base64),
    LS_FUNC(sodium_base642bin),
    LS_FUNC(sodium_increment),
    LS_FUNC(sodium_add),
    LS_FUNC(sodium_sub),
    LS_FUNC(sodium_compare),
    LS_FUNC(sodium_is_zero),
    LS_FUNC(sodium_pad),
    LS_FUNC(sodium_unpad),
    LS_FUNC(sodium_base64_encoded_len),
    { NULL, NULL },
};

