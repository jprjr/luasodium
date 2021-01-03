#include "../luasodium-ffi.h"
#include "../ffi-function-loader.h"
#include "../ffi-default-signatures.h"
#include "constants.h"
#include "ffi-signatures.h"
#include "ffi-implementation.h"

static const luasodium_function_t ls_version_functions[] = {
    LS_FUNC(sodium_version_string),
    LS_FUNC(sodium_library_version_major),
    LS_FUNC(sodium_library_version_minor),
    LS_FUNC(sodium_library_minimal),
    { NULL, NULL },
};
