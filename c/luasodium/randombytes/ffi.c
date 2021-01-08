#include "../luasodium-ffi.h"
#include "constants.h"

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


int luaopen_luasodium_randombytes_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, randombytes);
}

