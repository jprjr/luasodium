#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_version_functions[] = {
    LS_FUNC(sodium_version_string),
    LS_FUNC(sodium_library_version_major),
    LS_FUNC(sodium_library_version_minor),
    LS_FUNC(sodium_library_minimal),
    { NULL, NULL },
};

int
luaopen_luasodium_version_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, version);
}

