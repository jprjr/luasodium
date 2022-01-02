#include "../luasodium.h"

#include "../internals/ls_lua_push_constants.h"
#include "../internals/ls_lua_push_functions.h"

#include "constants.h"

static const luasodium_function_t ls_version_functions[] = {
    LS_FUNC(sodium_version_string),
    LS_FUNC(sodium_library_version_major),
    LS_FUNC(sodium_library_version_minor),
    LS_FUNC(sodium_library_minimal),
    { NULL, NULL },
};

LS_PUBLIC
int luaopen_luasodium_version_ffi(lua_State *L) {
    /* use our own variant of LOAD_FFI since we have a string
     * constant to include */

    lua_getglobal(L,"require");
    lua_pushliteral(L,"luasodium._ffi.ffi_loader");
    /* LCOV_EXCL_START */
    if(lua_pcall(L,1,1,0)) {
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pushstring(L,"version");
    ls_lua_push_functions(L,ls_version_functions);
    ls_lua_push_constants(L,ls_version_constants);

    /* top of stack is the constant table */
    lua_pushliteral(L,LUASODIUM_VERSION);
    lua_setfield(L,-2,"_VERSION");

    /* LCOV_EXCL_START */
    if(lua_pcall(L,3,1,0)) {
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */
    return 1;
}

