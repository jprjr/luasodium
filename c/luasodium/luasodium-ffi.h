#ifndef LUASODIUM_FFI_H
#define LUASODIUM_FFI_H

#include "luasodium.h"

#include "internals/ls_lua_push_constants.h"
#include "internals/ls_lua_push_functions.h"

static int
ls_lua_load_ffi(lua_State *L, const char *mod, const luasodium_function_t *f, const luasodium_constant_t *c) {
    lua_getglobal(L,"require");
    lua_pushliteral(L,"luasodium._ffi.ffi_loader");
    /* LCOV_EXCL_START */
    if(lua_pcall(L,1,1,0)) {
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */

    lua_pushstring(L,mod);
    ls_lua_push_functions(L,f);
    ls_lua_push_constants(L,c);

    /* LCOV_EXCL_START */
    if(lua_pcall(L,3,1,0)) {
        return lua_error(L);
    }
    /* LCOV_EXCL_STOP */
    return 1;
}

#define LS_LOAD_FFI(L,x) ls_lua_load_ffi(L, #x, ls_ ## x ## _functions, ls_ ## x ## _constants)


#endif
