#include "ffi.h"

int luaopen_luasodium_utils_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,ls_utils_ffi_implementation,ls_utils_ffi_implementation_length - 1,"utils.lua") ) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }

    if(luaL_loadbuffer(L,ffi_function_loader,ffi_function_loader_length - 1,"luasodium/_ffi/function_loader.lua")) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }

    if(luaL_loadbuffer(L,ffi_default_signatures,ffi_default_signatures_length - 1, "luasodium/_ffi/default_signatures.lua")) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }

    if(luaL_loadbuffer(L,ls_utils_ffi_signatures,ls_utils_ffi_signatures_length - 1,"luasodium/utils/signatures.lua")) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }

    if(lua_pcall(L,1,1,0)) {
        return lua_error(L);
    }

    luasodium_push_functions(L,ls_utils_functions);
    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }

    luasodium_push_constants(L,ls_utils_constants);

    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }
    return 1;
}
