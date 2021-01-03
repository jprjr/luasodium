#include "ffi.h"

int
luaopen_luasodium_version_ffi(lua_State*L) {
    if(luaL_loadbuffer(L,ls_version_ffi_implementation,ls_version_ffi_implementation_length - 1,"version.lua") ) {
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

    if(luaL_loadbuffer(L,ls_version_ffi_signatures,ls_version_ffi_signatures_length - 1,"luasodium/version/signatures.lua")) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }

    if(lua_pcall(L,1,1,0)) {
        return lua_error(L);
    }

    lua_newtable(L);
    luasodium_push_functions(L,ls_version_functions,lua_gettop(L));
    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }

    lua_newtable(L);
    luasodium_push_constants(L,ls_version_constants,lua_gettop(L));

    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }
    return 1;
}


