#ifndef LUASODIUM_FFI_H
#define LUASODIUM_FFI_H

#include "luasodium.h"

#include <stdio.h>

static void
luasodium_push_constants(lua_State *L, const luasodium_constant_t *c) {
    int index = 0;
    lua_newtable(L);
    index = lua_gettop(L);
    luasodium_set_constants(L,c,index);
}

static void
luasodium_push_functions(lua_State *L, const luasodium_function_t *f) {
    int index = 0;
    lua_newtable(L);
    index = lua_gettop(L);
    for(; f->name != NULL; f++) {
        lua_pushlightuserdata(L,f->func);
        lua_setfield(L,index,f->name);
    }
}

static int
luasodium_load_ffi(lua_State *L, const char *mod, const luasodium_function_t *f, const luasodium_constant_t *c) {
    lua_getglobal(L,"require");
    lua_pushliteral(L,"luasodium._ffi.ffi_loader");
    if(lua_pcall(L,1,1,0)) {
        return lua_error(L);
    }

    lua_pushstring(L,mod);
    luasodium_push_functions(L,f);
    luasodium_push_constants(L,c);

    if(lua_pcall(L,3,1,0)) {
        return lua_error(L);
    }
    return 1;
}

#define LS_LOAD_FFI(L,x) luasodium_load_ffi(L, #x, ls_ ## x ## _functions, ls_ ## x ## _constants)


#endif
