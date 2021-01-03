#ifndef LUASODIUM_FFI_H
#define LUASODIUM_FFI_H

#include "luasodium.h"

#include <stdio.h>

static unsigned int
luasodium_push_constants(lua_State *L, const luasodium_constant_t *c, int index) {
    luasodium_set_constants(L,c,index);
    return 1;
}

static unsigned int
luasodium_push_functions(lua_State *L, const luasodium_function_t *f, int index) {
    for(; f->name != NULL; f++) {
        lua_pushlightuserdata(L,f->func);
        lua_setfield(L,index,f->name);
    }
    return 1;
}


#endif
