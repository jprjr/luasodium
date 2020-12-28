#ifndef LUASODIUM_FFI_H
#define LUASODIUM_FFI_H

#include "luasodium.h"

typedef void * ffi_pointer_t;

static unsigned int
luasodium_push_constants(lua_State *L, const luasodium_constant_t *c) {
    int i = 0;
    for(; c->name != NULL; i++, c++) {
        lua_pushinteger(L,c->value);
    }
    return i;
}

static unsigned int
luasodium_push_functions(lua_State *L, const ffi_pointer_t *p) {
    int i = 0;
    while(*p != NULL) {
        lua_pushlightuserdata(L,*p);
        p++;
        i++;
    }
    return i;
}

#endif
