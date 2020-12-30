#ifndef LUASODIUM_FFI_H
#define LUASODIUM_FFI_H

#include "luasodium.h"

#include <stdio.h>

static unsigned int
luasodium_push_constants(lua_State *L, const luasodium_constant_t *c) {
    lua_newtable(L);
    luasodium_set_constants(L,c);
    return 1;
}

static unsigned int
luasodium_push_functions(lua_State *L, const luasodium_function_t * const *f) {
    unsigned int i = 0;
    lua_newtable(L);

    for(; *f != NULL; f++) {
        lua_newtable(L);
        lua_pushstring(L,(*f)->name);
        lua_setfield(L,-2,"name");
        lua_pushstring(L,(*f)->signature);
        lua_setfield(L,-2,"signature");
        lua_pushlightuserdata(L,(*f)->func);
        lua_setfield(L,-2,"func");
        lua_rawseti(L,-2,++i);
    }
    return 1;
}



static void
luasodium_push_inittable(lua_State *L) {
    lua_newtable(L);

    lua_newtable(L);
    lua_pushlightuserdata(L,sodium_init);
    lua_setfield(L,-2,"func");

    lua_pushliteral(L,"int (*)(void)");
    lua_setfield(L,-2,"signature");

    lua_setfield(L,-2,"sodium_init");

    lua_newtable(L);
    lua_pushlightuserdata(L,sodium_memzero);
    lua_setfield(L,-2,"func");

    lua_pushliteral(L,"void (*)(void * const, const size_t)");
    lua_setfield(L,-2,"signature");

    lua_setfield(L,-2,"sodium_memzero");
}

#endif
