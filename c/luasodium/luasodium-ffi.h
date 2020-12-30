#ifndef LUASODIUM_FFI_H
#define LUASODIUM_FFI_H

#include "luasodium.h"

typedef void * ffi_pointer_t;

struct luasodium_ffi_func_s {
    ffi_pointer_t func;
    const char *name;
    const char *signature;
};

typedef struct luasodium_ffi_func_s luasodium_ffi_func;

#define LS_FFI_FUNC(x, sig) { x, #x, sig }
#define LS_FFI_END { NULL, NULL, NULL }

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

static unsigned int
luasodium_push_init(lua_State *L) {
    lua_pushlightuserdata(L,sodium_init);
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


static void
luasodium_push_ffi_funcs(lua_State *L, const luasodium_ffi_func *f) {
    unsigned int i = 0;
    lua_newtable(L);
    for(; f->func != NULL; f++) {
        lua_newtable(L);

        lua_pushstring(L,f->name);
        lua_setfield(L,-2,"name");

        lua_pushlightuserdata(L,f->func);
        lua_setfield(L,-2,"func");

        lua_pushstring(L,f->signature);
        lua_setfield(L,-2,"signature");

        lua_rawseti(L,-2,++i);
    }
}

#endif
