#ifndef LUASODIUM_C_H
#define LUASODIUM_C_H

#include "luasodium.h"

#define LS_LUA_FUNC(x) { #x, ls_ ## x }

#define LUASODIUM_INIT(L) \
if(sodium_init() == -1) { \
    lua_pushliteral(L,"sodium_init error"); \
    return lua_error(L); \
}

#endif
