#ifndef LUASODIUM_H
#define LUASODIUM_H

#include <sodium.h>
#include <lua.h>
#include <lauxlib.h>
#include <assert.h>

typedef struct luasodium_constant_s {
    const char *name;
    size_t value;
} luasodium_constant_t;

#endif
