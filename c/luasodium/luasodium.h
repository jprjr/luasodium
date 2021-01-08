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

#define LS_CONST(x) { #x, x }

typedef void (*ls_func_ptr)(void);

/* base type for function definitions */
typedef struct luasodium_function_s {
    const char *name;
    ls_func_ptr func;
} luasodium_function_t;

#define LS_FUNC(x) { #x, (ls_func_ptr)x }

#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(_MSC_VER)
#define LS_PUBLIC __declspec(dllexport)
#else
#define LS_PUBLIC
#endif


#endif
