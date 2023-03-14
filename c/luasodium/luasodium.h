#ifndef LUASODIUM_H
#define LUASODIUM_H

#include <sodium.h>
#include <lua.h>
#include <lauxlib.h>
#include <assert.h>

typedef void (*ls_func_ptr)(void);

/* base type for function definitions */
typedef struct luasodium_function_s {
    const char *name;
    ls_func_ptr func;
} luasodium_function_t;

#define LS_FUNC(x) { #x, (ls_func_ptr)x }

/* used to find consts via functions at runtime */
typedef struct luasodium_constant_s {
    const char *name;
    ls_func_ptr func;
    int type;
} luasodium_constant_t;

#define LS_CONST_PTR(x,y,t) { #x, (ls_func_ptr)y,t }

#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(_MSC_VER)
#define LS_PUBLIC __declspec(dllexport)
#else
#define LS_PUBLIC
#endif

#ifdef __cplusplus
extern "C" {
#endif

LS_PUBLIC
int luaopen_luasodium(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_aead_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_auth_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_box_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_generichash_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_hash_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_kx_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_onetimeauth_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_pwhash_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_scalarmult_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_secretbox_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_secretstream_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_shorthash_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_sign_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_stream_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_crypto_verify_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_randombytes_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_utils_core(lua_State *L);

LS_PUBLIC
int luaopen_luasodium_version_core(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif
