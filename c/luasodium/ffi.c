#include <assert.h>

#include "crypto_auth/ffi.h"
#include "crypto_box/ffi.h"
#include "crypto_hash/ffi.h"
#include "crypto_scalarmult/ffi.h"
#include "crypto_secretbox/ffi.h"
#include "crypto_sign/ffi.h"
#include "randombytes/ffi.h"
#include "utils/ffi.h"
#include "version/ffi.h"

#define COPYDOWN_FFI_IMPLEMENTATION(x) \
    if(luaL_loadbuffer(L,ls_ ## x ## _ffi_implementation,ls_ ## x ## _ffi_implementation_length - 1, "luasodium/" #x "/implementation.lua")) { \
        return lua_error(L); \
    } \
    if(lua_pcall(L,0,1,0)) { \
        return lua_error(L); \
    } \
    lua_pushvalue(L,libs_index); \
    lua_pushvalue(L,constants_index); \
    if(lua_pcall(L,2,1,0)) { \
        return lua_error(L); \
    } \
    ls_copydown_table(L,table_index,lua_gettop(L)); \
    lua_pop(L,1);


#define PUSH_CONSTANTS_TABLE(x) \
    luasodium_push_constants(L,ls_ ## x ## _constants,lua_gettop(L));

#define PUSH_FUNC_TABLE(x) \
    luasodium_push_functions(L,ls_ ## x ## _functions,lua_gettop(L));

#define COPYDOWN_SIG_TABLE(x) \
    if(luaL_loadbuffer(L,ls_ ## x ## _ffi_signatures,ls_ ## x ## _ffi_signatures_length - 1, "luasodium/" #x "/signatures.lua")) { \
        return lua_error(L); \
    } \
    if(lua_pcall(L,0,1,0)) { \
        return lua_error(L); \
    } \
    ls_copydown_table(L,signatures_index,lua_gettop(L)); \
    lua_pop(L,1);

/* assumes table is on top */
static void
ls_copydown_table(lua_State *L, int target, int source) {
    lua_pushnil(L);
    while(lua_next(L,source) != 0) {
        /* stack: key, value (top) */
        lua_setfield(L,target,lua_tostring(L,-2)); /* pops value from top */
    }
}

int
luaopen_luasodium_ffi(lua_State *L) {
    int table_index;
    int default_signatures_index;
    int function_loader_index;
    int signatures_index;
    int function_pointers_index;
    int constants_index;
    int libs_index;

    lua_newtable(L);
    table_index = lua_gettop(L);

    if(luaL_loadbuffer(L,ffi_default_signatures,ffi_default_signatures_length - 1, "luasodium/_ffi/default_signatures.lua")) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }
    default_signatures_index = lua_gettop(L);

    if(luaL_loadbuffer(L,ffi_function_loader,ffi_function_loader_length - 1, "luasodium/_ffi/function_loader.lua")) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }
    function_loader_index = lua_gettop(L);

    lua_newtable(L);
    signatures_index = lua_gettop(L);

    lua_newtable(L);
    function_pointers_index = lua_gettop(L);

    /* first, load all the signatures into the big signature table */
    COPYDOWN_SIG_TABLE(crypto_auth)
    COPYDOWN_SIG_TABLE(crypto_box)
    COPYDOWN_SIG_TABLE(crypto_hash)
    COPYDOWN_SIG_TABLE(crypto_scalarmult)
    COPYDOWN_SIG_TABLE(crypto_secretbox)
    COPYDOWN_SIG_TABLE(crypto_sign)
    COPYDOWN_SIG_TABLE(randombytes)
    COPYDOWN_SIG_TABLE(utils)
    COPYDOWN_SIG_TABLE(version)

    /* call the default_signatures function */
    lua_pushvalue(L,default_signatures_index);
    lua_pushvalue(L,signatures_index);
    if(lua_pcall(L,1,1,0)) {
        return lua_error(L);
    }
    lua_pop(L,1);

    assert(lua_gettop(L) == function_pointers_index);

    /* now load all the function pointers */
    PUSH_FUNC_TABLE(crypto_auth)
    PUSH_FUNC_TABLE(crypto_box)
    PUSH_FUNC_TABLE(crypto_hash)
    PUSH_FUNC_TABLE(crypto_scalarmult)
    PUSH_FUNC_TABLE(crypto_secretbox)
    PUSH_FUNC_TABLE(crypto_sign)
    PUSH_FUNC_TABLE(randombytes)
    PUSH_FUNC_TABLE(utils)
    PUSH_FUNC_TABLE(version)

    assert(lua_gettop(L) == function_pointers_index);

    /* now we call the function loader with our signatures and pointers */
    assert(lua_gettop(L) == function_loader_index + 2);
    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }

    libs_index = lua_gettop(L);

    /* now build the constants table */
    lua_newtable(L);
    constants_index = lua_gettop(L);

    PUSH_CONSTANTS_TABLE(crypto_auth)
    PUSH_CONSTANTS_TABLE(crypto_box)
    PUSH_CONSTANTS_TABLE(crypto_hash)
    PUSH_CONSTANTS_TABLE(crypto_scalarmult)
    PUSH_CONSTANTS_TABLE(crypto_secretbox)
    PUSH_CONSTANTS_TABLE(crypto_sign)
    PUSH_CONSTANTS_TABLE(randombytes)
    PUSH_CONSTANTS_TABLE(utils)
    PUSH_CONSTANTS_TABLE(version)

    assert(lua_gettop(L) == constants_index);

    /* deviation - there's no crypto_sign_STATEBYTES in libsodium */
    lua_pushinteger(L,crypto_sign_statebytes());
    lua_setfield(L,-2,"crypto_sign_STATEBYTES");

    /* deviation - there's no crypto_hash_sha256_STATEBYTES in libsodium */
    lua_pushinteger(L,crypto_hash_sha256_statebytes());
    lua_setfield(L,-2,"crypto_hash_sha256_STATEBYTES");

    /* deviation - there's no crypto_hash_sha512_STATEBYTES in libsodium */
    lua_pushinteger(L,crypto_hash_sha512_statebytes());
    lua_setfield(L,-2,"crypto_hash_sha512_STATEBYTES");

    COPYDOWN_FFI_IMPLEMENTATION(crypto_auth)
    COPYDOWN_FFI_IMPLEMENTATION(crypto_box)
    COPYDOWN_FFI_IMPLEMENTATION(crypto_hash)
    COPYDOWN_FFI_IMPLEMENTATION(crypto_scalarmult)
    COPYDOWN_FFI_IMPLEMENTATION(crypto_secretbox)
    COPYDOWN_FFI_IMPLEMENTATION(crypto_sign)
    COPYDOWN_FFI_IMPLEMENTATION(randombytes)
    COPYDOWN_FFI_IMPLEMENTATION(utils)
    COPYDOWN_FFI_IMPLEMENTATION(version)

    lua_settop(L,table_index);

    return 1;
}
