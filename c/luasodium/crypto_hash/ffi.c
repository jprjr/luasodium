#include "ffi.h"

int luaopen_luasodium_crypto_hash_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,ls_crypto_hash_ffi_implementation,ls_crypto_hash_ffi_implementation_length - 1,"crypto_hash.lua") ) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }

    if(luaL_loadbuffer(L,ffi_function_loader,ffi_function_loader_length - 1,"luasodium/_ffi/function_loader.lua")) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }

    if(luaL_loadbuffer(L,ffi_default_signatures,ffi_default_signatures_length - 1, "luasodium/_ffi/default_signatures.lua")) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }

    if(luaL_loadbuffer(L,ls_crypto_hash_ffi_signatures,ls_crypto_hash_ffi_signatures_length - 1,"luasodium/crypto_hash/signatures.lua")) {
        return lua_error(L);
    }
    if(lua_pcall(L,0,1,0)) {
        return lua_error(L);
    }

    if(lua_pcall(L,1,1,0)) {
        return lua_error(L);
    }

    luasodium_push_functions(L,ls_crypto_hash_functions);
    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }

    luasodium_push_constants(L,ls_crypto_hash_constants);

    /* deviation - there's no crypto_hash_sha256_STATEBYTES in libsodium */
    lua_pushinteger(L,crypto_hash_sha256_statebytes());
    lua_setfield(L,-2,"crypto_hash_sha256_STATEBYTES");

    /* deviation - there's no crypto_hash_sha512_STATEBYTES in libsodium */
    lua_pushinteger(L,crypto_hash_sha512_statebytes());
    lua_setfield(L,-2,"crypto_hash_sha512_STATEBYTES");

    if(lua_pcall(L,2,1,0)) {
        return lua_error(L);
    }
    return 1;
}
