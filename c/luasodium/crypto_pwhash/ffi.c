#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_pwhash_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_pwhash),
    LS_FUNC(crypto_pwhash_str),
    LS_FUNC(crypto_pwhash_str_verify),
    LS_FUNC(crypto_pwhash_str_needs_rehash),
    LS_FUNC(crypto_pwhash_argon2i),
    LS_FUNC(crypto_pwhash_argon2i_str),
    LS_FUNC(crypto_pwhash_argon2i_str_verify),
    LS_FUNC(crypto_pwhash_argon2i_str_needs_rehash),
    LS_FUNC(crypto_pwhash_argon2id),
    LS_FUNC(crypto_pwhash_argon2id_str),
    LS_FUNC(crypto_pwhash_argon2id_str_verify),
    LS_FUNC(crypto_pwhash_argon2id_str_needs_rehash),
    LS_FUNC(crypto_pwhash_scryptsalsa208sha256),
    LS_FUNC(crypto_pwhash_scryptsalsa208sha256_str),
    LS_FUNC(crypto_pwhash_scryptsalsa208sha256_str_verify),
    LS_FUNC(crypto_pwhash_scryptsalsa208sha256_str_needs_rehash),
    { NULL }
};


LS_PUBLIC
int luaopen_luasodium_crypto_pwhash_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_pwhash);
}
