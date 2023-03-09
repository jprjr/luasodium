#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_sign_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(crypto_sign_keypair),
    LS_FUNC(crypto_sign_seed_keypair),
    LS_FUNC(crypto_sign),
    LS_FUNC(crypto_sign_open),
    LS_FUNC(crypto_sign_detached),
    LS_FUNC(crypto_sign_verify_detached),
    LS_FUNC(crypto_sign_init),
    LS_FUNC(crypto_sign_update),
    LS_FUNC(crypto_sign_final_create),
    LS_FUNC(crypto_sign_final_verify),
    LS_FUNC(crypto_sign_statebytes),

    LS_FUNC(crypto_sign_ed25519_keypair),
    LS_FUNC(crypto_sign_ed25519_seed_keypair),
    LS_FUNC(crypto_sign_ed25519),
    LS_FUNC(crypto_sign_ed25519_open),
    LS_FUNC(crypto_sign_ed25519_detached),
    LS_FUNC(crypto_sign_ed25519_verify_detached),
    LS_FUNC(crypto_sign_ed25519ph_init),
    LS_FUNC(crypto_sign_ed25519ph_update),
    LS_FUNC(crypto_sign_ed25519ph_final_create),
    LS_FUNC(crypto_sign_ed25519ph_final_verify),
    LS_FUNC(crypto_sign_ed25519ph_statebytes),
    LS_FUNC(crypto_sign_ed25519_sk_to_seed),
    LS_FUNC(crypto_sign_ed25519_sk_to_pk),
    { NULL }
};

LS_PUBLIC
int luaopen_luasodium_crypto_sign_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_sign);
}
