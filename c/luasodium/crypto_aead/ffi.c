#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_aead_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),
    LS_FUNC(malloc),
    LS_FUNC(free),

    LS_FUNC(crypto_aead_chacha20poly1305_encrypt),
    LS_FUNC(crypto_aead_chacha20poly1305_decrypt),
    LS_FUNC(crypto_aead_chacha20poly1305_encrypt_detached),
    LS_FUNC(crypto_aead_chacha20poly1305_decrypt_detached),
    LS_FUNC(crypto_aead_chacha20poly1305_keygen),

    LS_FUNC(crypto_aead_chacha20poly1305_ietf_encrypt),
    LS_FUNC(crypto_aead_chacha20poly1305_ietf_decrypt),
    LS_FUNC(crypto_aead_chacha20poly1305_ietf_encrypt_detached),
    LS_FUNC(crypto_aead_chacha20poly1305_ietf_decrypt_detached),
    LS_FUNC(crypto_aead_chacha20poly1305_ietf_keygen),

    LS_FUNC(crypto_aead_xchacha20poly1305_ietf_encrypt),
    LS_FUNC(crypto_aead_xchacha20poly1305_ietf_decrypt),
    LS_FUNC(crypto_aead_xchacha20poly1305_ietf_encrypt_detached),
    LS_FUNC(crypto_aead_xchacha20poly1305_ietf_decrypt_detached),
    LS_FUNC(crypto_aead_xchacha20poly1305_ietf_keygen),

    LS_FUNC(crypto_aead_aes256gcm_is_available),
    LS_FUNC(crypto_aead_aes256gcm_encrypt),
    LS_FUNC(crypto_aead_aes256gcm_decrypt),
    LS_FUNC(crypto_aead_aes256gcm_encrypt_detached),
    LS_FUNC(crypto_aead_aes256gcm_decrypt_detached),
    LS_FUNC(crypto_aead_aes256gcm_keygen),

    LS_FUNC(crypto_aead_aes256gcm_statebytes),
    LS_FUNC(crypto_aead_aes256gcm_beforenm),
    LS_FUNC(crypto_aead_aes256gcm_encrypt_afternm),
    LS_FUNC(crypto_aead_aes256gcm_decrypt_afternm),
    LS_FUNC(crypto_aead_aes256gcm_encrypt_detached_afternm),
    LS_FUNC(crypto_aead_aes256gcm_decrypt_detached_afternm),
    { NULL }
};

LS_PUBLIC
int luaopen_luasodium_crypto_aead_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_aead);
}

