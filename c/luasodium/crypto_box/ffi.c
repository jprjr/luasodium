#include "../luasodium-ffi.h"
#include "constants.h"

static const luasodium_function_t ls_crypto_box_functions[] = {
    LS_FUNC(sodium_init),
    LS_FUNC(sodium_memzero),

    LS_FUNC(crypto_box_keypair),
    LS_FUNC(crypto_box_seed_keypair),
    LS_FUNC(crypto_box),
    LS_FUNC(crypto_box_open),
    LS_FUNC(crypto_box_beforenm),
    LS_FUNC(crypto_box_afternm),
    LS_FUNC(crypto_box_open_afternm),

    LS_FUNC(crypto_box_curve25519xsalsa20poly1305_keypair),
    LS_FUNC(crypto_box_curve25519xsalsa20poly1305_seed_keypair),
    LS_FUNC(crypto_box_curve25519xsalsa20poly1305),
    LS_FUNC(crypto_box_curve25519xsalsa20poly1305_open),
    LS_FUNC(crypto_box_curve25519xsalsa20poly1305_beforenm),
    LS_FUNC(crypto_box_curve25519xsalsa20poly1305_afternm),
    LS_FUNC(crypto_box_curve25519xsalsa20poly1305_open_afternm),

    LS_FUNC(crypto_box_easy),
    LS_FUNC(crypto_box_open_easy),
    LS_FUNC(crypto_box_detached),
    LS_FUNC(crypto_box_open_detached),
    LS_FUNC(crypto_box_easy_afternm),
    LS_FUNC(crypto_box_open_easy_afternm),
    LS_FUNC(crypto_box_detached_afternm),
    LS_FUNC(crypto_box_open_detached_afternm),
    { NULL }
};

LS_PUBLIC
int luaopen_luasodium_crypto_box_ffi(lua_State *L) {
    return LS_LOAD_FFI(L, crypto_box);
}
