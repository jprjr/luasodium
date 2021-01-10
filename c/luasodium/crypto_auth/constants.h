static const luasodium_constant_t ls_crypto_auth_constants[] = {
    LS_CONST(crypto_auth_BYTES),
    LS_CONST(crypto_auth_KEYBYTES),
    LS_CONST(crypto_auth_hmacsha256_BYTES),
    LS_CONST(crypto_auth_hmacsha256_KEYBYTES),
    LS_CONST(crypto_auth_hmacsha512256_BYTES),
    LS_CONST(crypto_auth_hmacsha512256_KEYBYTES),
    /* libsodium addition */
    LS_CONST(crypto_auth_hmacsha512_BYTES),
    LS_CONST(crypto_auth_hmacsha512_KEYBYTES),
    { NULL, 0 },
};


