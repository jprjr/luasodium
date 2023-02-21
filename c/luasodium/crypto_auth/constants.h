static const luasodium_constant_t ls_crypto_auth_constants[] = {
    LS_CONST_PTR(crypto_auth_BYTES,crypto_auth_bytes,1),
    LS_CONST_PTR(crypto_auth_KEYBYTES,crypto_auth_keybytes,1),
    LS_CONST_PTR(crypto_auth_hmacsha256_BYTES,crypto_auth_hmacsha256_bytes,1),
    LS_CONST_PTR(crypto_auth_hmacsha256_KEYBYTES,crypto_auth_hmacsha256_keybytes,1),
    LS_CONST_PTR(crypto_auth_hmacsha512256_BYTES,crypto_auth_hmacsha512256_bytes,1),
    LS_CONST_PTR(crypto_auth_hmacsha512256_KEYBYTES,crypto_auth_hmacsha512256_keybytes,1),
    /* libsodium addition */
    LS_CONST_PTR(crypto_auth_hmacsha512_BYTES,crypto_auth_hmacsha512_bytes,1),
    LS_CONST_PTR(crypto_auth_hmacsha512_KEYBYTES,crypto_auth_hmacsha512_keybytes,1),
    { NULL, 0, 0 },
};


