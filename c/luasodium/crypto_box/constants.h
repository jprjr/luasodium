static const luasodium_constant_t ls_crypto_box_constants[] = {
    LS_CONST_PTR(crypto_box_PUBLICKEYBYTES,crypto_box_publickeybytes,1),
    LS_CONST_PTR(crypto_box_SECRETKEYBYTES,crypto_box_secretkeybytes,1),
    LS_CONST_PTR(crypto_box_MACBYTES,crypto_box_macbytes,1),
    LS_CONST_PTR(crypto_box_NONCEBYTES,crypto_box_noncebytes,1),
    LS_CONST_PTR(crypto_box_SEEDBYTES,crypto_box_seedbytes,1),
    LS_CONST_PTR(crypto_box_BEFORENMBYTES,crypto_box_beforenmbytes,1),
    LS_CONST_PTR(crypto_box_BOXZEROBYTES,crypto_box_boxzerobytes,1),
    LS_CONST_PTR(crypto_box_ZEROBYTES,crypto_box_zerobytes,1),

    LS_CONST_PTR(crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,crypto_box_curve25519xsalsa20poly1305_publickeybytes,1),
    LS_CONST_PTR(crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,crypto_box_curve25519xsalsa20poly1305_secretkeybytes,1),
    LS_CONST_PTR(crypto_box_curve25519xsalsa20poly1305_MACBYTES,crypto_box_curve25519xsalsa20poly1305_macbytes,1),
    LS_CONST_PTR(crypto_box_curve25519xsalsa20poly1305_NONCEBYTES,crypto_box_curve25519xsalsa20poly1305_noncebytes,1),
    LS_CONST_PTR(crypto_box_curve25519xsalsa20poly1305_SEEDBYTES,crypto_box_curve25519xsalsa20poly1305_seedbytes,1),
    LS_CONST_PTR(crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES,crypto_box_curve25519xsalsa20poly1305_beforenmbytes,1),
    LS_CONST_PTR(crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES,crypto_box_curve25519xsalsa20poly1305_boxzerobytes,1),
    LS_CONST_PTR(crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,crypto_box_curve25519xsalsa20poly1305_zerobytes,1),

    { NULL, 0, 0 },
};

