static const luasodium_constant_t ls_crypto_box_constants[] = {
    LS_CONST(crypto_box_PUBLICKEYBYTES),
    LS_CONST(crypto_box_SECRETKEYBYTES),
    LS_CONST(crypto_box_MACBYTES),
    LS_CONST(crypto_box_NONCEBYTES),
    LS_CONST(crypto_box_SEEDBYTES),
    LS_CONST(crypto_box_BEFORENMBYTES),
    LS_CONST(crypto_box_BOXZEROBYTES),
    LS_CONST(crypto_box_ZEROBYTES),

    LS_CONST(crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES),
    LS_CONST(crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES),
    LS_CONST(crypto_box_curve25519xsalsa20poly1305_MACBYTES),
    LS_CONST(crypto_box_curve25519xsalsa20poly1305_NONCEBYTES),
    LS_CONST(crypto_box_curve25519xsalsa20poly1305_SEEDBYTES),
    LS_CONST(crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES),
    LS_CONST(crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES),
    LS_CONST(crypto_box_curve25519xsalsa20poly1305_ZEROBYTES),

    LS_CONST(crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES),
    LS_CONST(crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES),
    LS_CONST(crypto_box_curve25519xchacha20poly1305_MACBYTES),
    LS_CONST(crypto_box_curve25519xchacha20poly1305_NONCEBYTES),
    LS_CONST(crypto_box_curve25519xchacha20poly1305_SEEDBYTES),
    LS_CONST(crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES),
    { NULL, 0 },
};

