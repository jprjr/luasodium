static const luasodium_constant_t ls_crypto_secretbox_constants[] = {
    LS_CONST(crypto_secretbox_KEYBYTES),
    LS_CONST(crypto_secretbox_MACBYTES),
    LS_CONST(crypto_secretbox_NONCEBYTES),

    LS_CONST(crypto_secretbox_xsalsa20poly1305_KEYBYTES),
    LS_CONST(crypto_secretbox_xsalsa20poly1305_NONCEBYTES),
    LS_CONST(crypto_secretbox_xsalsa20poly1305_MACBYTES),

    LS_CONST(crypto_secretbox_xchacha20poly1305_KEYBYTES),
    LS_CONST(crypto_secretbox_xchacha20poly1305_NONCEBYTES),
    LS_CONST(crypto_secretbox_xchacha20poly1305_MACBYTES),

    LS_CONST(crypto_secretbox_ZEROBYTES),
    LS_CONST(crypto_secretbox_xsalsa20poly1305_ZEROBYTES),

    LS_CONST(crypto_secretbox_BOXZEROBYTES),
    LS_CONST(crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES),
    { NULL, 0 },
};


