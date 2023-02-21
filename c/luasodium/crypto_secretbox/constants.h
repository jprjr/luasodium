static const luasodium_constant_t ls_crypto_secretbox_constants[] = {
    LS_CONST_PTR(crypto_secretbox_KEYBYTES,crypto_secretbox_keybytes,1),
    LS_CONST_PTR(crypto_secretbox_MACBYTES,crypto_secretbox_macbytes,1),
    LS_CONST_PTR(crypto_secretbox_NONCEBYTES,crypto_secretbox_noncebytes,1),
    LS_CONST_PTR(crypto_secretbox_BOXZEROBYTES,crypto_secretbox_boxzerobytes,1),
    LS_CONST_PTR(crypto_secretbox_ZEROBYTES,crypto_secretbox_zerobytes,1),

    LS_CONST_PTR(crypto_secretbox_xsalsa20poly1305_KEYBYTES,crypto_secretbox_xsalsa20poly1305_keybytes,1),
    LS_CONST_PTR(crypto_secretbox_xsalsa20poly1305_MACBYTES,crypto_secretbox_xsalsa20poly1305_macbytes,1),
    LS_CONST_PTR(crypto_secretbox_xsalsa20poly1305_NONCEBYTES,crypto_secretbox_xsalsa20poly1305_noncebytes,1),
    LS_CONST_PTR(crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES,crypto_secretbox_xsalsa20poly1305_boxzerobytes,1),
    LS_CONST_PTR(crypto_secretbox_xsalsa20poly1305_ZEROBYTES,crypto_secretbox_xsalsa20poly1305_zerobytes,1),

    { NULL, 0, 0 },
};


