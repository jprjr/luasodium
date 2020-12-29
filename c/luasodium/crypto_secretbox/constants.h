static const luasodium_constant_t luasodium_secretbox_constants[] = {
    { "crypto_secretbox_KEYBYTES",                     crypto_secretbox_KEYBYTES       },
    { "crypto_secretbox_MACBYTES",                     crypto_secretbox_MACBYTES       },
    { "crypto_secretbox_NONCEBYTES",                   crypto_secretbox_NONCEBYTES     },
#if 0
    { "crypto_secretbox_xsalsa20poly1305_KEYBYTES",    crypto_secretbox_xsalsa20poly1305_KEYBYTES },
    { "crypto_secretbox_xsalsa20poly1305_NONCEBYTES",  crypto_secretbox_xsalsa20poly1305_NONCEBYTES },
    { "crypto_secretbox_xsalsa20poly1305_MACBYTES",    crypto_secretbox_xsalsa20poly1305_MACBYTES },
    { "crypto_secretbox_xchacha20poly1305_KEYBYTES",   crypto_secretbox_xchacha20poly1305_KEYBYTES },
    { "crypto_secretbox_xchacha20poly1305_NONCEBYTES", crypto_secretbox_xchacha20poly1305_NONCEBYTES },
    { "crypto_secretbox_xchacha20poly1305_MACBYTES",   crypto_secretbox_xchacha20poly1305_MACBYTES },
#endif
    { NULL, 0 },
};


