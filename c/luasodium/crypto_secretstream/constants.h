static const
luasodium_constant_t ls_crypto_secretstream_constants[] = {
    LS_CONST(crypto_secretstream_xchacha20poly1305_ABYTES),
    LS_CONST(crypto_secretstream_xchacha20poly1305_HEADERBYTES),
    LS_CONST(crypto_secretstream_xchacha20poly1305_KEYBYTES),
    LS_CONST(crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX),
    LS_CONST(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE),
    LS_CONST(crypto_secretstream_xchacha20poly1305_TAG_PUSH),
    LS_CONST(crypto_secretstream_xchacha20poly1305_TAG_REKEY),
    LS_CONST(crypto_secretstream_xchacha20poly1305_TAG_FINAL),
    { NULL, 0 },
};
