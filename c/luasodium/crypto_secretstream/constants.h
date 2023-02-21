static const
luasodium_constant_t ls_crypto_secretstream_constants[] = {
    LS_CONST_PTR(crypto_secretstream_xchacha20poly1305_ABYTES,crypto_secretstream_xchacha20poly1305_abytes,1),
    LS_CONST_PTR(crypto_secretstream_xchacha20poly1305_HEADERBYTES,crypto_secretstream_xchacha20poly1305_headerbytes,1),
    LS_CONST_PTR(crypto_secretstream_xchacha20poly1305_KEYBYTES,crypto_secretstream_xchacha20poly1305_keybytes,1),
    LS_CONST_PTR(crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX,crypto_secretstream_xchacha20poly1305_messagebytes_max,1),
    LS_CONST_PTR(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,crypto_secretstream_xchacha20poly1305_tag_message,1),
    LS_CONST_PTR(crypto_secretstream_xchacha20poly1305_TAG_PUSH,crypto_secretstream_xchacha20poly1305_tag_push,1),
    LS_CONST_PTR(crypto_secretstream_xchacha20poly1305_TAG_REKEY,crypto_secretstream_xchacha20poly1305_tag_rekey,1),
    LS_CONST_PTR(crypto_secretstream_xchacha20poly1305_TAG_FINAL,crypto_secretstream_xchacha20poly1305_tag_final,1),
    { NULL, 0, 0 },
};
