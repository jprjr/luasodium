static const luasodium_constant_t luasodium_box_constants[] = {
    { "PUBLICKEYBYTES", crypto_box_PUBLICKEYBYTES },
    { "SECRETKEYBYTES", crypto_box_SECRETKEYBYTES },
    { "MACBYTES",       crypto_box_MACBYTES       },
    { "NONCEBYTES",     crypto_box_NONCEBYTES     },
    { "SEEDBYTES",      crypto_box_SEEDBYTES      },
    { "BEFORENMBYTES",  crypto_box_BEFORENMBYTES  },
    { NULL, 0 },
};

