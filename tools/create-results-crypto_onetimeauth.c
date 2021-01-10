#include <sodium.h>
#include <stdio.h>
#include <assert.h>

#include "misc.h"

int main(void) {
    const unsigned char *message = (const unsigned char *)"a message";
    #define MESSAGE_LEN 9

    unsigned char seed[randombytes_SEEDBYTES];

    unsigned char key[crypto_onetimeauth_KEYBYTES];
    unsigned char out[crypto_onetimeauth_BYTES];

    unsigned char key_poly1305[crypto_onetimeauth_poly1305_KEYBYTES];
    unsigned char out_poly1305[crypto_onetimeauth_poly1305_BYTES];

    sodium_memzero(seed,randombytes_SEEDBYTES);
    randombytes_buf_deterministic(key,crypto_onetimeauth_KEYBYTES,seed);
    randombytes_buf_deterministic(key_poly1305,crypto_onetimeauth_poly1305_KEYBYTES,seed);

    crypto_onetimeauth(out,message,MESSAGE_LEN,key);
    crypto_onetimeauth(out_poly1305,message,MESSAGE_LEN,key_poly1305);

    printf("local expected_results = {\n");

    open_section("crypto_onetimeauth");
    dump_table("premade_key",key,crypto_onetimeauth_KEYBYTES);
    dump_table("auth",out,crypto_onetimeauth_BYTES);
    close_section();

    open_section("crypto_onetimeauth_poly1305");
    dump_table("premade_key",key_poly1305,crypto_onetimeauth_poly1305_KEYBYTES);
    dump_table("auth",out_poly1305,crypto_onetimeauth_poly1305_BYTES);
    close_section();

    printf("}\n");

    return 0;
}

