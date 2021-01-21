#include <sodium.h>
#include <stdio.h>
#include <assert.h>

#include "misc.h"

static
void generate_crypto_shorthash_results(void) {
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char hash[crypto_shorthash_BYTES];
    unsigned char key[crypto_shorthash_KEYBYTES];

    const unsigned char *message = (const unsigned char *)"a message";
    #define MESSAGE_LEN 9

    sodium_memzero(seed,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_shorthash_KEYBYTES,seed);
    crypto_shorthash(hash,message,MESSAGE_LEN,key);

    open_section("crypto_shorthash");
    dump_table("key",key,crypto_shorthash_KEYBYTES);
    dump_table("hash",hash,crypto_shorthash_BYTES);

    close_section();
}

static
void generate_crypto_shorthash_siphashx24_results(void) {
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char hash[crypto_shorthash_siphashx24_BYTES];
    unsigned char key[crypto_shorthash_siphashx24_KEYBYTES];

    const unsigned char *message = (const unsigned char *)"a message";
    #define MESSAGE_LEN 9

    sodium_memzero(seed,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_shorthash_siphashx24_KEYBYTES,seed);
    crypto_shorthash_siphashx24(hash,message,MESSAGE_LEN,key);

    open_section("crypto_shorthash_siphashx24");
    dump_table("key",key,crypto_shorthash_siphashx24_KEYBYTES);
    dump_table("hash",hash,crypto_shorthash_siphashx24_BYTES);

    close_section();
}

int main(void) {

    printf("local expected_results = {\n");

    generate_crypto_shorthash_results();
    generate_crypto_shorthash_siphashx24_results();

    printf("}\n");

    return 0;
}

