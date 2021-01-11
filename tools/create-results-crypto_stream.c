#include <sodium.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "misc.h"

static void generate_crypto_stream(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_stream_KEYBYTES];
    unsigned char nonce[crypto_stream_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5
    unsigned char c[MESSAGE_LEN];

    memset(nonce,0,crypto_stream_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_stream_KEYBYTES,seed);

    r = crypto_stream_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);

    open_section("crypto_stream");
    dump_table("key",key,crypto_stream_KEYBYTES);
    dump_table("cipher",c,MESSAGE_LEN);
    crypto_stream(seed,randombytes_SEEDBYTES,nonce,key);
    dump_table("stream",seed,randombytes_SEEDBYTES);
    close_section();
}

static void generate_crypto_stream_xsalsa20(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_stream_xsalsa20_KEYBYTES];
    unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5
    unsigned char c[MESSAGE_LEN];

    memset(nonce,0,crypto_stream_xsalsa20_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_stream_xsalsa20_KEYBYTES,seed);

    r = crypto_stream_xsalsa20_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);

    open_section("crypto_stream_xsalsa20");
    dump_table("key",key,crypto_stream_xsalsa20_KEYBYTES);
    dump_table("cipher",c,MESSAGE_LEN);
    crypto_stream_xsalsa20(seed,randombytes_SEEDBYTES,nonce,key);
    dump_table("stream",seed,randombytes_SEEDBYTES);
    close_section();
}

static void generate_crypto_stream_salsa20(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_stream_salsa20_KEYBYTES];
    unsigned char nonce[crypto_stream_salsa20_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5
    unsigned char c[MESSAGE_LEN];

    memset(nonce,0,crypto_stream_salsa20_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_stream_salsa20_KEYBYTES,seed);

    r = crypto_stream_salsa20_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);

    open_section("crypto_stream_salsa20");
    dump_table("key",key,crypto_stream_salsa20_KEYBYTES);
    dump_table("cipher",c,MESSAGE_LEN);
    crypto_stream_salsa20(seed,randombytes_SEEDBYTES,nonce,key);
    dump_table("stream",seed,randombytes_SEEDBYTES);
    close_section();
}

static void generate_crypto_stream_salsa2012(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_stream_salsa2012_KEYBYTES];
    unsigned char nonce[crypto_stream_salsa2012_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5
    unsigned char c[MESSAGE_LEN];

    memset(nonce,0,crypto_stream_salsa2012_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_stream_salsa2012_KEYBYTES,seed);

    r = crypto_stream_salsa2012_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);

    open_section("crypto_stream_salsa2012");
    dump_table("key",key,crypto_stream_salsa2012_KEYBYTES);
    dump_table("cipher",c,MESSAGE_LEN);
    crypto_stream_salsa2012(seed,randombytes_SEEDBYTES,nonce,key);
    dump_table("stream",seed,randombytes_SEEDBYTES);
    close_section();
}


int main(void) {
    printf("local expected_results = {\n");

    generate_crypto_stream();
    generate_crypto_stream_xsalsa20();
    generate_crypto_stream_salsa20();
    generate_crypto_stream_salsa2012();

    printf("}\n");
    return 0;
}
