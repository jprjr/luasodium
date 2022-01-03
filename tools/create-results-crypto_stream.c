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

    open_section("crypto_stream");
    dump_table("key",key,crypto_stream_KEYBYTES);

    r = crypto_stream_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);
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

    open_section("crypto_stream_xsalsa20");
    dump_table("key",key,crypto_stream_xsalsa20_KEYBYTES);

    r = crypto_stream_xsalsa20_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);
    dump_table("cipher",c,MESSAGE_LEN);

    r = crypto_stream_xsalsa20_xor_ic(c,message,MESSAGE_LEN,nonce,1,key);
    assert(r == 0);
    dump_table("cipher_ic",c,MESSAGE_LEN);

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

    open_section("crypto_stream_salsa20");
    dump_table("key",key,crypto_stream_salsa20_KEYBYTES);

    r = crypto_stream_salsa20_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);
    dump_table("cipher",c,MESSAGE_LEN);

    r = crypto_stream_salsa20_xor_ic(c,message,MESSAGE_LEN,nonce,1,key);
    assert(r == 0);
    dump_table("cipher_ic",c,MESSAGE_LEN);

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

    open_section("crypto_stream_salsa2012");
    dump_table("key",key,crypto_stream_salsa2012_KEYBYTES);

    r = crypto_stream_salsa2012_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);
    dump_table("cipher",c,MESSAGE_LEN);

    crypto_stream_salsa2012(seed,randombytes_SEEDBYTES,nonce,key);
    dump_table("stream",seed,randombytes_SEEDBYTES);

    close_section();
}

static void generate_crypto_stream_salsa208(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_stream_salsa208_KEYBYTES];
    unsigned char nonce[crypto_stream_salsa208_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5
    unsigned char c[MESSAGE_LEN];

    memset(nonce,0,crypto_stream_salsa208_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_stream_salsa208_KEYBYTES,seed);

    open_section("crypto_stream_salsa208");
    dump_table("key",key,crypto_stream_salsa208_KEYBYTES);

    r = crypto_stream_salsa208_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);
    dump_table("cipher",c,MESSAGE_LEN);

    crypto_stream_salsa208(seed,randombytes_SEEDBYTES,nonce,key);
    dump_table("stream",seed,randombytes_SEEDBYTES);

    close_section();
}

static void generate_crypto_stream_xchacha20(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_stream_xchacha20_KEYBYTES];
    unsigned char nonce[crypto_stream_xchacha20_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5
    unsigned char c[MESSAGE_LEN];

    memset(nonce,0,crypto_stream_xchacha20_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_stream_xchacha20_KEYBYTES,seed);

    open_section("crypto_stream_xchacha20");
    dump_table("key",key,crypto_stream_xchacha20_KEYBYTES);

    r = crypto_stream_xchacha20_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);
    dump_table("cipher",c,MESSAGE_LEN);

    r = crypto_stream_xchacha20_xor_ic(c,message,MESSAGE_LEN,nonce,1,key);
    assert(r == 0);
    dump_table("cipher_ic",c,MESSAGE_LEN);

    crypto_stream_xchacha20(seed,randombytes_SEEDBYTES,nonce,key);
    dump_table("stream",seed,randombytes_SEEDBYTES);

    close_section();
}

static void generate_crypto_stream_chacha20(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_stream_chacha20_KEYBYTES];
    unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5
    unsigned char c[MESSAGE_LEN];

    memset(nonce,0,crypto_stream_chacha20_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_stream_chacha20_KEYBYTES,seed);

    open_section("crypto_stream_chacha20");
    dump_table("key",key,crypto_stream_chacha20_KEYBYTES);

    r = crypto_stream_chacha20_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);
    dump_table("cipher",c,MESSAGE_LEN);

    r = crypto_stream_chacha20_xor_ic(c,message,MESSAGE_LEN,nonce,1,key);
    assert(r == 0);
    dump_table("cipher_ic",c,MESSAGE_LEN);

    crypto_stream_chacha20(seed,randombytes_SEEDBYTES,nonce,key);
    dump_table("stream",seed,randombytes_SEEDBYTES);

    close_section();
}

static void generate_crypto_stream_chacha20_ietf(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_stream_chacha20_ietf_KEYBYTES];
    unsigned char nonce[crypto_stream_chacha20_ietf_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5
    unsigned char c[MESSAGE_LEN];

    memset(nonce,0,crypto_stream_chacha20_ietf_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_stream_chacha20_ietf_KEYBYTES,seed);

    open_section("crypto_stream_chacha20_ietf");
    dump_table("key",key,crypto_stream_chacha20_ietf_KEYBYTES);

    r = crypto_stream_chacha20_ietf_xor(c,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);
    dump_table("cipher",c,MESSAGE_LEN);

    r = crypto_stream_chacha20_ietf_xor_ic(c,message,MESSAGE_LEN,nonce,1,key);
    assert(r == 0);
    dump_table("cipher_ic",c,MESSAGE_LEN);

    crypto_stream_chacha20_ietf(seed,randombytes_SEEDBYTES,nonce,key);
    dump_table("stream",seed,randombytes_SEEDBYTES);

    close_section();
}

int main(void) {
    printf("local expected_results = {\n");

    generate_crypto_stream();
    generate_crypto_stream_xsalsa20();
    generate_crypto_stream_salsa20();
    generate_crypto_stream_salsa2012();
    generate_crypto_stream_salsa208();
    generate_crypto_stream_xchacha20();
    generate_crypto_stream_chacha20();
    generate_crypto_stream_chacha20_ietf();

    printf("}\n");
    return 0;
}
