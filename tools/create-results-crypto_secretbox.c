#include <sodium.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "misc.h"

static void generate_crypto_secretbox(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5

    unsigned char boxed_message[crypto_secretbox_ZEROBYTES + MESSAGE_LEN];
    unsigned char boxed_cipher[crypto_secretbox_BOXZEROBYTES + crypto_secretbox_MACBYTES+ MESSAGE_LEN];

    memset(boxed_message,0,crypto_secretbox_ZEROBYTES + MESSAGE_LEN);
    memset(boxed_cipher,0,crypto_secretbox_BOXZEROBYTES + crypto_secretbox_MACBYTES + MESSAGE_LEN);
    memset(nonce,0,crypto_secretbox_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    memcpy(&boxed_message[crypto_secretbox_ZEROBYTES],message,MESSAGE_LEN);

    randombytes_buf_deterministic(key,crypto_secretbox_KEYBYTES,seed);

    r = crypto_secretbox(boxed_cipher,boxed_message,crypto_secretbox_ZEROBYTES + MESSAGE_LEN,nonce,key);
    assert(r == 0);

    open_section("crypto_secretbox");
    dump_table("key",key,crypto_secretbox_KEYBYTES);
    dump_table("mac",&boxed_cipher[crypto_secretbox_BOXZEROBYTES],crypto_secretbox_MACBYTES);
    dump_table("cipher",&boxed_cipher[crypto_secretbox_BOXZEROBYTES + crypto_secretbox_MACBYTES],MESSAGE_LEN);
    close_section();
}

static void generate_crypto_secretbox_xsalsa20poly1305(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_secretbox_xsalsa20poly1305_KEYBYTES];
    unsigned char nonce[crypto_secretbox_xsalsa20poly1305_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5

    unsigned char boxed_message[crypto_secretbox_xsalsa20poly1305_ZEROBYTES + MESSAGE_LEN];
    unsigned char boxed_cipher[crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES + crypto_secretbox_xsalsa20poly1305_MACBYTES+ MESSAGE_LEN];

    memset(boxed_message,0,crypto_secretbox_xsalsa20poly1305_ZEROBYTES + MESSAGE_LEN);
    memset(boxed_cipher,0,crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES + crypto_secretbox_xsalsa20poly1305_MACBYTES + MESSAGE_LEN);
    memset(nonce,0,crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    memcpy(&boxed_message[crypto_secretbox_xsalsa20poly1305_ZEROBYTES],message,MESSAGE_LEN);

    randombytes_buf_deterministic(key,crypto_secretbox_xsalsa20poly1305_KEYBYTES,seed);

    r = crypto_secretbox_xsalsa20poly1305(boxed_cipher,boxed_message,crypto_secretbox_xsalsa20poly1305_ZEROBYTES + MESSAGE_LEN,nonce,key);
    assert(r == 0);

    open_section("crypto_secretbox_xsalsa20poly1305");
    dump_table("key",key,crypto_secretbox_xsalsa20poly1305_KEYBYTES);
    dump_table("mac",&boxed_cipher[crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES],crypto_secretbox_xsalsa20poly1305_MACBYTES);
    dump_table("cipher",&boxed_cipher[crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES + crypto_secretbox_xsalsa20poly1305_MACBYTES],MESSAGE_LEN);
    close_section();
}

static void generate_crypto_secretbox_easy(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5

    unsigned char cipher[crypto_secretbox_MACBYTES+ MESSAGE_LEN];

    memset(nonce,0,crypto_secretbox_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_secretbox_KEYBYTES,seed);

    r = crypto_secretbox_easy(cipher,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);

    open_section("crypto_secretbox_easy");
    dump_table("key",key,crypto_secretbox_KEYBYTES);
    dump_table("mac",&cipher[0],crypto_secretbox_MACBYTES);
    dump_table("cipher",&cipher[crypto_secretbox_MACBYTES],MESSAGE_LEN);
    close_section();
}

static void generate_crypto_secretbox_xchacha20poly1305_easy(void) {
    int r;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char key[crypto_secretbox_xchacha20poly1305_KEYBYTES];
    unsigned char nonce[crypto_secretbox_xchacha20poly1305_NONCEBYTES];
    const unsigned char *message = (const unsigned char *) "hello";
    #define MESSAGE_LEN 5

    unsigned char cipher[crypto_secretbox_xchacha20poly1305_MACBYTES+ MESSAGE_LEN];

    memset(nonce,0,crypto_secretbox_xchacha20poly1305_NONCEBYTES);
    memset(seed,0,randombytes_SEEDBYTES);

    randombytes_buf_deterministic(key,crypto_secretbox_xchacha20poly1305_KEYBYTES,seed);

    r = crypto_secretbox_xchacha20poly1305_easy(cipher,message,MESSAGE_LEN,nonce,key);
    assert(r == 0);

    open_section("crypto_secretbox_xchacha20poly1305_easy");
    dump_table("key",key,crypto_secretbox_xchacha20poly1305_KEYBYTES);
    dump_table("mac",&cipher[0],crypto_secretbox_xchacha20poly1305_MACBYTES);
    dump_table("cipher",&cipher[crypto_secretbox_xchacha20poly1305_MACBYTES],MESSAGE_LEN);
    close_section();
}

int main(void) {
    printf("local expected_results = {\n");

    generate_crypto_secretbox();
    generate_crypto_secretbox_xsalsa20poly1305();
    generate_crypto_secretbox_easy();
    generate_crypto_secretbox_xchacha20poly1305_easy();

    printf("}\n");

    return 0;
}
