#include <sodium.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "misc.h"

/* generates expected results for the crypto_auth spec tests */


/* in spec tests, sender uses a seed of all zeroes,
 * receiver uses a seed of all 0xff */

static void generate_crypto_box(void) {
    int r;
    unsigned char seed[crypto_box_SEEDBYTES];
    unsigned char sender_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sender_sk[crypto_box_SECRETKEYBYTES];
    unsigned char receiver_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char receiver_sk[crypto_box_SECRETKEYBYTES];
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char beforenm_encrypt[crypto_box_BEFORENMBYTES];
    unsigned char beforenm_decrypt[crypto_box_BEFORENMBYTES];
    const unsigned char *message = (const unsigned char *) "hello";

    unsigned char boxed_message[crypto_box_ZEROBYTES + 5];
    unsigned char boxed_cipher[crypto_box_BOXZEROBYTES + crypto_box_MACBYTES + 5];

    memset(boxed_message,0,crypto_box_ZEROBYTES+5);
    memset(boxed_cipher,0,crypto_box_BOXZEROBYTES + crypto_box_MACBYTES + 5);
    memset(nonce,0,crypto_box_NONCEBYTES);

    memcpy(&boxed_message[crypto_box_ZEROBYTES],message,5);

    memset(seed,0,crypto_box_SEEDBYTES);
    crypto_box_seed_keypair(sender_pk,sender_sk,seed);
    memset(seed,0xff,crypto_box_SEEDBYTES);
    crypto_box_seed_keypair(receiver_pk,receiver_sk,seed);

    r = crypto_box_beforenm(beforenm_encrypt,receiver_pk,sender_sk);
    assert(r == 0);
    r = crypto_box_beforenm(beforenm_decrypt,sender_pk,receiver_sk);
    assert(r == 0);

    r = crypto_box(boxed_cipher,boxed_message,crypto_box_ZEROBYTES+5,nonce,receiver_pk,sender_sk);
    assert(r == 0);

    open_section("crypto_box");
    dump_table("sender_pk",sender_pk,crypto_box_PUBLICKEYBYTES);
    dump_table("sender_sk",sender_sk,crypto_box_PUBLICKEYBYTES);
    dump_table("receiver_pk",receiver_pk,crypto_box_PUBLICKEYBYTES);
    dump_table("receiver_sk",receiver_sk,crypto_box_PUBLICKEYBYTES);
    dump_table("beforenm_encrypt",beforenm_encrypt,crypto_box_BEFORENMBYTES);
    dump_table("beforenm_decrypt",beforenm_decrypt,crypto_box_BEFORENMBYTES);
    dump_table("mac",&boxed_cipher[crypto_box_BOXZEROBYTES],crypto_box_MACBYTES);
    dump_table("cipher",&boxed_cipher[crypto_box_BOXZEROBYTES + crypto_box_MACBYTES],5);

    close_section();
}

static void generate_crypto_box_easy(void) {
    int r;
    unsigned char seed[crypto_box_SEEDBYTES];
    unsigned char sender_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sender_sk[crypto_box_SECRETKEYBYTES];
    unsigned char receiver_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char receiver_sk[crypto_box_SECRETKEYBYTES];
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char beforenm_encrypt[crypto_box_BEFORENMBYTES];
    unsigned char beforenm_decrypt[crypto_box_BEFORENMBYTES];
    const unsigned char *message = (const unsigned char *) "hello";

    unsigned char cipher[crypto_box_MACBYTES + 5];

    memset(cipher,0,crypto_box_MACBYTES + 5);
    memset(nonce,0,crypto_box_NONCEBYTES);

    memset(seed,0,crypto_box_SEEDBYTES);
    crypto_box_seed_keypair(sender_pk,sender_sk,seed);
    memset(seed,0xff,crypto_box_SEEDBYTES);
    crypto_box_seed_keypair(receiver_pk,receiver_sk,seed);

    r = crypto_box_beforenm(beforenm_encrypt,receiver_pk,sender_sk);
    assert(r == 0);
    r = crypto_box_beforenm(beforenm_decrypt,sender_pk,receiver_sk);
    assert(r == 0);

    r = crypto_box_easy(cipher,message,5,nonce,receiver_pk,sender_sk);
    assert(r == 0);

    open_section("crypto_box_easy");
    dump_table("sender_pk",sender_pk,crypto_box_PUBLICKEYBYTES);
    dump_table("sender_sk",sender_sk,crypto_box_PUBLICKEYBYTES);
    dump_table("receiver_pk",receiver_pk,crypto_box_PUBLICKEYBYTES);
    dump_table("receiver_sk",receiver_sk,crypto_box_PUBLICKEYBYTES);
    dump_table("beforenm_encrypt",beforenm_encrypt,crypto_box_BEFORENMBYTES);
    dump_table("beforenm_decrypt",beforenm_decrypt,crypto_box_BEFORENMBYTES);
    dump_table("mac",&cipher[0],crypto_box_MACBYTES);
    dump_table("cipher",&cipher[crypto_box_MACBYTES],5);

    close_section();
}

static void generate_crypto_box_curve25519xsalsa20poly1305(void) {
    int r;
    unsigned char seed[crypto_box_curve25519xsalsa20poly1305_SEEDBYTES];
    unsigned char sender_pk[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
    unsigned char sender_sk[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];
    unsigned char receiver_pk[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
    unsigned char receiver_sk[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];
    unsigned char nonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES];
    unsigned char beforenm_encrypt[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
    unsigned char beforenm_decrypt[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
    const unsigned char *message = (const unsigned char *) "hello";

    unsigned char boxed_message[crypto_box_curve25519xsalsa20poly1305_ZEROBYTES + 5];
    unsigned char boxed_cipher[crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES + crypto_box_curve25519xsalsa20poly1305_MACBYTES + 5];

    memset(boxed_message,0,crypto_box_curve25519xsalsa20poly1305_ZEROBYTES+5);
    memset(boxed_cipher,0,crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES + crypto_box_curve25519xsalsa20poly1305_MACBYTES + 5);
    memset(nonce,0,crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);

    memcpy(&boxed_message[crypto_box_curve25519xsalsa20poly1305_ZEROBYTES],message,5);

    memset(seed,0,crypto_box_curve25519xsalsa20poly1305_SEEDBYTES);
    crypto_box_curve25519xsalsa20poly1305_seed_keypair(sender_pk,sender_sk,seed);
    memset(seed,0xff,crypto_box_curve25519xsalsa20poly1305_SEEDBYTES);
    crypto_box_curve25519xsalsa20poly1305_seed_keypair(receiver_pk,receiver_sk,seed);

    r = crypto_box_curve25519xsalsa20poly1305_beforenm(beforenm_encrypt,receiver_pk,sender_sk);
    assert(r == 0);
    r = crypto_box_curve25519xsalsa20poly1305_beforenm(beforenm_decrypt,sender_pk,receiver_sk);
    assert(r == 0);

    r = crypto_box_curve25519xsalsa20poly1305(boxed_cipher,boxed_message,crypto_box_curve25519xsalsa20poly1305_ZEROBYTES+5,nonce,receiver_pk,sender_sk);
    assert(r == 0);

    open_section("crypto_box_curve25519xsalsa20poly1305");
    dump_table("sender_pk",sender_pk,crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    dump_table("sender_sk",sender_sk,crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    dump_table("receiver_pk",receiver_pk,crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    dump_table("receiver_sk",receiver_sk,crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    dump_table("beforenm_encrypt",beforenm_encrypt,crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    dump_table("beforenm_decrypt",beforenm_decrypt,crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    dump_table("mac",&boxed_cipher[crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES],crypto_box_curve25519xsalsa20poly1305_MACBYTES);
    dump_table("cipher",&boxed_cipher[crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES + crypto_box_curve25519xsalsa20poly1305_MACBYTES],5);

    close_section();
}

int main(void) {
    printf("local expected_results = {\n");

    generate_crypto_box();
    generate_crypto_box_curve25519xsalsa20poly1305();

    /* somewhat redundant, but if crypto_box_easy changes primitives or anything, I
     * want to be able to generate new results */
    generate_crypto_box_easy();

    printf("}\n");

    return 0;
}
