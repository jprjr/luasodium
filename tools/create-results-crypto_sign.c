#include <sodium.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "misc.h"

static void
create_results_crypto_sign(void) {

    const unsigned char *message = (const unsigned char *)"a message";

    #define MESSAGE_LEN 9

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char seed[crypto_sign_SEEDBYTES];

    unsigned char sm[MESSAGE_LEN + crypto_sign_BYTES];
    unsigned char sig[crypto_sign_BYTES];

    unsigned long long smlen;
    unsigned long long siglen;


    open_section("crypto_sign");

    memset(seed,0,crypto_sign_SEEDBYTES);
    crypto_sign_seed_keypair(pk,sk,seed);

    crypto_sign(sm,&smlen,message,MESSAGE_LEN,sk);
    crypto_sign_detached(sig,&siglen,message,MESSAGE_LEN,sk);

    dump_table("pk",pk,crypto_sign_PUBLICKEYBYTES);
    dump_table("sk",sk,crypto_sign_SECRETKEYBYTES);
    dump_table("sm",sm,smlen);
    dump_table("sig",sig,siglen);

    close_section();
}

static void
create_results_crypto_sign_mp(void) {

    const unsigned char *message_part1 = (const unsigned char *)"a ";
    const unsigned char *message_part2 = (const unsigned char *)"message";

    #define MESSAGE_PART1_LEN 2
    #define MESSAGE_PART2_LEN 7

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char seed[crypto_sign_SEEDBYTES];

    unsigned char sig[crypto_sign_BYTES];

    unsigned long long siglen;

    crypto_sign_state state;

    open_section("crypto_sign_mp");

    memset(seed,0,crypto_sign_SEEDBYTES);
    crypto_sign_seed_keypair(pk,sk,seed);

    crypto_sign_init(&state);
    crypto_sign_update(&state,message_part1,MESSAGE_PART1_LEN);
    crypto_sign_update(&state,message_part2,MESSAGE_PART2_LEN);
    crypto_sign_final_create(&state,sig,&siglen,sk);
    dump_table("sig",sig,siglen);

    close_section();
}

static void
create_results_crypto_sign_ed25519(void) {

    const unsigned char *message = (const unsigned char *)"a message";

    #define MESSAGE_LEN 9

    unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
    unsigned char seed[crypto_sign_ed25519_SEEDBYTES];

    unsigned char sm[MESSAGE_LEN + crypto_sign_ed25519_BYTES];
    unsigned char sig[crypto_sign_ed25519_BYTES];

    unsigned long long smlen;
    unsigned long long siglen;

    open_section("crypto_sign_ed25519");

    memset(seed,0,crypto_sign_ed25519_SEEDBYTES);
    crypto_sign_ed25519_seed_keypair(pk,sk,seed);

    crypto_sign_ed25519(sm,&smlen,message,MESSAGE_LEN,sk);
    crypto_sign_ed25519_detached(sig,&siglen,message,MESSAGE_LEN,sk);

    dump_table("pk",pk,crypto_sign_ed25519_PUBLICKEYBYTES);
    dump_table("sk",sk,crypto_sign_ed25519_SECRETKEYBYTES);
    dump_table("sm",sm,smlen);
    dump_table("sig",sig,siglen);

    close_section();
}

static void
create_results_crypto_sign_ed25519_mp(void) {
    const unsigned char *message_part1 = (const unsigned char *)"a ";
    const unsigned char *message_part2 = (const unsigned char *)"message";

    #define MESSAGE_PART1_LEN 2
    #define MESSAGE_PART2_LEN 7

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char seed[crypto_sign_SEEDBYTES];

    unsigned char sig[crypto_sign_BYTES];

    unsigned long long siglen;

    crypto_sign_ed25519ph_state state;

    open_section("crypto_sign_ed25519_mp");

    memset(seed,0,crypto_sign_ed25519_SEEDBYTES);
    crypto_sign_ed25519_seed_keypair(pk,sk,seed);

    crypto_sign_init(&state);
    crypto_sign_update(&state,message_part1,MESSAGE_PART1_LEN);
    crypto_sign_update(&state,message_part2,MESSAGE_PART2_LEN);
    crypto_sign_final_create(&state,sig,&siglen,sk);
    dump_table("sig",sig,siglen);

    close_section();
}

int main(void) {
    printf("local expected_results = {\n");

    create_results_crypto_sign();
    create_results_crypto_sign_mp();
    create_results_crypto_sign_ed25519();
    create_results_crypto_sign_ed25519_mp();

    printf("}\n");
    return 0;
}

