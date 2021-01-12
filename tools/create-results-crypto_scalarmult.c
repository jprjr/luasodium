#include <sodium.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "misc.h"

int main(void) {
    int r = 0;
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char n[crypto_scalarmult_SCALARBYTES];
    unsigned char p[crypto_scalarmult_BYTES];
    unsigned char pk[crypto_scalarmult_BYTES];
    unsigned char q[crypto_scalarmult_BYTES];

    unsigned char n_curve25519[crypto_scalarmult_curve25519_SCALARBYTES];
    unsigned char p_curve25519[crypto_scalarmult_curve25519_BYTES];
    unsigned char pk_curve25519[crypto_scalarmult_curve25519_BYTES];
    unsigned char q_curve25519[crypto_scalarmult_curve25519_BYTES];

    memset(seed,0,randombytes_SEEDBYTES);
    randombytes_buf_deterministic(n,crypto_scalarmult_SCALARBYTES,seed);
    sodium_increment(seed,randombytes_SEEDBYTES);
    randombytes_buf_deterministic(p,crypto_scalarmult_BYTES,seed);

    memset(seed,0,randombytes_SEEDBYTES);
    randombytes_buf_deterministic(n_curve25519,crypto_scalarmult_curve25519_SCALARBYTES,seed);
    sodium_increment(seed,randombytes_SEEDBYTES);
    randombytes_buf_deterministic(p_curve25519,crypto_scalarmult_curve25519_BYTES,seed);

    r = crypto_scalarmult_base(pk,n);
    assert(r == 0);
    r = crypto_scalarmult(q, n, p);
    assert(r == 0);

    r = crypto_scalarmult_curve25519_base(pk_curve25519,n_curve25519);
    assert(r == 0);
    r = crypto_scalarmult_curve25519(q_curve25519, n_curve25519, p_curve25519);
    assert(r == 0);

    printf("local expected_results = {\n");

    open_section("crypto_scalarmult");
    dump_table("n",n,crypto_scalarmult_SCALARBYTES);
    dump_table("p",p,crypto_scalarmult_BYTES);
    dump_table("pk",pk,crypto_scalarmult_BYTES);
    dump_table("q",q,crypto_scalarmult_BYTES);
    close_section();

    open_section("crypto_scalarmult_curve25519");
    dump_table("n",n_curve25519,crypto_scalarmult_curve25519_SCALARBYTES);
    dump_table("p",p_curve25519,crypto_scalarmult_curve25519_BYTES);
    dump_table("pk",pk_curve25519,crypto_scalarmult_curve25519_BYTES);
    dump_table("q",q_curve25519,crypto_scalarmult_curve25519_BYTES);
    close_section();

    printf("}\n");
    return 0;
}
