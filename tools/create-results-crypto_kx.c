#include <sodium.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "misc.h"

int main(void) {
    int r;
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES], client_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char client_rx[crypto_kx_SESSIONKEYBYTES], client_tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char server_rx[crypto_kx_SESSIONKEYBYTES], server_tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char seed0[crypto_kx_SEEDBYTES];
    unsigned char seed1[crypto_kx_SEEDBYTES];

    memset(seed0,0,crypto_kx_SEEDBYTES);

    r = crypto_kx_seed_keypair(client_pk,client_sk,seed0);
    assert(r == 0);

    memcpy(seed1,seed0,crypto_kx_SEEDBYTES);
    sodium_increment(seed1,crypto_kx_SEEDBYTES);
    r = crypto_kx_seed_keypair(server_pk,server_sk,seed1);
    assert(r == 0);

    r = crypto_kx_client_session_keys(client_rx,client_tx,client_pk,client_sk,server_pk);
    assert(r == 0);
    r = crypto_kx_server_session_keys(server_rx,server_tx,server_pk,server_sk,client_pk);
    assert(r == 0);

    printf("local expected_results = {\n");

    open_section("crypto_kx");
    dump_table("client_pk",client_pk,crypto_kx_PUBLICKEYBYTES);
    dump_table("client_sk",client_sk,crypto_kx_SECRETKEYBYTES);
    dump_table("client_rx",client_rx,crypto_kx_SESSIONKEYBYTES);
    dump_table("client_tx",client_tx,crypto_kx_SESSIONKEYBYTES);
    dump_table("server_pk",server_pk,crypto_kx_PUBLICKEYBYTES);
    dump_table("server_sk",server_sk,crypto_kx_SECRETKEYBYTES);
    dump_table("server_rx",server_rx,crypto_kx_SESSIONKEYBYTES);
    dump_table("server_tx",server_tx,crypto_kx_SESSIONKEYBYTES);
    close_section();

    printf("}\n");

    printf("\n crypto_kx_SESSIONKEYBYTES = %lu\n",crypto_kx_SESSIONKEYBYTES);
    printf("crypto_secretbox_KEYBYTES = %lu\n",crypto_secretbox_KEYBYTES);

    return 0;
}
