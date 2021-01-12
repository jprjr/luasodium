#include <sodium.h>
#include <stdio.h>
#include <assert.h>

#include "misc.h"

int main(void) {
    const unsigned char *message = (const unsigned char *)"a message";
    #define MESSAGE_LEN 9

    unsigned char hash[crypto_hash_BYTES];
    unsigned char hash_sha256[crypto_hash_sha256_BYTES];
    unsigned char hash_sha512[crypto_hash_sha512_BYTES];

    crypto_hash(hash,message,MESSAGE_LEN);
    crypto_hash_sha256(hash_sha256,message,MESSAGE_LEN);
    crypto_hash_sha512(hash_sha512,message,MESSAGE_LEN);

    printf("local expected_results = {\n");

    open_section("crypto_hash");
    dump_table("hash",hash,crypto_hash_BYTES);
    close_section();

    open_section("crypto_hash_sha256");
    dump_table("hash",hash_sha256,crypto_hash_sha256_BYTES);
    close_section();

    open_section("crypto_hash_sha512");
    dump_table("hash",hash_sha512,crypto_hash_sha512_BYTES);
    close_section();

    printf("}\n");

    return 0;
}
