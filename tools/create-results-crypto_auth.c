#include <sodium.h>
#include <stdio.h>
#include <assert.h>

/* generates expected results for the crypto_auth spec tests */

static void
open_section(const char *name) {
    printf("  ['%s'] = {\n",name);
}

static void
close_section(void) {
    printf("  },\n");
}

static void
dump_table(const char *name, unsigned char *data, size_t length) {
    size_t i = 0;
    printf("    ['%s'] = {",name);
    for(i=0;i<length;i++) {
        if(i % 8 == 0) {
            printf("\n      ");
        }
        printf(" %u,",data[i]);
    }
    printf("\n    },\n");
}

int main(void) {
    const unsigned char *message = (const unsigned char *)"hello";

    unsigned char key[crypto_auth_KEYBYTES];
    unsigned char mac[crypto_auth_BYTES];

    unsigned char key_hmacsha256[crypto_auth_hmacsha256_KEYBYTES];
    unsigned char mac_hmacsha256[crypto_auth_hmacsha256_BYTES];

    unsigned char key_hmacsha512256[crypto_auth_hmacsha512256_KEYBYTES];
    unsigned char mac_hmacsha512256[crypto_auth_hmacsha512256_BYTES];

    unsigned char key_hmacsha512[crypto_auth_hmacsha512_KEYBYTES];
    unsigned char mac_hmacsha512[crypto_auth_hmacsha512_BYTES];

    int r;

    sodium_memzero(key,crypto_auth_KEYBYTES);
    sodium_memzero(mac,crypto_auth_BYTES);

    sodium_memzero(key_hmacsha256,crypto_auth_hmacsha256_KEYBYTES);
    sodium_memzero(mac_hmacsha256,crypto_auth_hmacsha256_BYTES);

    sodium_memzero(key_hmacsha512256,crypto_auth_hmacsha512256_KEYBYTES);
    sodium_memzero(mac_hmacsha512256,crypto_auth_hmacsha512256_BYTES);

    sodium_memzero(key_hmacsha512,crypto_auth_hmacsha512_KEYBYTES);
    sodium_memzero(mac_hmacsha512,crypto_auth_hmacsha512_BYTES);

    r = crypto_auth(mac,message,5,key);
    assert(r == 0);

    r = crypto_auth_hmacsha256(mac_hmacsha256,message,5,key_hmacsha256);
    assert(r == 0);

    r = crypto_auth_hmacsha512256(mac_hmacsha512256,message,5,key_hmacsha512256);
    assert(r == 0);

    r = crypto_auth_hmacsha512(mac_hmacsha512,message,5,key_hmacsha512);
    assert(r == 0);

    printf("local expected_results = {\n");

    open_section("crypto_auth");
    dump_table("mac",mac,crypto_auth_BYTES);
    close_section();

    open_section("crypto_auth_hmacsha256");
    dump_table("mac",mac_hmacsha256,crypto_auth_hmacsha256_BYTES);
    close_section();

    open_section("crypto_auth_hmacsha512256");
    dump_table("mac",mac_hmacsha512256,crypto_auth_hmacsha512256_BYTES);
    close_section();

    open_section("crypto_auth_hmacsha512");
    dump_table("mac",mac_hmacsha512,crypto_auth_hmacsha512_BYTES);
    close_section();

    printf("}\n");


    return 0;
}

