#include <sodium.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "misc.h"

static void generate_crypto_generichash(void) {
    unsigned char seed[randombytes_SEEDBYTES];

    unsigned char key[crypto_generichash_KEYBYTES];

    unsigned char hash[crypto_generichash_BYTES];
    unsigned char hash_min[crypto_generichash_BYTES_MIN];
    unsigned char hash_max[crypto_generichash_BYTES_MAX];

    unsigned char hash_mp[crypto_generichash_BYTES];
    unsigned char hash_mp_min[crypto_generichash_BYTES_MIN];
    unsigned char hash_mp_max[crypto_generichash_BYTES_MAX];

    const unsigned char *message = (const unsigned char *)"a message";
    const unsigned char *message_part1 = (const unsigned char *)"a ";
    const unsigned char *message_part2 = (const unsigned char *)"message";

    crypto_generichash_state state;
    crypto_generichash_state state_min;
    crypto_generichash_state state_max;

    sodium_memzero(seed,randombytes_SEEDBYTES);

    sodium_memzero(hash,crypto_generichash_BYTES);
    sodium_memzero(hash_min,crypto_generichash_BYTES_MIN);
    sodium_memzero(hash_max,crypto_generichash_BYTES_MAX);

    sodium_memzero(hash_mp,crypto_generichash_BYTES);
    sodium_memzero(hash_mp_min,crypto_generichash_BYTES_MIN);
    sodium_memzero(hash_mp_max,crypto_generichash_BYTES_MAX);

    randombytes_buf_deterministic(key,crypto_generichash_KEYBYTES,seed);

    crypto_generichash_init(&state, key, crypto_generichash_KEYBYTES, crypto_generichash_BYTES);
    crypto_generichash_init(&state_min, key, crypto_generichash_KEYBYTES, crypto_generichash_BYTES_MIN);
    crypto_generichash_init(&state_max, key, crypto_generichash_KEYBYTES, crypto_generichash_BYTES_MAX);

    crypto_generichash(hash,crypto_generichash_BYTES,
      message, 9,
      key,crypto_generichash_KEYBYTES);

    crypto_generichash(hash_min,crypto_generichash_BYTES_MIN,
      message, 9,
      key,crypto_generichash_KEYBYTES);

    crypto_generichash(hash_max,crypto_generichash_BYTES_MAX,
      message, 9,
      key,crypto_generichash_KEYBYTES);

   
    crypto_generichash_update(&state,message_part1,2);
    crypto_generichash_update(&state_min,message_part1,2);
    crypto_generichash_update(&state_max,message_part1,2);

    crypto_generichash_update(&state,message_part2,7);
    crypto_generichash_update(&state_min,message_part2,7);
    crypto_generichash_update(&state_max,message_part2,7);

    crypto_generichash_final(&state,hash_mp,crypto_generichash_BYTES);
    crypto_generichash_final(&state_min,hash_mp_min,crypto_generichash_BYTES_MIN);
    crypto_generichash_final(&state_max,hash_mp_max,crypto_generichash_BYTES_MAX);

    assert(sodium_memcmp(hash,hash_mp,crypto_generichash_BYTES) == 0);
    assert(sodium_memcmp(hash_min,hash_mp_min,crypto_generichash_BYTES_MIN) == 0);
    assert(sodium_memcmp(hash_max,hash_mp_max,crypto_generichash_BYTES_MAX) == 0);

    open_section("crypto_generichash");

    dump_table("key",key,crypto_generichash_KEYBYTES);

    dump_table("hash",hash,crypto_generichash_BYTES);
    dump_table("hash_min",hash_min,crypto_generichash_BYTES_MIN);
    dump_table("hash_max",hash_max,crypto_generichash_BYTES_MAX);

    /* this time, without a key */
    crypto_generichash_init(&state,     NULL, 0, crypto_generichash_BYTES);
    crypto_generichash_init(&state_min, NULL, 0, crypto_generichash_BYTES_MIN);
    crypto_generichash_init(&state_max, NULL, 0, crypto_generichash_BYTES_MAX);

    crypto_generichash(hash,crypto_generichash_BYTES,
      message, 9,
      NULL, 0);

    crypto_generichash(hash_min,crypto_generichash_BYTES_MIN,
      message, 9,
      NULL, 0);

    crypto_generichash(hash_max,crypto_generichash_BYTES_MAX,
      message, 9,
      NULL, 0);

   
    crypto_generichash_update(&state,message_part1,2);
    crypto_generichash_update(&state_min,message_part1,2);
    crypto_generichash_update(&state_max,message_part1,2);

    crypto_generichash_update(&state,message_part2,7);
    crypto_generichash_update(&state_min,message_part2,7);
    crypto_generichash_update(&state_max,message_part2,7);

    crypto_generichash_final(&state,hash_mp,crypto_generichash_BYTES);
    crypto_generichash_final(&state_min,hash_mp_min,crypto_generichash_BYTES_MIN);
    crypto_generichash_final(&state_max,hash_mp_max,crypto_generichash_BYTES_MAX);

    assert(sodium_memcmp(hash,hash_mp,crypto_generichash_BYTES) == 0);
    assert(sodium_memcmp(hash_min,hash_mp_min,crypto_generichash_BYTES_MIN) == 0);
    assert(sodium_memcmp(hash_max,hash_mp_max,crypto_generichash_BYTES_MAX) == 0);

    dump_table("hash_nokey",hash,crypto_generichash_BYTES);
    dump_table("hash_nokey_min",hash_min,crypto_generichash_BYTES_MIN);
    dump_table("hash_nokey_max",hash_max,crypto_generichash_BYTES_MAX);

    close_section();

}

int main(void) {
    printf("local expected_results = {\n");
    generate_crypto_generichash();
    printf("}\n");
    return 0;
}
