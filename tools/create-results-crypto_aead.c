#include <sodium.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "misc.h"


#define GEN_TEST_FUNC(x) \
static void generate_crypto_aead_ ## x(void) { \
    unsigned char seed[randombytes_SEEDBYTES]; \
    unsigned char nonce[crypto_aead_ ## x ## _NPUBBYTES]; \
    unsigned char key[crypto_aead_ ## x ## _KEYBYTES]; \
    unsigned char ciphertext[5 + crypto_aead_ ## x ## _ABYTES]; \
    unsigned char ciphertext_detached[5]; \
    unsigned char mac_detached[crypto_aead_ ## x ## _ABYTES]; \
    const unsigned char *message = (const unsigned char *) "hello"; \
    const unsigned char *ad = (const unsigned char *)"ad-data"; \
    unsigned long long ciphertext_len = 0; \
    memset(seed,0,randombytes_SEEDBYTES); \
    memset(nonce,0xFF,crypto_aead_ ## x ## _NPUBBYTES); \
    memset(key,0xFF,crypto_aead_ ## x ## _KEYBYTES); \
    randombytes_buf_deterministic(key,crypto_aead_ ## x ## _KEYBYTES,seed); \
    randombytes_buf_deterministic(nonce,crypto_aead_ ## x ## _NPUBBYTES,seed); \
    open_section("crypto_aead_" #x); \
    dump_table("nonce",nonce,crypto_aead_ ## x ## _NPUBBYTES); \
    dump_table("key",key,crypto_aead_ ## x ## _KEYBYTES); \
    crypto_aead_ ## x ## _encrypt(ciphertext,&ciphertext_len, \
      message, 5, ad, 7, \
      NULL, nonce, key); \
    dump_table("cipher",ciphertext,ciphertext_len); \
    crypto_aead_ ## x ## _encrypt(ciphertext,&ciphertext_len, \
      message, 5, NULL, 0, \
      NULL, nonce, key); \
    dump_table("cipher_noad",ciphertext,ciphertext_len); \
    crypto_aead_ ## x ## _encrypt_detached(ciphertext_detached,mac_detached,&ciphertext_len, \
      message, 5, ad, 7, \
      NULL, nonce, key); \
    dump_table("cipher_detached",ciphertext_detached,5); \
    dump_table("mac",mac_detached,crypto_aead_ ## x ## _ABYTES); \
    crypto_aead_ ## x ## _encrypt_detached(ciphertext_detached,mac_detached,&ciphertext_len, \
      message, 5, NULL, 0, \
      NULL, nonce, key); \
    dump_table("cipher_noad_detached",ciphertext_detached,5); \
    dump_table("mac_noad",mac_detached,crypto_aead_ ## x ## _ABYTES); \
    close_section(); \
}

GEN_TEST_FUNC(chacha20poly1305)
GEN_TEST_FUNC(chacha20poly1305_ietf)
GEN_TEST_FUNC(xchacha20poly1305_ietf)
GEN_TEST_FUNC(aes256gcm)

int main(void) {
    printf("local expected_results = {\n");

    generate_crypto_aead_chacha20poly1305();
    generate_crypto_aead_chacha20poly1305_ietf();
    generate_crypto_aead_xchacha20poly1305_ietf();
    generate_crypto_aead_aes256gcm();

    printf("}\n");

    return 0;
}
