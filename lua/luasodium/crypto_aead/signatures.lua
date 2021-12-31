local crypto_aead_is_available_sig = [[
int %s(void)
]]

local crypto_aead_encrypt_sig = [[
int %s(unsigned char *c,
       unsigned long long *clen_p,
       const unsigned char *m,
       unsigned long long mlen,
       const unsigned char *ad,
       unsigned long long adlen,
       const unsigned char *nsec,
       const unsigned char *npub,
       const unsigned char *k)
]]

local crypto_aead_decrypt_sig = [[
int %s(unsigned char *m,
       unsigned long long *mlen_p,
       unsigned char *nsec,
       const unsigned char *c,
       unsigned long long clen,
       const unsigned char *ad,
       unsigned long long adlen,
       const unsigned char *npub,
       const unsigned char *k)
]]

local crypto_aead_encrypt_detached_sig = [[
int %s(unsigned char *c,
       unsigned char *mac,
       unsigned long long *maclen_p,
       const unsigned char *m,
       unsigned long long mlen,
       const unsigned char *ad,
       unsigned long long adlen,
       const unsigned char *nsec,
       const unsigned char *npub,
       const unsigned char *k)
]]

local crypto_aead_decrypt_detached_sig = [[
int %s(unsigned char *m,
       unsigned char *nsec,
       const unsigned char *c,
       unsigned long long clen,
       const unsigned char *mac,
       const unsigned char *ad,
       unsigned long long adlen,
       const unsigned char *npub,
       const unsigned char *k)
]]

local crypto_aead_keygen_sig = [[
void %s(unsigned char *k)
]]

local crypto_aead_beforenm_sig = [[
int %s(void *ctx_,
       const unsigned char *k)
]]

local crypto_aead_encrypt_afternm_sig = [[
int %s(unsigned char *c,
       unsigned long long *clen_p,
       const unsigned char *m,
       unsigned long long mlen,
       const unsigned char *ad,
       unsigned long long adlen,
       const unsigned char *nsec,
       const unsigned char *npub,
       const void *ctx_)
]]

local crypto_aead_decrypt_afternm_sig = [[
int %s(unsigned char *m,
       unsigned long long *mlen_p,
       unsigned char *nsec,
       const unsigned char *c,
       unsigned long long clen,
       const unsigned char *ad,
       unsigned long long adlen,
       const unsigned char *npub,
       const void *ctx_)
]]

local crypto_aead_encrypt_detached_afternm_sig = [[
int %s(unsigned char *c,
       unsigned char *mac,
       unsigned long long *maclen_p,
       const unsigned char *m,
       unsigned long long mlen,
       const unsigned char *ad,
       unsigned long long adlen,
       const unsigned char *nsec,
       const unsigned char *npub,
       const void *ctx_)
]]

local crypto_aead_decrypt_detached_afternm_sig = [[
int %s(unsigned char *m,
       unsigned char *nsec,
       const unsigned char *c,
       unsigned long long clen,
       const unsigned char *mac,
       const unsigned char *ad,
       unsigned long long adlen,
       const unsigned char *npub,
       const void *ctx_)
]]

local crypto_aead_statebytes_sig = [[
    size_t %s(void)
]]

local signatures = {
  ['crypto_aead_chacha20poly1305_keygen'] = crypto_aead_keygen_sig,
  ['crypto_aead_chacha20poly1305_encrypt'] = crypto_aead_encrypt_sig,
  ['crypto_aead_chacha20poly1305_decrypt'] = crypto_aead_decrypt_sig,
  ['crypto_aead_chacha20poly1305_encrypt_detached'] = crypto_aead_encrypt_detached_sig,
  ['crypto_aead_chacha20poly1305_decrypt_detached'] = crypto_aead_decrypt_detached_sig,

  ['crypto_aead_chacha20poly1305_ietf_keygen'] = crypto_aead_keygen_sig,
  ['crypto_aead_chacha20poly1305_ietf_encrypt'] = crypto_aead_encrypt_sig,
  ['crypto_aead_chacha20poly1305_ietf_decrypt'] = crypto_aead_decrypt_sig,
  ['crypto_aead_chacha20poly1305_ietf_encrypt_detached'] = crypto_aead_encrypt_detached_sig,
  ['crypto_aead_chacha20poly1305_ietf_decrypt_detached'] = crypto_aead_decrypt_detached_sig,

  ['crypto_aead_xchacha20poly1305_ietf_keygen'] = crypto_aead_keygen_sig,
  ['crypto_aead_xchacha20poly1305_ietf_encrypt'] = crypto_aead_encrypt_sig,
  ['crypto_aead_xchacha20poly1305_ietf_decrypt'] = crypto_aead_decrypt_sig,
  ['crypto_aead_xchacha20poly1305_ietf_encrypt_detached'] = crypto_aead_encrypt_detached_sig,
  ['crypto_aead_xchacha20poly1305_ietf_decrypt_detached'] = crypto_aead_decrypt_detached_sig,

  ['crypto_aead_aes256gcm_is_available'] = crypto_aead_is_available_sig,
  ['crypto_aead_aes256gcm_keygen'] = crypto_aead_keygen_sig,
  ['crypto_aead_aes256gcm_encrypt'] = crypto_aead_encrypt_sig,
  ['crypto_aead_aes256gcm_decrypt'] = crypto_aead_decrypt_sig,
  ['crypto_aead_aes256gcm_encrypt_detached'] = crypto_aead_encrypt_detached_sig,
  ['crypto_aead_aes256gcm_decrypt_detached'] = crypto_aead_decrypt_detached_sig,

  ['crypto_aead_aes256gcm_statebytes'] = crypto_aead_statebytes_sig,
  ['crypto_aead_aes256gcm_beforenm'] = crypto_aead_beforenm_sig,
  ['crypto_aead_aes256gcm_encrypt_afternm'] = crypto_aead_encrypt_afternm_sig,
  ['crypto_aead_aes256gcm_decrypt_afternm'] = crypto_aead_decrypt_afternm_sig,
  ['crypto_aead_aes256gcm_encrypt_detached_afternm'] = crypto_aead_encrypt_detached_afternm_sig,
  ['crypto_aead_aes256gcm_decrypt_detached_afternm'] = crypto_aead_decrypt_detached_afternm_sig,
}

return signatures
