local crypto_box_keypair_sig = [[
  int %s(unsigned char *pk, unsigned char *sk)
]]

local crypto_box_seed_keypair_sig = [[
  int %s(unsigned char *pk, unsigned char *sk,
         const unsigned char *seed)
]]

local crypto_box_sig = [[
  int %s(unsigned char *c, const unsigned char *m,
         unsigned long long mlen, const unsigned char *n,
         const unsigned char *pk, const unsigned char *sk)
]]

local crypto_box_open_sig = [[
  int %s(unsigned char *m, const unsigned char *c,
         unsigned long long clen, const unsigned char *n,
         const unsigned char *pk, const unsigned char *sk)
]]

local crypto_box_beforenm_sig = [[
  int %s(unsigned char *k, const unsigned char *pk,
         const unsigned char *sk)
]]

local crypto_box_afternm_sig = [[
  int %s(unsigned char *c, const unsigned char *m,
         unsigned long long mlen, const unsigned char *n,
         const unsigned char *k)
]]

local crypto_box_open_afternm_sig = [[
  int %s(unsigned char *m, const unsigned char *c,
         unsigned long long clen, const unsigned char *n,
         const unsigned char *p)
]]

local crypto_box_easy_sig = [[
  int %s(unsigned char *c, const unsigned char *m,
         unsigned long long mlen, const unsigned char *n,
         const unsigned char *pk, const unsigned char *sk)
]]

local crypto_box_open_easy_sig = [[
  int %s(unsigned char *m, const unsigned char *c,
         unsigned long long clen, const unsigned char *n,
         const unsigned char *pk, const unsigned char *sk)
]]

local crypto_box_detached_sig = [[
  int %s(unsigned char *c, unsigned char *mac,
         const unsigned char *m,
         unsigned long long mlen,
         const unsigned char *n,
         const unsigned char *pk,
         const unsigned char *sk)
]]

local crypto_box_open_detached_sig = [[
  int %s(unsigned char *m,
         const unsigned char *c,
         const unsigned char *mac,
         unsigned long long clen,
         const unsigned char *n,
         const unsigned char *pk,
         const unsigned char *sk)
]]

local crypto_box_easy_afternm_sig = [[
  int %s(unsigned char *c, const unsigned char *m,
         unsigned long long mlen, const unsigned char *n,
         const unsigned char *k)
]]

local crypto_box_open_easy_afternm_sig = [[
  int %s(unsigned char *m, const unsigned char *c,
         unsigned long long clen, const unsigned char *n,
         const unsigned char *k)
]]

local crypto_box_detached_afternm_sig = [[
  int %s(unsigned char *c, unsigned char *mac,
         const unsigned char *m, unsigned long long mlen,
         const unsigned char *n, const unsigned char *k)
]]

local crypto_box_open_detached_afternm_sig = [[
  int %s(unsigned char *m, const unsigned char *c,
         const unsigned char *mac,
         unsigned long long clen, const unsigned char *n,
         const unsigned char *k)
]]

local crypto_box_seal_sig = [[
  int %s(unsigned char* c, const unsigned char* m,
        unsigned long long mlen,
        const unsigned char* pk)
]]

local crypto_box_seal_open_sig = [[
  int %s(unsigned char* m, const unsigned char* c,
        unsigned long long clen,
        const unsigned char* pk,
        const unsigned char* sk)
]]

local signatures = {
  ['crypto_box'] = crypto_box_sig,
  ['crypto_box_open'] = crypto_box_open_sig,
  ['crypto_box_beforenm'] = crypto_box_beforenm_sig,
  ['crypto_box_afternm'] = crypto_box_afternm_sig,
  ['crypto_box_open_afternm'] = crypto_box_open_afternm_sig,
  ['crypto_box_curve25519xsalsa20poly1305'] = crypto_box_sig,
  ['crypto_box_curve25519xsalsa20poly1305_open'] = crypto_box_open_sig,
  ['crypto_box_curve25519xsalsa20poly1305_beforenm'] = crypto_box_beforenm_sig,
  ['crypto_box_curve25519xsalsa20poly1305_afternm'] = crypto_box_afternm_sig,
  ['crypto_box_curve25519xsalsa20poly1305_open_afternm'] = crypto_box_open_afternm_sig,

  ['crypto_box_keypair'] = crypto_box_keypair_sig,
  ['crypto_box_curve25519xsalsa20poly1305_keypair'] = crypto_box_keypair_sig,
  ['crypto_box_curve25519xchacha20poly1305_keypair'] = crypto_box_keypair_sig,

  ['crypto_box_seed_keypair'] = crypto_box_seed_keypair_sig,
  ['crypto_box_curve25519xsalsa20poly1305_seed_keypair'] = crypto_box_seed_keypair_sig,
  ['crypto_box_curve25519xchacha20poly1305_seed_keypair'] = crypto_box_seed_keypair_sig,

  ['crypto_box_easy'] = crypto_box_easy_sig,
  ['crypto_box_open_easy'] = crypto_box_open_easy_sig,
  ['crypto_box_detached'] = crypto_box_detached_sig,
  ['crypto_box_open_detached'] = crypto_box_open_detached_sig,
  ['crypto_box_easy_afternm'] = crypto_box_easy_afternm_sig,
  ['crypto_box_open_easy_afternm'] = crypto_box_open_easy_afternm_sig,
  ['crypto_box_detached_afternm'] = crypto_box_detached_afternm_sig,
  ['crypto_box_open_detached_afternm'] = crypto_box_open_detached_afternm_sig,

  ['crypto_box_curve25519xchacha20poly1305_easy'] = crypto_box_easy_sig,
  ['crypto_box_curve25519xchacha20poly1305_open_easy'] = crypto_box_open_easy_sig,
  ['crypto_box_curve25519xchacha20poly1305_detached'] = crypto_box_detached_sig,
  ['crypto_box_curve25519xchacha20poly1305_open_detached'] = crypto_box_open_detached_sig,
  ['crypto_box_curve25519xchacha20poly1305_beforenm'] = crypto_box_beforenm_sig,
  ['crypto_box_curve25519xchacha20poly1305_easy_afternm'] = crypto_box_easy_afternm_sig,
  ['crypto_box_curve25519xchacha20poly1305_open_easy_afternm'] = crypto_box_open_easy_afternm_sig,
  ['crypto_box_curve25519xchacha20poly1305_detached_afternm'] = crypto_box_detached_afternm_sig,
  ['crypto_box_curve25519xchacha20poly1305_open_detached_afternm'] = crypto_box_open_detached_afternm_sig,

  ['crypto_box_seal'] = crypto_box_seal_sig,
  ['crypto_box_seal_open'] = crypto_box_seal_open_sig,

  ['crypto_box_curve25519xchacha20poly1305_seal'] = crypto_box_seal_sig,
  ['crypto_box_curve25519xchacha20poly1305_seal_open'] = crypto_box_seal_open_sig,
}

return signatures
