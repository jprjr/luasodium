local crypto_secretbox_keygen_sig = [[
  void %s(unsigned char *k)
]]

local crypto_secretbox_sig = [[
  int %s(unsigned char *c,
         const unsigned char *m,
         unsigned long long mlen,
         const unsigned char *n,
         const unsigned char *k)
]]

local crypto_secretbox_open_sig = [[
  int %s(unsigned char *m,
         const unsigned char *c,
         unsigned long long clen,
         const unsigned char *n,
         const unsigned char *k)
]]

local crypto_secretbox_easy_sig = [[
  int %s(unsigned char *c,
         const unsigned char *m,
         unsigned long long mlen,
         const unsigned char *n,
         const unsigned char *k)
]]

local crypto_secretbox_open_easy_sig = [[
  int %s(unsigned char *m,
         const unsigned char *c,
         unsigned long long clen,
         const unsigned char *n,
         const unsigned char *k)
]]

local crypto_secretbox_detached_sig = [[
  int %s(unsigned char *c,
         unsigned char *mac,
         const unsigned char *m,
         unsigned long long mlen,
         const unsigned char *n,
         const unsigned char *k)
]]

local crypto_secretbox_open_detached_sig = [[
  int %s(unsigned char *m,
         const unsigned char *c,
         const unsigned char *mac,
         unsigned long long clen,
         const unsigned char *n,
         const unsigned char *k)
]]

local signatures = {
  ['crypto_secretbox_keygen'] = crypto_secretbox_keygen_sig,
  ['crypto_secretbox'] = crypto_secretbox_sig,
  ['crypto_secretbox_open'] = crypto_secretbox_open_sig,
  ['crypto_secretbox_easy'] = crypto_secretbox_easy_sig,
  ['crypto_secretbox_open_easy'] = crypto_secretbox_open_easy_sig,
  ['crypto_secretbox_detached'] = crypto_secretbox_detached_sig,
  ['crypto_secretbox_open_detached'] = crypto_secretbox_open_detached_sig,

  ['crypto_secretbox_xsalsa20poly1305_keygen'] = crypto_secretbox_keygen_sig,
  ['crypto_secretbox_xsalsa20poly1305'] = crypto_secretbox_sig,
  ['crypto_secretbox_xsalsa20poly1305_open'] = crypto_secretbox_open_sig,
}

return signatures
