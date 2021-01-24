local crypto_pwhash_sig = [[
int %s(
  unsigned char * const,
  unsigned long long,
  const char * const,
  unsigned long long,
  const unsigned char * const,
  unsigned long long,
  size_t,
  int)
]]

local crypto_pwhash_str_sig = [[
int %s(
  char *,
  const char * const,
  unsigned long long,
  unsigned long long,
  size_t)
]]

local crypto_pwhash_str_verify_sig = [[
int %s(
  const char *,
  const char * const,
  unsigned long long)
]]

local crypto_pwhash_str_needs_rehash_sig = [[
int %s(
  const char *,
  unsigned long long,
  size_t)
]]

local signatures = {
  ['crypto_pwhash'] = crypto_pwhash_sig,
  ['crypto_pwhash_str'] = crypto_pwhash_str_sig,
  ['crypto_pwhash_str_verify'] = crypto_pwhash_str_verify_sig,
  ['crypto_pwhash_str_needs_rehash'] = crypto_pwhash_str_needs_rehash_sig,
  ['crypto_pwhash_argon2i'] = crypto_pwhash_sig,
  ['crypto_pwhash_argon2i_str'] = crypto_pwhash_str_sig,
  ['crypto_pwhash_argon2i_str_verify'] = crypto_pwhash_str_verify_sig,
  ['crypto_pwhash_argon2i_str_needs_rehash'] = crypto_pwhash_str_needs_rehash_sig,
  ['crypto_pwhash_argon2id'] = crypto_pwhash_sig,
  ['crypto_pwhash_argon2id_str'] = crypto_pwhash_str_sig,
  ['crypto_pwhash_argon2id_str_verify'] = crypto_pwhash_str_verify_sig,
  ['crypto_pwhash_argon2id_str_needs_rehash'] = crypto_pwhash_str_needs_rehash_sig,
}

return signatures
