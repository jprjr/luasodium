local crypto_secretstream_keygen_sig = [[
  void %s(unsigned char *)
]]

local crypto_secretstream_init_push_sig = [[
  int %s(
  void *,
  unsigned char *,
  const unsigned char *)
]]

local crypto_secretstream_push_sig = [[
  int %s(
  void *state,
  unsigned char *,
  unsigned long long *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  unsigned long long,
  unsigned char)
]]

local crypto_secretstream_init_pull_sig = [[
  int %s(
  void *state,
  const unsigned char *,
  const unsigned char *)
]]

local crypto_secretstream_pull_sig = [[
  int %s(
  void *state,
  unsigned char *,
  unsigned long long *,
  unsigned char *,
  const unsigned char *,
  unsigned long long,
  const unsigned char *,
  unsigned long long)
]]

local crypto_secretstream_rekey_sig = [[
  void %s(void)
]]

local crypto_secretstream_size_sig = [[
  size_t %s(void)
]]

local crypto_secretstream_char_sig = [[
  unsigned char %s(void)
]]

local signatures = {
  ['crypto_secretstream_xchacha20poly1305_keygen'] = crypto_secretstream_keygen_sig,
  ['crypto_secretstream_xchacha20poly1305_init_push'] = crypto_secretstream_init_push_sig,
  ['crypto_secretstream_xchacha20poly1305_push'] = crypto_secretstream_push_sig,
  ['crypto_secretstream_xchacha20poly1305_init_pull'] = crypto_secretstream_init_pull_sig,
  ['crypto_secretstream_xchacha20poly1305_pull'] = crypto_secretstream_pull_sig,
  ['crypto_secretstream_xchacha20poly1305_rekey'] = crypto_secretstream_rekey_sig,
  ['crypto_secretstream_xchacha20poly1305_tag_message'] = crypto_secretstream_char_sig,
  ['crypto_secretstream_xchacha20poly1305_tag_push'] = crypto_secretstream_char_sig,
  ['crypto_secretstream_xchacha20poly1305_tag_rekey'] = crypto_secretstream_char_sig,
  ['crypto_secretstream_xchacha20poly1305_tag_final'] = crypto_secretstream_char_sig,
  ['crypto_secretstream_xchacha20poly1305_statebytes'] = crypto_secretstream_size_sig,
}

return signatures
