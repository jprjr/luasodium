local signatures = {
  ['crypto_stream'] = [[
    int (%s)(unsigned char *c, unsigned long long clen,
             const unsigned char *n, const unsigned char *k)
  ]],
  ['crypto_stream_xor'] = [[
    int (%s)(unsigned char *c, const unsigned char *m,
             unsigned long long mlen,
             const unsigned char *n, const unsigned char *k)
  ]],
  ['crypto_stream_keygen'] = [[
    void (%s)(unsigned char *k)
  ]],
}

return signatures
