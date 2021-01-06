local signatures = {
  ['sodium_init'] = [[
    int %s(void)
  ]],
  ['sodium_memzero'] = [[
    void %s(void * const pnt, const size_t len)
  ]],
  ['randombytes_random'] = [[
    uint32_t %s(void)
  ]],
  ['randombytes_uniform'] = [[
    uint32_t %s(const uint32_t upper_bound)
  ]],
  ['randombytes_buf'] = [[
    void %s(void * const buf, const size_t size)
  ]],
  ['randombytes_buf_deterministic'] = [[
    void %s(void * const buf, const size_t size,
            const unsigned char *seed)
  ]],
  ['randombytes_close'] = [[
    int %s(void)
  ]],
  ['randombytes_stir'] = [[
    void %s(void)
  ]],
}

return signatures
