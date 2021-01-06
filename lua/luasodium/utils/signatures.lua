local signatures = {
  ['sodium_memcmp'] = [[
    int %s(const void * const, const void * const, size_t)
  ]],

  ['sodium_bin2hex'] = [[
    char *%s(char * const, const size_t,
             const unsigned char * const, const size_t)
  ]],

  ['sodium_hex2bin'] = [[
    int %s(unsigned char * const, const size_t,
            const char * const, const size_t,
            const char * const, size_t * const,
            const char ** const)
  ]],

  ['sodium_bin2base64'] = [[
    char *%s(char * const, const size_t,
               const unsigned char * const, const size_t,
               const int variant)
  ]],

  ['sodium_base642bin'] = [[
    int %s(unsigned char * const, const size_t,
            const char * const, const size_t,
            const char * const, size_t * const,
            const char ** const, const int)
  ]],

  ['sodium_increment'] = [[
    void %s(unsigned char *, const size_t)
  ]],

  ['sodium_add'] = [[
    void %s(unsigned char *, const unsigned char *, const size_t)
  ]],

  ['sodium_sub'] = [[
    void %s(unsigned char *, const unsigned char *, const size_t)
  ]],

  ['sodium_compare'] = [[
    int %s(const void * const, const void * const, size_t)
  ]],

  ['sodium_is_zero'] = [[
    int %s(const unsigned char *, const size_t)
  ]],

  ['sodium_pad'] = [[
    int %s(size_t *, unsigned char *,
            size_t, size_t, size_t)
  ]],

  ['sodium_unpad'] = [[
    int %s(size_t *, const unsigned char *, size_t, size_t)
  ]],

  ['sodium_base64_encoded_len'] = [[
    size_t %s(size_t bin_len, int variant)
  ]],
}

return signatures
