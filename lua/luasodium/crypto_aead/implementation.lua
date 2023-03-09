return function(libs, constants)

  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium
  local clib = libs.C

  local char_array = ffi.typeof('char[?]')

  -- returns the "is_available" function
  local function ls_crypto_aead_is_available(basename)
    local crypto_aead_is_available = string_format('%s_is_available',basename)

    return {
      [crypto_aead_is_available] = function()
        return tonumber(sodium_lib[crypto_aead_is_available]()) == 1
      end
    }
  end

  -- returns all the common crypto_aead functions (keygen, encrypt, decrypt, encrypt_detached, decrypt_detached)
  local function ls_crypto_aead(basename)
    local crypto_aead_keygen = string_format('%s_keygen',basename)
    local crypto_aead_encrypt = string_format('%s_encrypt',basename)
    local crypto_aead_decrypt = string_format('%s_decrypt',basename)
    local crypto_aead_encrypt_detached = string_format('%s_encrypt_detached',basename)
    local crypto_aead_decrypt_detached = string_format('%s_decrypt_detached',basename)

    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]
    local NPUBBYTES = constants[string_format('%s_NPUBBYTES',basename)]
    local ABYTES = constants[string_format('%s_ABYTES',basename)]

    return {
      [crypto_aead_keygen] = function()
        local k = char_array(KEYBYTES)
        sodium_lib[crypto_aead_keygen](k)

        local k_str = ffi_string(k,KEYBYTES)
        sodium_lib.sodium_memzero(k,KEYBYTES)
        return k_str
      end,

      [crypto_aead_encrypt] = function(k, m, npub, ad)
        if not npub then
          return error('requires 3 arguments')
        end

        if string_len(k) ~= KEYBYTES then
          return error(string_format('wrong key length, expected: %d',KEYBYTES))
        end

        if string_len(npub) ~= NPUBBYTES then
          return error(string_format('wrong nonce length, expected: %d',NPUBBYTES))
        end

        local mlen = string_len(m)
        local adlen = 0
        if ad then
          adlen = string_len(ad)
        end
        local clen = ffi.new('size_t[1]')
        local c = char_array(mlen + ABYTES)
        sodium_lib[crypto_aead_encrypt](c,clen,
          m,mlen,ad,adlen,nil,npub,k)

        local c_str = ffi_string(c,clen[0])
        sodium_lib.sodium_memzero(c,mlen + ABYTES)
        return c_str
      end,

      [crypto_aead_decrypt] = function(k, c, npub, ad)
        if not npub then
          return error('requires 3 arguments')
        end

        if string_len(k) ~= KEYBYTES then
          return error(string_format('wrong key length, expected: %d',KEYBYTES))
        end

        local clen = string_len(c)

        if clen < ABYTES then
          return error(string_format('wrong cipher length, expected at least: %d',ABYTES))
        end

        if string_len(npub) ~= NPUBBYTES then
          return error(string_format('wrong nonce length, expected: %d',NPUBBYTES))
        end

        local adlen = 0
        if ad then
          adlen = string_len(ad)
        end

        local mlen = ffi.new('size_t[1]')
        local m = char_array(clen - ABYTES)

        if tonumber(sodium_lib[crypto_aead_decrypt](m,mlen,
          nil,c,clen,ad,adlen,npub,k)) == -1 then
          return nil, string_format('%s error',crypto_aead_decrypt)
        end

        local m_str = ffi_string(m,mlen[0])
        sodium_lib.sodium_memzero(m,clen - ABYTES)
        return m_str
      end,

      [crypto_aead_encrypt_detached] = function(k, m, npub, ad)
        if not npub then
          return error('requires 3 arguments')
        end

        if string_len(k) ~= KEYBYTES then
          return error(string_format('wrong key length, expected: %d',KEYBYTES))
        end

        if string_len(npub) ~= NPUBBYTES then
          return error(string_format('wrong nonce length, expected: %d',NPUBBYTES))
        end

        local mlen = string_len(m)
        local adlen = 0
        if ad then
          adlen = string_len(ad)
        end
        local maclen = ffi.new('size_t[1]')
        local c = char_array(mlen)
        local mac = char_array(ABYTES)
        sodium_lib[crypto_aead_encrypt_detached](c,mac,maclen,
          m,mlen,ad,adlen,nil,npub,k)

        local c_str = ffi_string(c,mlen)
        local mac_str = ffi_string(mac,maclen[0])
        sodium_lib.sodium_memzero(c,mlen)
        sodium_lib.sodium_memzero(mac,ABYTES)
        return c_str, mac_str
      end,

      [crypto_aead_decrypt_detached] = function(k, c, mac, npub, ad)
        if not npub then
          return error('requires 4 arguments')
        end

        if string_len(k) ~= KEYBYTES then
          return error(string_format('wrong key length, expected: %d',KEYBYTES))
        end

        if string_len(mac) ~= ABYTES then
          return error(string_format('wrong mac length, expected: %d',ABYTES))
        end

        if string_len(npub) ~= NPUBBYTES then
          return error(string_format('wrong nonce length, expected: %d',NPUBBYTES))
        end

        local adlen = 0
        if ad then
          adlen = string_len(ad)
        end

        local clen = string_len(c)
        local m = char_array(clen)

        if tonumber(sodium_lib[crypto_aead_decrypt_detached](m,nil,
          c,clen,mac,ad,adlen,npub,k)) == -1 then
          return nil, string_format('%s error',crypto_aead_decrypt_detached)
        end

        local m_str = ffi_string(m,clen)
        sodium_lib.sodium_memzero(m,clen)
        return m_str
      end,
    }
  end

  -- handles creating the precomputation functions
  local function ls_crypto_aead_precomp(basename)
    local crypto_aead_beforenm = string_format('%s_beforenm',basename)
    local crypto_aead_encrypt_afternm = string_format('%s_encrypt_afternm',basename)
    local crypto_aead_decrypt_afternm = string_format('%s_decrypt_afternm',basename)
    local crypto_aead_encrypt_detached_afternm = string_format('%s_encrypt_detached_afternm',basename)
    local crypto_aead_decrypt_detached_afternm = string_format('%s_decrypt_detached_afternm',basename)

    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]
    local NPUBBYTES = constants[string_format('%s_NPUBBYTES',basename)]
    local ABYTES = constants[string_format('%s_ABYTES',basename)]
    local STATEBYTES = tonumber(sodium_lib[string_format('%s_statebytes',basename)]())

    local ls_crypto_aead_beforenm__gc = function(state)
      sodium_lib.sodium_memzero(state,STATEBYTES)
      clib.free(state)
    end

    local ls_crypto_aead_methods = {}
    local ls_crypto_aead_mt = {
      __index = ls_crypto_aead_methods
    }

    local M = {
      [crypto_aead_beforenm] = function(k)
        if string_len(k) ~= KEYBYTES then
          return error(string_format('wrong key size, expected: %d',KEYBYTES))
        end

        -- the pre-computation interface requires a 16-byte alignment, see
        -- https://doc.libsodium.org/secret-key_cryptography/aead/aes-256-gcm/aes-gcm_with_precomputation
        --
        -- an example for ensuring alignment with standard malloc is here:
        -- https://stackoverflow.com/questions/227897/how-to-allocate-aligned-memory-only-using-the-standard-library
        --
        -- Internally luajit's bitwise ops use a 32-bit signed type, so doing the
        -- addition + masking in the linked answer may not work.
        --
        -- We'll do the equivalent with standard math ops
        local state_unaligned = ffi.gc(clib.malloc(STATEBYTES+15),ls_crypto_aead_beforenm__gc)
        local state_uintptr = ffi.cast("uintptr_t",state_unaligned)
        state_uintptr = state_uintptr + 15
        state_uintptr = state_uintptr - (state_uintptr % 16)
        local state = ffi.cast("void *", state_uintptr)
        sodium_lib[crypto_aead_beforenm](state,k)

        local ls_state = setmetatable({
          state = state,
          state_unaligned = state_unaligned,
        }, ls_crypto_aead_mt)

        return ls_state
      end,

      [crypto_aead_encrypt_afternm] = function(ls_state, m, npub, ad)
        if not npub then
          return error('requires 3 arguments')
        end

        if getmetatable(ls_state) ~= ls_crypto_aead_mt then
          return error('invalid userdata')
        end

        if string_len(npub) ~= NPUBBYTES then
          return error(string_format('wrong nonce length, expected: %d',NPUBBYTES))
        end

        local mlen = string_len(m)
        local adlen = 0
        if ad then
          adlen = string_len(ad)
        end
        local clen = ffi.new('size_t[1]')
        local c = char_array(mlen + ABYTES)
        sodium_lib[crypto_aead_encrypt_afternm](c,clen,
          m,mlen,ad,adlen,nil,npub,ls_state.state)

        local c_str = ffi_string(c,clen[0])
        sodium_lib.sodium_memzero(c,mlen + ABYTES)
        return c_str
      end,

      [crypto_aead_decrypt_afternm] = function(ls_state, c, npub, ad)
        if not npub then
          return error('requires 3 arguments')
        end

        if getmetatable(ls_state) ~= ls_crypto_aead_mt then
          return error('invalid userdata')
        end

        local clen = string_len(c)
        if clen < ABYTES then
          return error(string_format('wrong cipher length, expected at least: %d',ABYTES))
        end

        if string_len(npub) ~= NPUBBYTES then
          return error(string_format('wrong nonce length, expected: %d',NPUBBYTES))
        end

        local adlen = 0
        if ad then
          adlen = string_len(ad)
        end

        local mlen = ffi.new('size_t[1]')
        local m = char_array(clen - ABYTES)

        if tonumber(sodium_lib[crypto_aead_decrypt_afternm](m,mlen,
          nil,c,clen,ad,adlen,npub,ls_state.state)) == -1 then
          return nil, string_format('%s error',crypto_aead_decrypt_afternm)
        end

        local m_str = ffi_string(m,mlen[0])
        sodium_lib.sodium_memzero(m,clen - ABYTES)
        return m_str
      end,

      [crypto_aead_encrypt_detached_afternm] = function(ls_state, m, npub, ad)
        if not npub then
          return error('requires 3 arguments')
        end

        if getmetatable(ls_state) ~= ls_crypto_aead_mt then
          return error('invalid userdata')
        end

        if string_len(npub) ~= NPUBBYTES then
          return error(string_format('wrong nonce length, expected: %d',NPUBBYTES))
        end

        local mlen = string_len(m)
        local adlen = 0
        if ad then
          adlen = string_len(ad)
        end
        local maclen = ffi.new('size_t[1]')
        local c = char_array(mlen)
        local mac = char_array(ABYTES)
        sodium_lib[crypto_aead_encrypt_detached_afternm](c,mac,maclen,
          m,mlen,ad,adlen,nil,npub,ls_state.state)

        local c_str = ffi_string(c,mlen)
        local mac_str = ffi_string(mac,maclen[0])
        sodium_lib.sodium_memzero(c,mlen)
        sodium_lib.sodium_memzero(mac,ABYTES)
        return c_str, mac_str
      end,

      [crypto_aead_decrypt_detached_afternm] = function(ls_state, c, mac, npub, ad)
        if not npub then
          return error('requires 4 arguments')
        end

        if getmetatable(ls_state) ~= ls_crypto_aead_mt then
          return error('invalid userdata')
        end

        if string_len(mac) ~= ABYTES then
          return error(string_format('wrong mac length, expected: %d',ABYTES))
        end

        if string_len(npub) ~= NPUBBYTES then
          return error(string_format('wrong nonce length, expected: %d',NPUBBYTES))
        end

        local adlen = 0
        if ad then
          adlen = string_len(ad)
        end

        local clen = string_len(c)
        local m = char_array(clen)

        if tonumber(sodium_lib[crypto_aead_decrypt_detached_afternm](m,nil,
          c,clen,mac,ad,adlen,npub,ls_state.state)) == -1 then
          return nil, string_format('%s error',crypto_aead_decrypt_detached_afternm)
        end

        local m_str = ffi_string(m,clen)
        sodium_lib.sodium_memzero(m,clen)
        return m_str
      end,
    }

    ls_crypto_aead_methods.beforenm = M[crypto_aead_beforenm]
    ls_crypto_aead_methods.encrypt = M[crypto_aead_encrypt_afternm]
    ls_crypto_aead_methods.decrypt = M[crypto_aead_decrypt_afternm]
    ls_crypto_aead_methods.encrypt_detached = M[crypto_aead_encrypt_detached_afternm]
    ls_crypto_aead_methods.decrypt_detached = M[crypto_aead_decrypt_detached_afternm]

    return M
  end


  if tonumber(sodium_lib.sodium_init()) == -1 then
    return error('sodium_init error')
  end

  local M = {}

  -- handle base crypto_aead functions
  for _,basename in ipairs({
    'crypto_aead_chacha20poly1305',
    'crypto_aead_chacha20poly1305_ietf',
    'crypto_aead_xchacha20poly1305_ietf',
    'crypto_aead_aes256gcm',
  }) do
    local m = ls_crypto_aead(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  -- handle crypto_aead_is_available functions
  for _,basename in ipairs({
    'crypto_aead_aes256gcm',
  }) do
    local m = ls_crypto_aead_is_available(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for _,basename in ipairs({
    'crypto_aead_aes256gcm',
  }) do
    local m = ls_crypto_aead_precomp(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M

end
