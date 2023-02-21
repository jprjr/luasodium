return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string

  local char_array = ffi.typeof('char[?]')

  local sodium_lib = libs.sodium

  local function ls_crypto_secretbox_keygen(basename)
    local crypto_secretbox_keygen = string_format('%s_keygen',basename)
    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]

    return {
      [crypto_secretbox_keygen] = function()
        local k = char_array(KEYBYTES)
        sodium_lib.crypto_secretbox_keygen(k)
        local k_str = ffi_string(k,KEYBYTES)
        sodium_lib.sodium_memzero(k,KEYBYTES)
        return k_str
      end,
    }
  end

  local function ls_crypto_secretbox(basename)
    local crypto_secretbox = string_format('%s',basename)
    local crypto_secretbox_open = string_format('%s_open',basename)
    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]
    local MACBYTES = constants[string_format('%s_MACBYTES',basename)]
    local NONCEBYTES = constants[string_format('%s_NONCEBYTES',basename)]
    local ZEROBYTES = constants[string_format('%s_ZEROBYTES',basename)]
    local BOXZEROBYTES = constants[string_format('%s_BOXZEROBYTES',basename)]

    return {
      [crypto_secretbox] = function(m,nonce,key)
        if not key then
          return error('requires 3 arguments')
        end

        local mlen = string_len(m)
        local clen = mlen + MACBYTES

        if string_len(nonce) ~= NONCEBYTES then
          return error(string_format('wrong nonce size, expected: %d',
            NONCEBYTES))
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format('wrong key size, expected: %d',
            KEYBYTES))
        end

        local tmp_m = char_array(mlen + ZEROBYTES)
        ffi.fill(tmp_m,ZEROBYTES,0)
        ffi.copy(tmp_m+ZEROBYTES,m,mlen)

        local c = char_array(clen + BOXZEROBYTES)
        ffi.fill(c,BOXZEROBYTES,0)

        if tonumber(sodium_lib[crypto_secretbox](
          c,tmp_m,mlen+ZEROBYTES,
          nonce,key)) == -1  then
          return nil, string_format('%s error',crypto_secretbox)
        end
        local c_str = ffi_string(c+BOXZEROBYTES,clen)
        sodium_lib.sodium_memzero(tmp_m,mlen + ZEROBYTES)
        sodium_lib.sodium_memzero(c,clen + BOXZEROBYTES)
        return c_str
      end,

      [crypto_secretbox_open] = function(c,nonce,key)
        if not key then
          return error('requires 3 arguments')
        end

        local clen = string_len(c)

        if clen < MACBYTES then
          return error(string_format('wrong c size, expected at least: %d',
            MACBYTES))
        end

        if string_len(nonce) ~= NONCEBYTES then
          return error(string_format('wrong nonce size, expected: %d',
            NONCEBYTES))
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format('wrong key size, expected: %d',
            KEYBYTES))
        end

        local mlen = clen - MACBYTES

        local tmp_c = char_array(clen + BOXZEROBYTES)
        ffi.fill(tmp_c,BOXZEROBYTES,0)
        ffi.copy(tmp_c+BOXZEROBYTES,c,clen)

        local m = char_array(mlen + ZEROBYTES)
        ffi.fill(m,ZEROBYTES,0)

        if tonumber(sodium_lib[crypto_secretbox_open](
          m,tmp_c,clen+BOXZEROBYTES,
          nonce,key)) == -1  then
          return nil, string_format('%s error',crypto_secretbox_open)
        end

        local m_str = ffi_string(m+ZEROBYTES,mlen)
        sodium_lib.sodium_memzero(tmp_c,clen + BOXZEROBYTES)
        sodium_lib.sodium_memzero(m,mlen + ZEROBYTES)
        return m_str

      end,
    }
  end

  local function ls_crypto_secretbox_easy(basename)
    local crypto_secretbox_easy = string_format('%s_easy',basename)
    local crypto_secretbox_open_easy = string_format('%s_open_easy',basename)
    local crypto_secretbox_detached = string_format('%s_detached',basename)
    local crypto_secretbox_open_detached = string_format('%s_open_detached',basename)
    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]
    local MACBYTES = constants[string_format('%s_MACBYTES',basename)]
    local NONCEBYTES = constants[string_format('%s_NONCEBYTES',basename)]

    return {
      [crypto_secretbox_easy] = function(m, nonce, key)
        if not key then
          return error('requires 3 arguments')
        end

        local mlen = string_len(m)
        local clen = mlen + MACBYTES

        if string_len(nonce) ~= NONCEBYTES then
          return error(string_format('wrong nonce size, expected: %d',
            NONCEBYTES))
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format('wrong key size, expected: %d',
            KEYBYTES))
        end

        local c = char_array(clen)

        if tonumber(sodium_lib[crypto_secretbox_easy](
          c,m,mlen,
          nonce,key)) == -1  then
          return nil, string_format('%s error',crypto_secretbox_easy)
        end

        local c_str = ffi_string(c,clen)
        sodium_lib.sodium_memzero(c,clen)
        return c_str
      end,

      [crypto_secretbox_open_easy] = function(c, nonce, key)
        if not key then
          return error('requires 3 arguments')
        end

        local clen = string_len(c)

        if clen < MACBYTES then
          return error(string_format('wrong c size, expected at least: %d',
            MACBYTES))
        end

        if string_len(nonce) ~= NONCEBYTES then
          return error(string_format('wrong nonce size, expected: %d',
            NONCEBYTES))
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format('wrong key size, expected: %d',
            KEYBYTES))
        end

        local mlen = clen - MACBYTES
        local m = char_array(mlen)

        if tonumber(sodium_lib[crypto_secretbox_open_easy](
          m,c,clen,
          nonce,key)) == -1  then
          return nil, string_format('%s error',crypto_secretbox_open_easy)
        end

        local m_str = ffi_string(m,mlen)
        sodium_lib.sodium_memzero(m,mlen)
        return m_str
      end,

      [crypto_secretbox_detached] = function(message, nonce, key)
        if not key then
          return error('requires 3 arguments')
        end

        local mlen = string_len(message)

        if string_len(nonce) ~= NONCEBYTES then
          return error(string_format('wrong nonce size, expected: %d',
            NONCEBYTES))
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format('wrong key size, expected: %d',
            KEYBYTES))
        end

        local c = char_array(mlen)
        local mac = char_array(MACBYTES)

        if tonumber(sodium_lib[crypto_secretbox_detached](
          c,mac,message,mlen,
          nonce,key)) == -1  then
          return nil, string_format('%s error',crypto_secretbox_detached)
        end
        local c_str = ffi_string(c,mlen)
        local mac_str = ffi_string(mac,MACBYTES)
        sodium_lib.sodium_memzero(c,mlen)
        sodium_lib.sodium_memzero(mac,MACBYTES)
        return c_str, mac_str
      end,

      [crypto_secretbox_open_detached] = function(cipher, mac, nonce, key)
        if not key then
          return error('requires 4 arguments')
        end

        local clen = string_len(cipher)

        if string_len(mac) ~= MACBYTES then
          return error(string_format('wrong mac size, expected: %d',
            MACBYTES))
        end

        if string_len(nonce) ~= NONCEBYTES then
          return error(string_format('wrong nonce size, expected: %d',
            NONCEBYTES))
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format('wrong key size, expected: %d',
            NONCEBYTES))
        end

        local m = char_array(clen)
        if tonumber(sodium_lib[crypto_secretbox_open_detached](
          m,cipher,mac,clen,
          nonce,key)) == -1  then
          return nil, string_format('%s error',crypto_secretbox_open_detached)
        end

        local m_str = ffi_string(m,clen)
        sodium_lib.sodium_memzero(m,clen)
        return m_str
      end,
    }
  end

  if tonumber(sodium_lib.sodium_init()) == -1 then
    return error('sodium_init error')
  end

  local M = {}

  for _,basename in ipairs({
    'crypto_secretbox',
    'crypto_secretbox_xsalsa20poly1305'
  }) do
    local m = ls_crypto_secretbox(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for _,basename in ipairs({
    'crypto_secretbox',
    'crypto_secretbox_xsalsa20poly1305'
  }) do
    local m = ls_crypto_secretbox_keygen(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for _,basename in ipairs({
    'crypto_secretbox',
  }) do
    local m = ls_crypto_secretbox_easy(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end
