return function(libs, constants)

  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local sodium_lib = libs.sodium

  local char_array = ffi.typeof('char[?]')

  -- returns crypto_box functions
  local function ls_crypto_box(basename)
    local crypto_box_keypair = string_format('%s_keypair',basename)
    local crypto_box = string_format('%s',basename)
    local crypto_box_open = string_format('%s_open',basename)
    local crypto_box_beforenm = string_format('%s_beforenm',basename)
    local crypto_box_afternm = string_format('%s_afternm',basename)
    local crypto_box_open_afternm = string_format('%s_open_afternm',basename)

    local PUBLICKEYBYTES = constants[string_format('%s_PUBLICKEYBYTES',basename)]
    local SECRETKEYBYTES = constants[string_format('%s_SECRETKEYBYTES',basename)]
    local MACBYTES = constants[string_format('%s_MACBYTES',basename)]
    local NONCEBYTES = constants[string_format('%s_NONCEBYTES',basename)]
    local BEFORENMBYTES = constants[string_format('%s_BEFORENMBYTES',basename)]
    local BOXZEROBYTES = constants[string_format('%s_BOXZEROBYTES',basename)]
    local ZEROBYTES = constants[string_format('%s_ZEROBYTES',basename)]

    return {
      [crypto_box_keypair] = function()
        local pk = char_array(PUBLICKEYBYTES)
        local sk = char_array(SECRETKEYBYTES)
        if tonumber(sodium_lib[crypto_box_keypair](pk,sk)) == -1 then
          return nil, string_format('%s error',crypto_box_keypair)
        end

        local pk_str = ffi_string(pk,PUBLICKEYBYTES)
        local sk_str = ffi_string(sk,SECRETKEYBYTES)

        sodium_lib.sodium_memzero(pk,PUBLICKEYBYTES)
        sodium_lib.sodium_memzero(sk,SECRETKEYBYTES)
        return pk_str, sk_str
      end,

      [crypto_box] = function(m, nonce, pk, sk)
        if not sk then
          return error('requires 4 arguments')
        end

        local mlen = string_len(m)
        local clen = mlen + MACBYTES

        if string_len(nonce) ~= NONCEBYTES then
          return error(string_format('wrong nonce size, expected: %d',
            NONCEBYTES))
        end

        if string_len(pk) ~= PUBLICKEYBYTES then
          return error(string_format('wrong key size, expected: %d',
            PUBLICKEYBYTES))
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string_format('wrong key size, expected: %d',
            PUBLICKEYBYTES))
        end

        local tmp_m = char_array(mlen + ZEROBYTES)
        ffi.fill(tmp_m,ZEROBYTES,0)
        ffi.copy(tmp_m+ZEROBYTES,m,mlen)

        local c = char_array(clen + BOXZEROBYTES)
        ffi.fill(c,BOXZEROBYTES,0)

        if sodium_lib[crypto_box](
          c,tmp_m,mlen+ZEROBYTES,
          nonce,pk,sk) == -1  then
          return nil, string_format('%s error',crypto_box)
        end
        local c_str = ffi_string(c + BOXZEROBYTES,clen)
        sodium_lib.sodium_memzero(tmp_m,mlen + ZEROBYTES)
        sodium_lib.sodium_memzero(c,clen + BOXZEROBYTES)
        return c_str

      end,

      [crypto_box_open] = function(c, nonce, pk, sk)
        if not sk then
          return error('requires 4 arguments')
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

        if string_len(pk) ~= PUBLICKEYBYTES then
          return error(string_format('wrong key size, expected: %d',
            PUBLICKEYBYTES))
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string_format('wrong key size, expected: %d',
            PUBLICKEYBYTES))
        end

        local mlen = clen - MACBYTES

        local tmp_c = char_array(clen + BOXZEROBYTES)
        ffi.fill(tmp_c,BOXZEROBYTES,0)
        ffi.copy(tmp_c+BOXZEROBYTES,c,clen)

        local m = char_array(mlen + ZEROBYTES)
        ffi.fill(m,ZEROBYTES,0)

        if sodium_lib[crypto_box_open](
          m,tmp_c,clen+BOXZEROBYTES,
          nonce,pk,sk) == -1  then
          return nil, string_format('%s error',crypto_box_open)
        end

        local m_str = ffi_string(m+ZEROBYTES,mlen)
        sodium_lib.sodium_memzero(tmp_c,clen + BOXZEROBYTES)
        sodium_lib.sodium_memzero(m,mlen + ZEROBYTES)
        return m_str

      end,

      [crypto_box_beforenm] = function(pk,sk)
        local k

        if not sk then
          return error('requires 2 arguments')
        end

        if string_len(pk) ~= PUBLICKEYBYTES then
          return error(string_format(
            'wrong public key length, expected: %d', PUBLICKEYBYTES))
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string_format(
            'wrong secret key length, expected: %d', SECRETKEYBYTES))
        end

        k = char_array(BEFORENMBYTES)

        if tonumber(sodium_lib[crypto_box_beforenm](k,pk,sk)) == -1  then
          return nil, string_format('%s error',crypto_box_beforenm)
        end

        local k_str = ffi_string(k,BEFORENMBYTES)
        sodium_lib.sodium_memzero(k,BEFORENMBYTES)
        return k_str

      end,

      [crypto_box_afternm] = function(m, nonce, k)
        if not k then
          return error('requires 3 arguments')
        end

        local mlen = string_len(m)
        local clen = mlen + MACBYTES

        if string_len(nonce) ~= NONCEBYTES then
          return error(string_format('wrong nonce size, expected: %d',
            NONCEBYTES))
        end

        if string_len(k) ~= BEFORENMBYTES then
          return error(string_format('wrong key size, expected: %d',
            BEFORENMBYTES))
        end

        local tmp_m = char_array(mlen + ZEROBYTES)
        ffi.fill(tmp_m,ZEROBYTES,0)
        ffi.copy(tmp_m+ZEROBYTES,m,mlen)

        local c = char_array(clen + BOXZEROBYTES)
        ffi.fill(c,BOXZEROBYTES,0)

        if sodium_lib[crypto_box_afternm](
          c,tmp_m,mlen+ZEROBYTES,
          nonce,k) == -1  then
          return nil, string_format('%s',crypto_box_afternm)
        end
        local c_str = ffi_string(c + BOXZEROBYTES,clen)
        sodium_lib.sodium_memzero(tmp_m,mlen + ZEROBYTES)
        sodium_lib.sodium_memzero(c,clen + BOXZEROBYTES)
        return c_str
      end,

      [crypto_box_open_afternm] = function(c, nonce, k)
        if not k then
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

        if string_len(k) ~= BEFORENMBYTES then
          return error(string_format('wrong key size, expected: %d',
            BEFORENMBYTES))
        end

        local mlen = clen - MACBYTES

        local tmp_c = char_array(clen + BOXZEROBYTES)
        ffi.fill(tmp_c,BOXZEROBYTES,0)
        ffi.copy(tmp_c+BOXZEROBYTES,c,clen)

        local m = char_array(mlen + ZEROBYTES)
        ffi.fill(m,ZEROBYTES,0)

        if sodium_lib[crypto_box_open_afternm](
          m,tmp_c,clen+BOXZEROBYTES,
          nonce,k) == -1  then
          return nil, string_format('%s',crypto_box_open_afternm)
        end

        local m_str = ffi_string(m+ZEROBYTES,mlen)
        sodium_lib.sodium_memzero(tmp_c,clen + BOXZEROBYTES)
        sodium_lib.sodium_memzero(m,mlen + ZEROBYTES)
        return m_str

      end,
    }
  end

  local function ls_crypto_box_seed_keypair(basename)
    local crypto_box_seed_keypair = string_format('%s_seed_keypair',basename)

    local PUBLICKEYBYTES = constants[string_format('%s_PUBLICKEYBYTES',basename)]
    local SECRETKEYBYTES = constants[string_format('%s_SECRETKEYBYTES',basename)]
    local SEEDBYTES = constants[string_format('%s_SEEDBYTES',basename)]

    return {
      [crypto_box_seed_keypair] = function(seed)
        if not seed then
          return error('requires 1 argument')
        end
        if string_len(seed) ~= SEEDBYTES then
          return error(string_format(
            'wrong seed length, expected: %d', SEEDBYTES))
        end
        local pk = char_array(PUBLICKEYBYTES)
        local sk = char_array(SECRETKEYBYTES)
        if tonumber(sodium_lib[crypto_box_seed_keypair](pk,sk,seed)) == -1 then
          return nil, string_format('%s error',crypto_box_seed_keypair)
        end

        local pk_str = ffi_string(pk,PUBLICKEYBYTES)
        local sk_str = ffi_string(sk,SECRETKEYBYTES)
        sodium_lib.sodium_memzero(pk,PUBLICKEYBYTES)
        sodium_lib.sodium_memzero(sk,SECRETKEYBYTES)
        return pk_str, sk_str
      end,
    }
  end

  local function ls_crypto_box_easy(basename)
    local crypto_box_easy = string_format('%s_easy',basename)
    local crypto_box_open_easy = string_format('%s_open_easy',basename)

    local crypto_box_detached = string_format('%s_detached',basename)
    local crypto_box_open_detached = string_format('%s_open_detached',basename)

    local crypto_box_easy_afternm = string_format('%s_easy_afternm',basename)
    local crypto_box_open_easy_afternm = string_format('%s_open_easy_afternm',basename)

    local crypto_box_detached_afternm = string_format('%s_detached_afternm',basename)
    local crypto_box_open_detached_afternm = string_format('%s_open_detached_afternm',basename)


    local PUBLICKEYBYTES = constants[string_format('%s_PUBLICKEYBYTES',basename)]
    local SECRETKEYBYTES = constants[string_format('%s_SECRETKEYBYTES',basename)]
    local MACBYTES = constants[string_format('%s_MACBYTES',basename)]
    local NONCEBYTES = constants[string_format('%s_NONCEBYTES',basename)]
    local BEFORENMBYTES = constants[string_format('%s_BEFORENMBYTES',basename)]

    return {
      [crypto_box_easy] = function(m,n,pk,sk)
        local c
        if not sk then
          return error('requires 4 arguments')
        end

        local mlen = string_len(m)
        local clen = mlen + MACBYTES

        if string_len(n) ~= NONCEBYTES then
          return error(string_format(
            'wrong nonce length, expected: %d', NONCEBYTES))
        end

        if string_len(pk) ~= PUBLICKEYBYTES then
          return error(string_format(
            'wrong public key length, expected: %d', PUBLICKEYBYTES))
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string_format(
            'wrong secret key length, expected: %d', SECRETKEYBYTES))
        end

        c = char_array(clen)

        if tonumber(sodium_lib[crypto_box_easy](c,m,mlen,n,pk,sk)) == -1 then
          return nil, string_format('%s error',crypto_box_easy)
        end

        local c_str = ffi_string(c,clen)
        sodium_lib.sodium_memzero(c,clen)
        return c_str
      end,

      [crypto_box_open_easy] = function(c,n,pk,sk)
        local m
        if not sk then
          return error('requires 4 arguments')
        end

        local clen = string_len(c)

        if clen < MACBYTES then
          return error(string_format(
            'wrong cipher length, expected at least: %d',
            MACBYTES))
        end

        if string_len(n) ~= NONCEBYTES then
          return error(string_format(
            'wrong nonce length, expected: %d', NONCEBYTES))
        end

        if string_len(pk) ~= PUBLICKEYBYTES then
          return error(string_format(
            'wrong public key length, expected: %d', PUBLICKEYBYTES))
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string_format(
            'wrong secret key length, expected: %d', SECRETKEYBYTES))
        end

        local mlen = clen - MACBYTES

        m = char_array(mlen)

        if tonumber(sodium_lib[crypto_box_open_easy](m,c,clen,n,pk,sk)) == -1 then
          return nil, string_format('%s error',crypto_box_open_easy)
        end

        local m_str = ffi_string(m,mlen)
        sodium_lib.sodium_memzero(m,mlen)
        return m_str
      end,

      [crypto_box_detached] = function(m,n,pk,sk)
        local c
        local mac

        if not sk then
          return error('requires 4 arguments')
        end

        local mlen = string_len(m)

        if string_len(n) ~= NONCEBYTES then
          return error(string_format(
            'wrong nonce length, expected: %d', NONCEBYTES))
        end

        if string_len(pk) ~= PUBLICKEYBYTES then
          return error(string_format(
            'wrong public key length, expected: %d', PUBLICKEYBYTES))
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string_format(
            'wrong secret key length, expected: %d', SECRETKEYBYTES))
        end

        c = char_array(mlen)
        mac = char_array(MACBYTES)

        if tonumber(sodium_lib[crypto_box_detached](c,mac,m,mlen,n,pk,sk)) == -1 then
          return nil, string_format('%s error',crypto_box_detached)
        end

        local c_str = ffi_string(c,mlen)
        local mac_str = ffi_string(mac,MACBYTES)

        sodium_lib.sodium_memzero(c,mlen)
        sodium_lib.sodium_memzero(mac,MACBYTES)

        return c_str, mac_str

      end,

      [crypto_box_open_detached] = function(c,mac,n,pk,sk)
        local m

        if not sk then
          return error('requires 5 arguments')
        end

        local clen = string_len(c)
        local maclen = string_len(mac)

        if maclen ~= MACBYTES then
          return error(string_format(
            'wrong mac length, expected: %d',
            MACBYTES))
        end

        if string_len(n) ~= NONCEBYTES then
          return error(string_format(
            'wrong nonce length, expected: %d', NONCEBYTES))
        end

        if string_len(pk) ~= PUBLICKEYBYTES then
          return error(string_format(
            'wrong public key length, expected: %d', PUBLICKEYBYTES))
        end

        if string_len(sk) ~= SECRETKEYBYTES then
          return error(string_format(
            'wrong secret key length, expected: %d', SECRETKEYBYTES))
        end

        m = char_array(clen)

        if tonumber(sodium_lib[crypto_box_open_detached](m,c,mac,clen,n,pk,sk)) == -1 then
          return nil, string_format('%s error',crypto_box_open_detached)
        end

        local m_str = ffi_string(m,clen)
        sodium_lib.sodium_memzero(m,clen)
        return m_str

      end,

      [crypto_box_easy_afternm] = function(m,n,k)
        local c

        if not k then
          return error('requires 3 arguments')
        end

        local mlen = string_len(m)
        local clen = mlen + MACBYTES

        if string_len(n) ~= NONCEBYTES then
          return error(string_format(
            'wrong nonce length, expected: %d', NONCEBYTES))
        end

        if string_len(k) ~= BEFORENMBYTES then
          return error(string_format(
            'wrong shared key length, expected: %d', BEFORENMBYTES))
        end

        c = char_array(clen)

        if tonumber(sodium_lib[crypto_box_easy_afternm](c,m,mlen,n,k)) == -1 then
          return nil, string_format('%s error',crypto_box_easy_afternm)
        end
        local c_str = ffi_string(c,clen)
        sodium_lib.sodium_memzero(c,clen)
        return c_str
      end,

      [crypto_box_open_easy_afternm] = function(c,n,k)
        local m

        if not k then
          return error('requires 3 arguments')
        end

        local clen = string_len(c)

        if clen < MACBYTES then
          return error(string_format(
            'wrong cipher length, expected at least: %d',
            MACBYTES))
        end

        if string_len(n) ~= NONCEBYTES then
          return error(string_format(
            'wrong nonce length, expected: %d', NONCEBYTES))
        end

        if string_len(k) ~= BEFORENMBYTES then
          return error(string_format(
            'wrong shared key length, expected: %d', BEFORENMBYTES))
        end

        local mlen = clen - MACBYTES

        m = char_array(mlen)

        if tonumber(sodium_lib[crypto_box_open_easy_afternm](m,c,clen,n,k)) == -1 then
          return nil, string_format('%s error',crypto_box_open_easy_afternm)
        end

        local m_str = ffi_string(m,mlen)
        sodium_lib.sodium_memzero(m,mlen)
        return m_str
      end,

      [crypto_box_detached_afternm] = function(m,n,k)
        local c
        local mac

        if not k then
          return error('requires 3 arguments')
        end

        local mlen = string_len(m)

        if string_len(n) ~= NONCEBYTES then
          return error(string_format(
            'wrong nonce length, expected: %d', NONCEBYTES))
        end

        if string_len(k) ~= BEFORENMBYTES then
          return error(string_format(
            'wrong shared key length, expected: %d', BEFORENMBYTES))
        end

        c = char_array(mlen)
        mac = char_array(MACBYTES)

        if tonumber(sodium_lib[crypto_box_detached_afternm](c,mac,m,mlen,n,k)) == -1 then
          return nil, string_format('%s error',crypto_box_open_easy_afternm)
        end

        local c_str = ffi_string(c,mlen)
        local mac_str = ffi_string(mac,MACBYTES)

        sodium_lib.sodium_memzero(c,mlen)
        sodium_lib.sodium_memzero(mac,MACBYTES)

        return c_str, mac_str

      end,

      [crypto_box_open_detached_afternm] = function(c,mac,n,k)
        local m

        if not k then
          return error('requires 4 arguments')
        end

        local clen = string_len(c)
        local maclen = string_len(mac)

        if maclen ~= MACBYTES then
          return error(string_format(
            'wrong mac length, expected: %d',
            MACBYTES))
        end

        if string_len(n) ~= NONCEBYTES then
          return error(string_format(
            'wrong nonce length, expected: %d', NONCEBYTES))
        end

        if string_len(k) ~= BEFORENMBYTES then
          return error(string_format(
            'wrong shared key length, expected: %d', BEFORENMBYTES))
        end

        m = char_array(clen)

        if tonumber(sodium_lib[crypto_box_open_detached_afternm](m,c,mac,clen,n,k)) == -1 then
          return nil, string_format('%s error',crypto_box_open_detached_afternm)
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

  -- handle crypto_box functions
  for _,basename in ipairs({
    'crypto_box',
    'crypto_box_curve25519xsalsa20poly1305',
  }) do
    local m = ls_crypto_box(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  -- handle crypto_box_seed_keypair functions
  for _,basename in ipairs({
    'crypto_box',
    'crypto_box_curve25519xsalsa20poly1305',
  }) do
    local m = ls_crypto_box_seed_keypair(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  -- handle crypto_box_easy/detached functions
  for _,basename in ipairs({
    'crypto_box',
  }) do
    local m = ls_crypto_box_easy(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M

end
