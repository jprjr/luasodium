return function(libs, constants)

  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local sodium_lib = libs.sodium

  local char_array = ffi.typeof('char[?]')

  local crypto_box_PUBLICKEYBYTES = constants.crypto_box_PUBLICKEYBYTES
  local crypto_box_SECRETKEYBYTES = constants.crypto_box_SECRETKEYBYTES
  local crypto_box_MACBYTES       = constants.crypto_box_MACBYTES
  local crypto_box_NONCEBYTES     = constants.crypto_box_NONCEBYTES
  local crypto_box_SEEDBYTES      = constants.crypto_box_SEEDBYTES
  local crypto_box_BEFORENMBYTES  = constants.crypto_box_BEFORENMBYTES
  local crypto_box_BOXZEROBYTES   = constants.crypto_box_BOXZEROBYTES
  local crypto_box_ZEROBYTES      = constants.crypto_box_ZEROBYTES

  local crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES =
    constants.crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
  local crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES =
    constants.crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
  local crypto_box_curve25519xsalsa20poly1305_MACBYTES       =
    constants.crypto_box_curve25519xsalsa20poly1305_MACBYTES
  local crypto_box_curve25519xsalsa20poly1305_NONCEBYTES     =
    constants.crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
  local crypto_box_curve25519xsalsa20poly1305_SEEDBYTES      =
    constants.crypto_box_curve25519xsalsa20poly1305_SEEDBYTES
  local crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES  =
    constants.crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES
  local crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES   =
    constants.crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
  local crypto_box_curve25519xsalsa20poly1305_ZEROBYTES      =
    constants.crypto_box_curve25519xsalsa20poly1305_ZEROBYTES

  local function lua_crypto_box_keypair(F,PUBLICKEYBYTES,SECRETKEYBYTES)
    return function()
      local pk = char_array(PUBLICKEYBYTES)
      local sk = char_array(SECRETKEYBYTES)
      if tonumber(sodium_lib[F](pk,sk)) == -1 then
        return error(string_format('%s error',F))
      end

      local pk_str = ffi_string(pk,PUBLICKEYBYTES)
      local sk_str = ffi_string(sk,SECRETKEYBYTES)

      sodium_lib.sodium_memzero(pk,PUBLICKEYBYTES)
      sodium_lib.sodium_memzero(sk,SECRETKEYBYTES)
      return pk_str, sk_str
    end
  end

  local function lua_crypto_box(F,MACBYTES,NONCEBYTES,PUBLICKEYBYTES,SECRETKEYBYTES,ZEROBYTES,BOXZEROBYTES)
    return function(m, nonce, pk, sk)
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

      if sodium_lib[F](
        c,tmp_m,mlen+ZEROBYTES,
        nonce,pk,sk) == -1  then
        return error(string.format('%s error',F))
      end
      local c_str = ffi_string(c + BOXZEROBYTES,clen)
      sodium_lib.sodium_memzero(tmp_m,mlen + ZEROBYTES)
      sodium_lib.sodium_memzero(c,clen + BOXZEROBYTES)
      return c_str
    end
  end

  local function lua_crypto_box_open(F,MACBYTES,NONCEBYTES,PUBLICKEYBYTES,SECRETKEYBYTES,ZEROBYTES,BOXZEROBYTES)
    return function(c, nonce, pk, sk)
      if not sk then
        return error('requires 4 arguments')
      end

      local clen = string_len(c)

      if clen < MACBYTES then
        return error(string.format('wrong c size, expected at least: %d',
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

      if sodium_lib[F](
        m,tmp_c,clen+BOXZEROBYTES,
        nonce,pk,sk) == -1  then
        return error(string.format('%s error',F))
      end

      local m_str = ffi_string(m+ZEROBYTES,mlen)
      sodium_lib.sodium_memzero(tmp_c,clen + BOXZEROBYTES)
      sodium_lib.sodium_memzero(m,mlen + ZEROBYTES)
      return m_str
    end
  end

  local function lua_crypto_box_beforenm(F,BEFORENMBYTES,PUBLICKEYBYTES,SECRETKEYBYTES)
    return function(pk,sk)
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

      if tonumber(sodium_lib[F](k,pk,sk)) == -1  then
        return error(string_format('%s error',F))
      end

      local k_str = ffi_string(k,BEFORENMBYTES)
      sodium_lib.sodium_memzero(k,BEFORENMBYTES)
      return k_str
    end
  end

  local function lua_crypto_box_afternm(F,MACBYTES,NONCEBYTES,BEFORENMBYTES,ZEROBYTES,BOXZEROBYTES)
    return function(m,nonce,k)
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

      if sodium_lib[F](
        c,tmp_m,mlen+ZEROBYTES,
        nonce,k) == -1  then
        return error(string_format('%s',F))
      end
      local c_str = ffi_string(c + BOXZEROBYTES,clen)
      sodium_lib.sodium_memzero(tmp_m,mlen + ZEROBYTES)
      sodium_lib.sodium_memzero(c,clen + BOXZEROBYTES)
      return c_str
    end
  end

  local function lua_crypto_box_open_afternm(F,MACBYTES,NONCEBYTES,BEFORENMBYTES,ZEROBYTES,BOXZEROBYTES)
    return function(c, nonce, k)
      if not k then
        return error('requires 3 arguments')
      end

      local clen = string_len(c)

      if clen < MACBYTES then
        return error(string.format('wrong c size, expected at least: %d',
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

      if sodium_lib[F](
        m,tmp_c,clen+BOXZEROBYTES,
        nonce,k) == -1  then
        return error(string_format('%s',F))
      end

      local m_str = ffi_string(m+ZEROBYTES,mlen)
      sodium_lib.sodium_memzero(tmp_c,clen + BOXZEROBYTES)
      sodium_lib.sodium_memzero(m,mlen + ZEROBYTES)
      return m_str
    end
  end

  local function lua_crypto_box_easy(m,n,pk,sk)
    local c
    if not sk then
      return error('requires 4 arguments')
    end

    local mlen = string_len(m)
    local clen = mlen + crypto_box_MACBYTES

    if string_len(n) ~= crypto_box_NONCEBYTES then
      return error(string_format(
        'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
    end

    if string_len(pk) ~= crypto_box_PUBLICKEYBYTES then
      return error(string_format(
        'wrong public key length, expected: %d', crypto_box_PUBLICKEYBYTES))
    end

    if string_len(sk) ~= crypto_box_SECRETKEYBYTES then
      return error(string_format(
        'wrong secret key length, expected: %d', crypto_box_SECRETKEYBYTES))
    end

    c = char_array(clen)

    if tonumber(sodium_lib.crypto_box_easy(c,m,mlen,n,pk,sk)) == -1 then
      return error('crypto_box_easy error')
    end

    local c_str = ffi_string(c,clen)
    sodium_lib.sodium_memzero(c,clen)
    return c_str
  end

  local function lua_crypto_box_open_easy(c,n,pk,sk)
    local m
    if not sk then
      return error('requires 4 arguments')
    end

    local clen = string_len(c)

    if clen < crypto_box_MACBYTES then
      return error(string_format(
        'wrong cipher length, expected at least: %d',
        crypto_box_MACBYTES))
    end

    if string_len(n) ~= crypto_box_NONCEBYTES then
      return error(string_format(
        'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
    end

    if string_len(pk) ~= crypto_box_PUBLICKEYBYTES then
      return error(string_format(
        'wrong public key length, expected: %d', crypto_box_PUBLICKEYBYTES))
    end

    if string_len(sk) ~= crypto_box_SECRETKEYBYTES then
      return error(string_format(
        'wrong secret key length, expected: %d', crypto_box_SECRETKEYBYTES))
    end

    local mlen = clen - crypto_box_MACBYTES

    m = char_array(mlen)

    if tonumber(sodium_lib.crypto_box_open_easy(m,c,clen,n,pk,sk)) == -1 then
      return error('crypto_box_open_easy error')
    end

    local m_str = ffi_string(m,mlen)
    sodium_lib.sodium_memzero(m,mlen)
    return m_str
  end

  local function lua_crypto_box_detached(m,n,pk,sk)
    local c
    local mac

    if not sk then
      return error('requires 4 arguments')
    end

    local mlen = string_len(m)

    if string_len(n) ~= crypto_box_NONCEBYTES then
      return error(string_format(
        'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
    end

    if string_len(pk) ~= crypto_box_PUBLICKEYBYTES then
      return error(string_format(
        'wrong public key length, expected: %d', crypto_box_PUBLICKEYBYTES))
    end

    if string_len(sk) ~= crypto_box_SECRETKEYBYTES then
      return error(string_format(
        'wrong secret key length, expected: %d', crypto_box_SECRETKEYBYTES))
    end

    c = char_array(mlen)
    mac = char_array(crypto_box_MACBYTES)

    if tonumber(sodium_lib.crypto_box_detached(c,mac,m,mlen,n,pk,sk)) == -1 then
      return error('crypto_box_detached error')
    end

    local c_str = ffi_string(c,mlen)
    local mac_str = ffi_string(mac,crypto_box_MACBYTES)

    sodium_lib.sodium_memzero(c,mlen)
    sodium_lib.sodium_memzero(mac,crypto_box_MACBYTES)

    return c_str, mac_str
  end

  local function lua_crypto_box_open_detached(c,mac,n,pk,sk)
    local m

    if not sk then
      return error('requires 5 arguments')
    end

    local clen = string_len(c)
    local maclen = string_len(mac)

    if maclen ~= crypto_box_MACBYTES then
      return error(string_format(
        'wrong mac length, expected: %d',
        crypto_box_MACBYTES))
    end

    if string_len(n) ~= crypto_box_NONCEBYTES then
      return error(string_format(
        'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
    end

    if string_len(pk) ~= crypto_box_PUBLICKEYBYTES then
      return error(string_format(
        'wrong public key length, expected: %d', crypto_box_PUBLICKEYBYTES))
    end

    if string_len(sk) ~= crypto_box_SECRETKEYBYTES then
      return error(string_format(
        'wrong secret key length, expected: %d', crypto_box_SECRETKEYBYTES))
    end

    m = char_array(clen)

    if tonumber(sodium_lib.crypto_box_open_detached(m,c,mac,clen,n,pk,sk)) == -1 then
      return error('crypto_box_open_detached error')
    end

    local m_str = ffi_string(m,clen)
    sodium_lib.sodium_memzero(m,clen)
    return m_str
  end

  local function lua_crypto_box_easy_afternm(m,n,k)
    local c

    if not k then
      return error('requires 3 arguments')
    end

    local mlen = string_len(m)
    local clen = mlen + crypto_box_MACBYTES

    if string_len(n) ~= crypto_box_NONCEBYTES then
      return error(string_format(
        'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
    end

    if string_len(k) ~= crypto_box_BEFORENMBYTES then
      return error(string_format(
        'wrong shared key length, expected: %d', crypto_box_BEFORENMBYTES))
    end

    c = char_array(clen)

    if tonumber(sodium_lib.crypto_box_easy_afternm(c,m,mlen,n,k)) == -1 then
      return error('crypto_box_easy_afternm')
    end
    local c_str = ffi_string(c,clen)
    sodium_lib.sodium_memzero(c,clen)
    return c_str
  end

  local function lua_crypto_box_open_easy_afternm(c,n,k)
    local m

    if not k then
      return error('requires 3 arguments')
    end

    local clen = string_len(c)

    if clen < crypto_box_MACBYTES then
      return error(string_format(
        'wrong cipher length, expected at least: %d',
        crypto_box_MACBYTES))
    end

    if string_len(n) ~= crypto_box_NONCEBYTES then
      return error(string_format(
        'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
    end

    if string_len(k) ~= crypto_box_BEFORENMBYTES then
      return error(string_format(
        'wrong shared key length, expected: %d', crypto_box_BEFORENMBYTES))
    end

    local mlen = clen - crypto_box_MACBYTES

    m = char_array(mlen)

    if tonumber(sodium_lib.crypto_box_open_easy_afternm(m,c,clen,n,k)) == -1 then
      return error('crypto_box_open_easy_afternm')
    end

    local m_str = ffi_string(m,mlen)
    sodium_lib.sodium_memzero(m,mlen)
    return m_str
  end

  local function lua_crypto_box_detached_afternm(m,n,k)
    local c
    local mac

    if not k then
      return error('requires 3 arguments')
    end

    local mlen = string_len(m)

    if string_len(n) ~= crypto_box_NONCEBYTES then
      return error(string_format(
        'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
    end

    if string_len(k) ~= crypto_box_BEFORENMBYTES then
      return error(string_format(
        'wrong shared key length, expected: %d', crypto_box_BEFORENMBYTES))
    end

    c = char_array(mlen)
    mac = char_array(crypto_box_MACBYTES)

    if tonumber(sodium_lib.crypto_box_detached_afternm(c,mac,m,mlen,n,k)) == -1 then
      return error('crypto_box_detached_afternm error')
    end

    local c_str = ffi_string(c,mlen)
    local mac_str = ffi_string(mac,crypto_box_MACBYTES)

    sodium_lib.sodium_memzero(c,mlen)
    sodium_lib.sodium_memzero(mac,crypto_box_MACBYTES)

    return c_str, mac_str
  end

  local function lua_crypto_box_open_detached_afternm(c,mac,n,k)
    local m

    if not k then
      return error('requires 4 arguments')
    end

    local clen = string_len(c)
    local maclen = string_len(mac)

    if maclen ~= crypto_box_MACBYTES then
      return error(string_format(
        'wrong mac length, expected: %d',
        crypto_box_MACBYTES))
    end

    if string_len(n) ~= crypto_box_NONCEBYTES then
      return error(string_format(
        'wrong nonce length, expected: %d', crypto_box_NONCEBYTES))
    end

    if string_len(k) ~= crypto_box_BEFORENMBYTES then
      return error(string_format(
        'wrong shared key length, expected: %d', crypto_box_BEFORENMBYTES))
    end

    m = char_array(clen)

    if tonumber(sodium_lib.crypto_box_open_detached_afternm(m,c,mac,clen,n,k)) == -1 then
      return error('crypto_box_open_detached_afternm error')
    end
    local m_str = ffi_string(m,clen)
    sodium_lib.sodium_memzero(m,clen)
    return m_str
  end

  local function lua_crypto_box_seed_keypair(F,SEEDBYTES,PUBLICKEYBYTES,SECRETKEYBYTES)
    return function(seed)
      if not seed then
        return error('requires 1 argument')
      end
      if string_len(seed) ~= SEEDBYTES then
        return error(string_format(
          'wrong seed length, expected: %d', SEEDBYTES))
      end
      local pk = char_array(PUBLICKEYBYTES)
      local sk = char_array(SECRETKEYBYTES)
      if tonumber(sodium_lib[F](pk,sk,seed)) == -1 then
        return error(string_format('%s error',F))
      end

      local pk_str = ffi_string(pk,PUBLICKEYBYTES)
      local sk_str = ffi_string(sk,SECRETKEYBYTES)
      sodium_lib.sodium_memzero(pk,PUBLICKEYBYTES)
      sodium_lib.sodium_memzero(sk,SECRETKEYBYTES)
      return pk_str, sk_str
    end
  end


  if sodium_lib.sodium_init() == -1 then
    return error('sodium_init error')
  end

  local M = {
    crypto_box_keypair = lua_crypto_box_keypair(
      'crypto_box_keypair',
      crypto_box_PUBLICKEYBYTES,
      crypto_box_SECRETKEYBYTES
    ),
    crypto_box = lua_crypto_box(
      'crypto_box',
      crypto_box_MACBYTES,
      crypto_box_NONCEBYTES,
      crypto_box_PUBLICKEYBYTES,
      crypto_box_SECRETKEYBYTES,
      crypto_box_ZEROBYTES,
      crypto_box_BOXZEROBYTES
    ),
    crypto_box_open = lua_crypto_box_open(
      'crypto_box_open',
      crypto_box_MACBYTES,
      crypto_box_NONCEBYTES,
      crypto_box_PUBLICKEYBYTES,
      crypto_box_SECRETKEYBYTES,
      crypto_box_ZEROBYTES,
      crypto_box_BOXZEROBYTES
    ),
    crypto_box_beforenm = lua_crypto_box_beforenm(
      'crypto_box_beforenm',
      crypto_box_BEFORENMBYTES,
      crypto_box_PUBLICKEYBYTES,
      crypto_box_SECRETKEYBYTES
    ),
    crypto_box_afternm = lua_crypto_box_afternm(
      'crypto_box_afternm',
      crypto_box_MACBYTES,
      crypto_box_NONCEBYTES,
      crypto_box_BEFORENMBYTES,
      crypto_box_ZEROBYTES,
      crypto_box_BOXZEROBYTES
    ),
    crypto_box_open_afternm = lua_crypto_box_open_afternm(
      'crypto_box_open_afternm',
      crypto_box_MACBYTES,
      crypto_box_NONCEBYTES,
      crypto_box_BEFORENMBYTES,
      crypto_box_ZEROBYTES,
      crypto_box_BOXZEROBYTES
    ),
    crypto_box_curve25519xsalsa20poly1305_keypair = lua_crypto_box_keypair(
      'crypto_box_curve25519xsalsa20poly1305_keypair',
      crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
      crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
    ),
    crypto_box_curve25519xsalsa20poly1305 = lua_crypto_box(
      'crypto_box_curve25519xsalsa20poly1305',
      crypto_box_curve25519xsalsa20poly1305_MACBYTES,
      crypto_box_curve25519xsalsa20poly1305_NONCEBYTES,
      crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
      crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
      crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
      crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
    ),
    crypto_box_curve25519xsalsa20poly1305_open = lua_crypto_box_open(
      'crypto_box_curve25519xsalsa20poly1305_open',
      crypto_box_curve25519xsalsa20poly1305_MACBYTES,
      crypto_box_curve25519xsalsa20poly1305_NONCEBYTES,
      crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
      crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
      crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
      crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
    ),
    crypto_box_curve25519xsalsa20poly1305_beforenm = lua_crypto_box_beforenm(
      'crypto_box_curve25519xsalsa20poly1305_beforenm',
      crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES,
      crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
      crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
    ),
    crypto_box_curve25519xsalsa20poly1305_afternm = lua_crypto_box_afternm(
      'crypto_box_curve25519xsalsa20poly1305_afternm',
      crypto_box_curve25519xsalsa20poly1305_MACBYTES,
      crypto_box_curve25519xsalsa20poly1305_NONCEBYTES,
      crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES,
      crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
      crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
    ),
    crypto_box_curve25519xsalsa20poly1305_open_afternm = lua_crypto_box_open_afternm(
      'crypto_box_curve25519xsalsa20poly1305_open_afternm',
      crypto_box_curve25519xsalsa20poly1305_MACBYTES,
      crypto_box_curve25519xsalsa20poly1305_NONCEBYTES,
      crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES,
      crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
      crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
    ),
    crypto_box_seed_keypair = lua_crypto_box_seed_keypair(
      'crypto_box_seed_keypair',
      crypto_box_SEEDBYTES,
      crypto_box_PUBLICKEYBYTES,
      crypto_box_SECRETKEYBYTES
    ),
    crypto_box_curve25519xsalsa20poly1305_seed_keypair = lua_crypto_box_seed_keypair(
      'crypto_box_curve25519xsalsa20poly1305_seed_keypair',
      crypto_box_curve25519xsalsa20poly1305_SEEDBYTES,
      crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
      crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
    ),
    crypto_box_easy = lua_crypto_box_easy,
    crypto_box_open_easy = lua_crypto_box_open_easy,
    crypto_box_detached = lua_crypto_box_detached,
    crypto_box_open_detached = lua_crypto_box_open_detached,
    crypto_box_easy_afternm = lua_crypto_box_easy_afternm,
    crypto_box_open_easy_afternm = lua_crypto_box_open_easy_afternm,
    crypto_box_detached_afternm = lua_crypto_box_detached_afternm,
    crypto_box_open_detached_afternm = lua_crypto_box_open_detached_afternm,
  }

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M

end
