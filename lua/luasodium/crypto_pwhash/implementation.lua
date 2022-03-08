return function(sodium_lib, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_pwhash_noalg(basename)
    local SALTBYTES = constants[string_format('%s_SALTBYTES',basename)]
    local BYTES_MIN = constants[string_format('%s_BYTES_MIN',basename)]
    local BYTES_MAX = constants[string_format('%s_BYTES_MAX',basename)]
    local MEMLIMIT_MIN = constants[string_format('%s_MEMLIMIT_MIN',basename)]
    local MEMLIMIT_MAX = constants[string_format('%s_MEMLIMIT_MAX',basename)]
    local OPSLIMIT_MIN = constants[string_format('%s_OPSLIMIT_MIN',basename)]
    local OPSLIMIT_MAX = constants[string_format('%s_OPSLIMIT_MAX',basename)]
    local PASSWD_MIN = constants[string_format('%s_PASSWD_MIN',basename)]
    local PASSWD_MAX = constants[string_format('%s_PASSWD_MAX',basename)]

    return function(outlen, passwd, salt, opslimit, memlimit)
      if not memlimit then
        return error('requires 5 parameters')
      end

      local passwdlen = string_len(passwd)
      local saltlen = string_len(salt)

      if outlen < BYTES_MIN or outlen > BYTES_MAX then
        return error(string_format('incorrect outlen, must be between %d and %d', BYTES_MIN, BYTES_MAX))
      end

      if passwdlen < PASSWD_MIN or passwdlen > PASSWD_MAX then
        return error(string_format('incorrect passwdlen, must be between %s and %s', tostring(PASSWD_MIN), tostring(PASSWD_MAX)))
      end

      if saltlen ~= SALTBYTES then
        return error(string_format('incorrect salt length, must be: %d', SALTBYTES))
      end

      if opslimit < OPSLIMIT_MIN or opslimit > OPSLIMIT_MAX then
        return error(string_format('incorrect ops limit, must be between %d and %d', OPSLIMIT_MIN, OPSLIMIT_MAX))
      end

      if memlimit < MEMLIMIT_MIN or memlimit > MEMLIMIT_MAX then
        return error(string_format('incorrect mem limit, must be between %d and %d', MEMLIMIT_MIN, MEMLIMIT_MAX))
      end

      local out = char_array(outlen)

      local r = tonumber(sodium_lib[basename](out,outlen,passwd,passwdlen,salt,opslimit,memlimit))

      if r == -1 then
        return nil, string_format('%s error',basename)
      end
      local out_str = ffi_string(out,outlen)
      sodium_lib.sodium_memzero(out,outlen)
      return out_str
    end
  end

  local function ls_crypto_pwhash(basename,algo)
    local ALG = constants[string_format('crypto_pwhash_ALG_%s',algo)]
    local SALTBYTES = constants[string_format('%s_SALTBYTES',basename)]
    local BYTES_MIN = constants[string_format('%s_BYTES_MIN',basename)]
    local BYTES_MAX = constants[string_format('%s_BYTES_MAX',basename)]
    local MEMLIMIT_MIN = constants[string_format('%s_MEMLIMIT_MIN',basename)]
    local MEMLIMIT_MAX = constants[string_format('%s_MEMLIMIT_MAX',basename)]
    local OPSLIMIT_MIN = constants[string_format('%s_OPSLIMIT_MIN',basename)]
    local OPSLIMIT_MAX = constants[string_format('%s_OPSLIMIT_MAX',basename)]
    local PASSWD_MIN = constants[string_format('%s_PASSWD_MIN',basename)]
    local PASSWD_MAX = constants[string_format('%s_PASSWD_MAX',basename)]

    return function(outlen, passwd, salt, opslimit, memlimit, alg)
      if not memlimit then
        return error('requires 5 parameters')
      end

      alg = alg or ALG

      local passwdlen = string_len(passwd)
      local saltlen = string_len(salt)

      if outlen < BYTES_MIN or outlen > BYTES_MAX then
        return error(string_format('incorrect outlen, must be between %d and %d', BYTES_MIN, BYTES_MAX))
      end

      if passwdlen < PASSWD_MIN or passwdlen > PASSWD_MAX then
        return error(string_format('incorrect passwdlen, must be between %d and %d', PASSWD_MIN, PASSWD_MAX))
      end

      if saltlen ~= SALTBYTES then
        return error(string_format('incorrect salt length, must be: %d', SALTBYTES))
      end

      if opslimit < OPSLIMIT_MIN or opslimit > OPSLIMIT_MAX then
        return error(string_format('incorrect ops limit, must be between %d and %d', OPSLIMIT_MIN, OPSLIMIT_MAX))
      end

      if memlimit < MEMLIMIT_MIN or memlimit > MEMLIMIT_MAX then
        return error(string_format('incorrect mem limit, must be between %d and %d', MEMLIMIT_MIN, MEMLIMIT_MAX))
      end

      local out = char_array(outlen)

      local r = tonumber(sodium_lib[basename](out,outlen,passwd,passwdlen,salt,opslimit,memlimit,alg))

      if r == -1 then
        return nil, string_format('%s error',basename)
      end
      local out_str = ffi_string(out,outlen)
      sodium_lib.sodium_memzero(out,outlen)
      return out_str
    end
  end

  local function ls_crypto_pwhash_str(basename)
    local crypto_pwhash_str = string_format('%s_str',basename)
    local STRBYTES = constants[string_format('%s_STRBYTES',basename)]
    local MEMLIMIT_MIN = constants[string_format('%s_MEMLIMIT_MIN',basename)]
    local MEMLIMIT_MAX = constants[string_format('%s_MEMLIMIT_MAX',basename)]
    local OPSLIMIT_MIN = constants[string_format('%s_OPSLIMIT_MIN',basename)]
    local OPSLIMIT_MAX = constants[string_format('%s_OPSLIMIT_MAX',basename)]
    local PASSWD_MIN = constants[string_format('%s_PASSWD_MIN',basename)]
    local PASSWD_MAX = constants[string_format('%s_PASSWD_MAX',basename)]

    return function(passwd, opslimit, memlimit)
      if not memlimit then
        return error('requires 3 parameters')
      end

      local passwdlen = string_len(passwd)
      if passwdlen < PASSWD_MIN or passwdlen > PASSWD_MAX then
        return error(string_format('incorrect passwdlen, must be between %d and %d', PASSWD_MIN, PASSWD_MAX))
      end

      if opslimit < OPSLIMIT_MIN or opslimit > OPSLIMIT_MAX then
        return error(string_format('incorrect ops limit, must be between %d and %d', OPSLIMIT_MIN, OPSLIMIT_MAX))
      end

      if memlimit < MEMLIMIT_MIN or memlimit > MEMLIMIT_MAX then
        return error(string_format('incorrect mem limit, must be between %d and %d', MEMLIMIT_MIN, MEMLIMIT_MAX))
      end

      local out = char_array(STRBYTES)
      if tonumber(sodium_lib[crypto_pwhash_str](out,passwd,passwdlen,opslimit,memlimit)) == -1 then
        return nil, string_format('%s error',crypto_pwhash_str)
      end
      local out_str = ffi_string(out)
      sodium_lib.sodium_memzero(out,STRBYTES)
      return out_str
    end
  end

  local function ls_crypto_pwhash_str_verify(basename)
    local crypto_pwhash_str_verify = string_format('%s_str_verify',basename)
    local PASSWD_MIN = constants[string_format('%s_PASSWD_MIN',basename)]
    local PASSWD_MAX = constants[string_format('%s_PASSWD_MAX',basename)]
    return function(str,passwd)
      if not passwd then
        return error('requires 2 parameters')
      end

      local passwdlen = string_len(passwd)
      if passwdlen < PASSWD_MIN or passwdlen > PASSWD_MAX then
        return error(string_format('incorrect passwdlen, must be between %d and %d', PASSWD_MIN, PASSWD_MAX))
      end

      return tonumber(sodium_lib[crypto_pwhash_str_verify](str,passwd,passwdlen)) == 0
    end
  end

  local function ls_crypto_pwhash_str_needs_rehash(basename)
    local crypto_pwhash_str_needs_rehash = string_format('%s_str_needs_rehash',basename)
    local MEMLIMIT_MIN = constants[string_format('%s_MEMLIMIT_MIN',basename)]
    local MEMLIMIT_MAX = constants[string_format('%s_MEMLIMIT_MAX',basename)]
    local OPSLIMIT_MIN = constants[string_format('%s_OPSLIMIT_MIN',basename)]
    local OPSLIMIT_MAX = constants[string_format('%s_OPSLIMIT_MAX',basename)]
    return function(str, opslimit, memlimit)
      if not memlimit then
        return error('requires 3 parameters')
      end

      if opslimit < OPSLIMIT_MIN or opslimit > OPSLIMIT_MAX then
        return error(string_format('incorrect ops limit, must be between %d and %d', OPSLIMIT_MIN, OPSLIMIT_MAX))
      end

      if memlimit < MEMLIMIT_MIN or memlimit > MEMLIMIT_MAX then
        return error(string_format('incorrect mem limit, must be between %d and %d', MEMLIMIT_MIN, MEMLIMIT_MAX))
      end

      return tonumber(sodium_lib[crypto_pwhash_str_needs_rehash](str,opslimit,memlimit)) ~= 0
    end
  end

  local function ls_crypto_pwhash_strprefix(basename)
    local STRPREFIX_key = string_format('%s_STRPREFIX',basename)
    if not constants[STRPREFIX_key] then
      ffi.cdef(string_format('const char *%s(void)',
        string.lower(STRPREFIX_key)))
      constants[STRPREFIX_key] = ffi_string(sodium_lib[string.lower(STRPREFIX_key)]())
    end
  end

  if tonumber(sodium_lib.sodium_init()) == -1 then
    return error('sodium_init error')
  end

  local M = {
    ['crypto_pwhash'] = ls_crypto_pwhash('crypto_pwhash','DEFAULT'),
    ['crypto_pwhash_argon2i'] = ls_crypto_pwhash('crypto_pwhash_argon2i','ARGON2I13'),
    ['crypto_pwhash_argon2id'] = ls_crypto_pwhash('crypto_pwhash_argon2id','ARGON2ID13'),
    ['crypto_pwhash_scryptsalsa208sha256'] = ls_crypto_pwhash_noalg('crypto_pwhash_scryptsalsa208sha256'),
  }
  for _,k in ipairs({
    'crypto_pwhash',
    'crypto_pwhash_argon2i',
    'crypto_pwhash_argon2id',
    'crypto_pwhash_scryptsalsa208sha256'
  }) do
    local str = string_format('%s_str',k)
    local str_verify = string_format('%s_str_verify',k)
    local str_needs_rehash = string_format('%s_str_needs_rehash',k)
    M[str] = ls_crypto_pwhash_str(k)
    M[str_verify] = ls_crypto_pwhash_str_verify(k)
    M[str_needs_rehash] = ls_crypto_pwhash_str_needs_rehash(k)
    ls_crypto_pwhash_strprefix(k)
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end

