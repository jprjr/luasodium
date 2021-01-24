return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_pwhash(basename)
    local crypto_pwhash = string_format('%s',basename)
    local crypto_pwhash_str = string_format('%s_str',basename)
    local crypto_pwhash_str_verify = string_format('%s_str_verify',basename)
    local crypto_pwhash_str_needs_rehash = string_format('%s_str_needs_rehash',basename)

    local ALG_DEFAULT = constants[string_format('%s_ALG_DEFAULT',basename)]
    local SALTBYTES = constants[string_format('%s_SALTBYTES',basename)]
    local STRBYTES = constants[string_format('%s_STRBYTES',basename)]
    local BYTES_MIN = constants[string_format('%s_BYTES_MIN',basename)]
    local BYTES_MAX = constants[string_format('%s_BYTES_MAX',basename)]
    local MEMLIMIT_MIN = constants[string_format('%s_MEMLIMIT_MIN',basename)]
    local MEMLIMIT_MAX = constants[string_format('%s_MEMLIMIT_MAX',basename)]
    local OPSLIMIT_MIN = constants[string_format('%s_OPSLIMIT_MIN',basename)]
    local OPSLIMIT_MAX = constants[string_format('%s_OPSLIMIT_MAX',basename)]
    local PASSWD_MIN = constants[string_format('%s_PASSWD_MIN',basename)]
    local PASSWD_MAX = constants[string_format('%s_PASSWD_MAX',basename)]

    local STRPREFIX_key = string_format('%s_STRPREFIX',basename)
    if not constants[STRPREFIX_key] then
      ffi.cdef(string_format('const char *%s(void)',
        string.lower(STRPREFIX_key)))
      constants[STRPREFIX_key] = ffi_string(sodium_lib[string.lower(STRPREFIX_key)]())
    end

    local M = {
      [crypto_pwhash] = function(outlen, passwd, salt, opslimit, memlimit, alg)
        if not memlimit then
          return error('requires 5 parameters')
        end

        alg = alg or ALG_DEFAULT

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

        if tonumber(sodium_lib[crypto_pwhash](out,outlen,passwd,passwdlen,salt,opslimit,memlimit,alg)) == -1 then
          return error(string_format('%s error',crypto_pwhash))
        end
        local out_str = ffi_string(out,outlen)
        sodium_lib.sodium_memzero(out,outlen)
        return out_str
      end,

      [crypto_pwhash_str] = function(passwd, opslimit, memlimit)
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
          return error(string_format('%s error',crypto_pwhash_str))
        end
        local out_str = ffi_string(out)
        sodium_lib.sodium_memzero(out,STRBYTES)
        return out_str
      end,

      [crypto_pwhash_str_verify] = function(str,passwd)
        if not passwd then
          return error('requires 2 parameters')
        end

        local passwdlen = string_len(passwd)
        if passwdlen < PASSWD_MIN or passwdlen > PASSWD_MAX then
          return error(string_format('incorrect passwdlen, must be between %d and %d', PASSWD_MIN, PASSWD_MAX))
        end

        return tonumber(sodium_lib[crypto_pwhash_str_verify](str,passwd,passwdlen)) == 0
      end,

      [crypto_pwhash_str_needs_rehash] = function(str, opslimit, memlimit)
        if not memlimit then
          return error('requires 3 parameters')
        end

        if opslimit < OPSLIMIT_MIN or opslimit > OPSLIMIT_MAX then
          return error(string_format('incorrect ops limit, must be between %d and %d', OPSLIMIT_MIN, OPSLIMIT_MAX))
        end

        if memlimit < MEMLIMIT_MIN or memlimit > MEMLIMIT_MAX then
          return error(string_format('incorrect mem limit, must be between %d and %d', MEMLIMIT_MIN, MEMLIMIT_MAX))
        end

        local res = tonumber(sodium_lib[crypto_pwhash_str_needs_rehash](str,opslimit,memlimit))

        if res == -1 then
          return nil, string_format('%s error',crypto_pwhash_str_needs_rehash)
        end
        return res == 0
      end,

    }
    return M
  end

  if tonumber(sodium_lib.sodium_init()) == -1 then
    return error('sodium_init error')
  end

  local M = { }

  for _,basename in ipairs({
    'crypto_pwhash',
  }) do
    local m = ls_crypto_pwhash(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end

