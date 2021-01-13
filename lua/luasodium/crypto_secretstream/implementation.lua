return function(libs, constants)
  local ffi = require'ffi'
  local string_len = string.len
  local string_format = string.format
  local ffi_string = ffi.string
  local tonumber = tonumber

  local sodium_lib = libs.sodium
  local clib = libs.C

  local char_array = ffi.typeof('char[?]')

  local function ls_crypto_secretstream(basename)
    local crypto_secretstream_init_push = string_format('%s_init_push',basename)
    local crypto_secretstream_init_pull = string_format('%s_init_pull',basename)
    local crypto_secretstream_push = string_format('%s_push',basename)
    local crypto_secretstream_pull = string_format('%s_pull',basename)
    local crypto_secretstream_keygen = string_format('%s_keygen',basename)
    local crypto_secretstream_rekey = string_format('%s_rekey',basename)

    local ABYTES = constants[string_format('%s_ABYTES',basename)]
    local KEYBYTES = constants[string_format('%s_KEYBYTES',basename)]
    local HEADERBYTES = constants[string_format('%s_HEADERBYTES',basename)]
    local STATEBYTES = tonumber(sodium_lib[string_format('%s_statebytes',basename)]())
    local TAG_MESSAGE = tonumber(sodium_lib[string_format('%s_tag_message',basename)]())
    local TAG_PUSH = tonumber(sodium_lib[string_format('%s_tag_push',basename)]())
    local TAG_REKEY = tonumber(sodium_lib[string_format('%s_tag_rekey',basename)]())
    local TAG_FINAL = tonumber(sodium_lib[string_format('%s_tag_final',basename)]())

    local ls_crypto_secretstream_free = function(state)
      sodium_lib.sodium_memzero(state,STATEBYTES)
      clib.free(state)
    end

    local ls_crypto_secretstream_push_methods = {}
    local ls_crypto_secretstream_push_mt = {
      __index = ls_crypto_secretstream_push_methods
    }

    local ls_crypto_secretstream_pull_methods = {}
    local ls_crypto_secretstream_pull_mt = {
      __index = ls_crypto_secretstream_pull_methods
    }

    local M = {
      [crypto_secretstream_keygen] = function()
        local k = char_array(KEYBYTES)
        sodium_lib[crypto_secretstream_keygen](k)
        local k_str = ffi_string(k,KEYBYTES)
        sodium_lib.sodium_memzero(k,KEYBYTES)
        return k_str
      end,

      [crypto_secretstream_rekey] = function(ls_state)
        sodium_lib[crypto_secretstream_rekey](ls_state.state)
      end,

      [crypto_secretstream_init_push] = function(key)
        if not key then
          return error('requires 1 argument')
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format(
            'wrong key size, expected: %d',
            KEYBYTES))
        end

        local state = ffi.gc(clib.malloc(STATEBYTES),ls_crypto_secretstream_free)
        local header = char_array(HEADERBYTES)

        if tonumber(sodium_lib[crypto_secretstream_init_push](state,header,key)) == -1 then
          return error(string_format('%s error', crypto_secretstream_init_push))
        end

        local ls_state = setmetatable({
          state = state,
        },ls_crypto_secretstream_push_mt)

        local header_str = ffi_string(header,HEADERBYTES)
        sodium_lib.sodium_memzero(header,HEADERBYTES)

        return ls_state, header_str
      end,

      [crypto_secretstream_push] = function(ls_state, message, tag, ad)
        if not tag then
          return error('requires 3 arguments')
        end

        if getmetatable(ls_state) ~= ls_crypto_secretstream_push_mt then
          return error('invalid userdata')
        end

        local mlen = string_len(message)
        local adlen = 0
        if ad then
          adlen = string_len(ad)
        end
        local clen = ffi.new('unsigned long long[1]')

        local c = char_array(ABYTES + mlen)

        if tonumber(sodium_lib[crypto_secretstream_push](
          ls_state.state,c,clen,
          message,mlen,ad,adlen,tag)) == -1 then
          return error(string_format('%s error',crypto_secretstream_push))
        end

        local c_str = ffi_string(c,clen[0])
        sodium_lib.sodium_memzero(c,ABYTES + mlen)
        return c_str
      end,

      [crypto_secretstream_init_pull] = function(header, key)
        if not key then
          return error('requires 2 argument')
        end

        if string_len(header) ~= HEADERBYTES then
          return error(string_format(
            'wrong header size, expected: %d',
            HEADERBYTES))
        end

        if string_len(key) ~= KEYBYTES then
          return error(string_format(
            'wrong key size, expected: %d',
            KEYBYTES))
        end

        local state = ffi.gc(clib.malloc(STATEBYTES),ls_crypto_secretstream_free)

        if tonumber(sodium_lib[crypto_secretstream_init_pull](state,header,key)) == -1 then
          return nil, string_format('%s: invalid header',crypto_secretstream_init_pull)
        end

        local ls_state = setmetatable({
          state = state,
        },ls_crypto_secretstream_pull_mt)

        return ls_state
      end,

      [crypto_secretstream_pull] = function(ls_state, cipher, ad)
        if not cipher then
          return error('requires 2 arguments')
        end

        if getmetatable(ls_state) ~= ls_crypto_secretstream_pull_mt then
          return error('invalid userdata')
        end

        local clen = string_len(cipher)

        if clen < ABYTES then
          return error(string_format('invalid cipher length, expected at least: %d',
            ABYTES))
        end

        local adlen = 0
        if ad then
          adlen = string_len(ad)
        end
        local mlen = ffi.new('unsigned long long[1]')
        local tag = ffi.new('unsigned char[1]')

        local m = char_array(clen - ABYTES)

        if tonumber(sodium_lib[crypto_secretstream_pull](
          ls_state.state,m,mlen,tag,
          cipher,clen,ad,adlen)) == -1 then
          return nil, string_format('%s: invalid cipher',crypto_secretstream_pull)
        end

        local m_str = ffi_string(m,mlen[0])
        sodium_lib.sodium_memzero(m,clen - ABYTES)
        return m_str, tonumber(tag[0])
      end,
    }

    ls_crypto_secretstream_pull_methods.pull  = M[crypto_secretstream_pull]
    ls_crypto_secretstream_pull_methods.rekey = M[crypto_secretstream_rekey]

    local ls_push = M[crypto_secretstream_push]
    local ls_rekey = M[crypto_secretstream_rekey]

    ls_crypto_secretstream_push_methods.message = function(self, message, ad)
      if not message then
        return error('requires 2 parameters')
      end
      return ls_push(self,message,TAG_MESSAGE,ad)
    end

    ls_crypto_secretstream_push_methods.push = function(self, message, ad)
      if not message then
        return error('requires 2 parameters')
      end
      return ls_push(self,message,TAG_PUSH,ad)
    end

    ls_crypto_secretstream_push_methods.final = function(self, message, ad)
      if not message then
        return error('requires 2 parameters')
      end
      return ls_push(self,message,TAG_FINAL,ad)
    end

    ls_crypto_secretstream_push_methods.rekey = function(self, message, ad)
      if not message then
        if not self then
          return error('requires 1 parameter')
        end
        return ls_rekey(self)
      end
      return ls_push(self,message,TAG_REKEY,ad)
    end

    return M
  end

  local M = { }

  for _,basename in ipairs({
    'crypto_secretstream_xchacha20poly1305',
  }) do
    local m = ls_crypto_secretstream(basename)
    for k,v in pairs(m) do
      M[k] = v
    end
  end

  for k,v in pairs(constants) do
    M[k] = v
  end

  return M
end

