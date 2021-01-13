if pcall(require,'busted.runner') then
  require('busted.runner')()
else
  describe = function(_,cb) -- luacheck: ignore
    cb()
  end
  it = function(_,cb) -- luacheck: ignore
    cb()
  end
end

local mode = os.getenv('TESTMODE')
if not mode then
  mode = 'core'
end

local lib = require('luasodium.' .. mode)

-- no expected_results table in this module, we'll just
-- have to perform encryption/decryption and check it's
-- the same results

describe('library crypto_secretstream', function()
  it('is a library', function()
    assert(type(lib) == 'table')
  end)

  it('has constants', function()
    assert(type(lib.crypto_secretstream_xchacha20poly1305_ABYTES) == 'number')
    assert(type(lib.crypto_secretstream_xchacha20poly1305_HEADERBYTES) == 'number')
    assert(type(lib.crypto_secretstream_xchacha20poly1305_KEYBYTES) == 'number')
    assert(type(lib.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX) == 'number')
    assert(type(lib.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) == 'number')
    assert(type(lib.crypto_secretstream_xchacha20poly1305_TAG_PUSH) == 'number')
    assert(type(lib.crypto_secretstream_xchacha20poly1305_TAG_REKEY) == 'number')
    assert(type(lib.crypto_secretstream_xchacha20poly1305_TAG_FINAL) == 'number')
  end)

  for _,f in ipairs({
    'crypto_secretstream_xchacha20poly1305'
  }) do

    local crypto_secretstream_keygen = string.format('%s_keygen',f)
    local crypto_secretstream_rekey = string.format('%s_rekey',f)

    local crypto_secretstream_init_push = string.format('%s_init_push',f)
    local crypto_secretstream_push = string.format('%s_push',f)

    local crypto_secretstream_init_pull = string.format('%s_init_pull',f)
    local crypto_secretstream_pull = string.format('%s_pull',f)

    local KEYBYTES = string.format('%s_KEYBYTES',f)
    local ABYTES = string.format('%s_ABYTES',f)
    local HEADERBYTES = string.format('%s_HEADERBYTES',f)
    local TAG_MESSAGE = string.format('%s_TAG_MESSAGE',f)
    local TAG_PUSH = string.format('%s_TAG_PUSH',f)
    local TAG_REKEY = string.format('%s_TAG_REKEY',f)
    local TAG_FINAL = string.format('%s_TAG_FINAL',f)


    describe('function ' .. crypto_secretstream_keygen, function()
      it('should return a random key', function()
        assert(string.len(lib[crypto_secretstream_keygen]()) ==
          lib[KEYBYTES])
      end)
    end)

    describe('function ' .. crypto_secretstream_init_push, function()
      it('should error on invalid calls', function()
        assert(pcall(lib[crypto_secretstream_init_push]) == false)
        assert(pcall(lib[crypto_secretstream_init_push],'') == false)
      end)

      it('should return an object given a valid key', function()
        local key = lib[crypto_secretstream_keygen]()
        local state, header = lib[crypto_secretstream_init_push](key)
        assert(type(state) == 'table' or type(state) == 'userdata')
        assert(type(header) == 'string')
        assert(string.len(header) == lib[HEADERBYTES])
      end)
    end)

    describe('function ' .. crypto_secretstream_push, function()
      local key = lib[crypto_secretstream_keygen]()
      local state = lib[crypto_secretstream_init_push](key)
      it('should reject invalid calls', function()
        assert(pcall(lib[crypto_secretstream_push]) == false)
        assert(pcall(lib[crypto_secretstream_push],'','','') == false)
        assert(pcall(lib[crypto_secretstream_push],state,'','') == false)
      end)

      it('should encrypt a message', function()
        local c = lib[crypto_secretstream_push](state,'hello',lib.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
        assert(string.len(c) > lib[ABYTES])
        assert(string.len(c) <= lib[ABYTES] + 5)
      end)

      it('should support :message', function()
        local c = state:message('hello')
        assert(string.len(c) > lib[ABYTES])
        assert(string.len(c) <= lib[ABYTES] + 5)
        local d = state:message('hello','extrastuff')
        assert(string.len(d) > lib[ABYTES])
        assert(string.len(d) <= lib[ABYTES] + 5)
      end)
    end)

    describe('function ' .. crypto_secretstream_init_pull, function()
      it('should error on invalid calls', function()
        assert(pcall(lib[crypto_secretstream_init_pull]) == false)
        assert(pcall(lib[crypto_secretstream_init_pull],'','') == false)
        assert(pcall(lib[crypto_secretstream_init_pull],string.rep('\0',lib[HEADERBYTES]),'') == false)
      end)

      it('should return an object given a valid key and header', function()
        local key = lib[crypto_secretstream_keygen]()
        local _, header = lib[crypto_secretstream_init_push](key)
        local state = lib[crypto_secretstream_init_pull](header,key)
        assert(type(state) == 'table' or type(state) == 'userdata')
      end)
    end)

    describe('function ' .. crypto_secretstream_pull, function()
      local key = lib[crypto_secretstream_keygen]()
      local estate, header = lib[crypto_secretstream_init_push](key)

      local message1 = estate:message('message1')
      local message2 = estate:rekey('message2')
      local message3 = estate:push('message3')
      local message4 = estate:message('message4')
      lib[crypto_secretstream_rekey](estate)
      local message5 = estate:message('message5')
      assert(estate:rekey() == nil)
      local message6 = estate:final('message6')
      it('should error on invalid calls', function()
        local state = lib[crypto_secretstream_init_pull](header,key)
        assert(pcall(lib[crypto_secretstream_pull]) == false)
        assert(pcall(lib[crypto_secretstream_pull],'','','') == false)
        assert(pcall(lib[crypto_secretstream_pull],state,'','') == false)
      end)

      it('should decode encrypted messages', function()
        local state = lib[crypto_secretstream_init_pull](header,key)
        local m, tag

        m, tag = lib[crypto_secretstream_pull](state,message1)
        assert(m == 'message1')
        assert(tag == lib[TAG_MESSAGE])

        m, tag = lib[crypto_secretstream_pull](state,message2)
        assert(m == 'message2')
        assert(tag == lib[TAG_REKEY])

        m, tag = lib[crypto_secretstream_pull](state,message3)
        assert(m == 'message3')
        assert(tag == lib[TAG_PUSH])

        m, tag = lib[crypto_secretstream_pull](state,message4)
        assert(m == 'message4')
        assert(tag == lib[TAG_MESSAGE])

        lib[crypto_secretstream_rekey](state)

        m, tag = lib[crypto_secretstream_pull](state,message5)
        assert(m == 'message5')
        assert(tag == lib[TAG_MESSAGE])

        lib[crypto_secretstream_rekey](state)

        m, tag = lib[crypto_secretstream_pull](state,message6)
        assert(m == 'message6')
        assert(tag == lib[TAG_FINAL])

      end)

      it('should decode encrypted messages, object-oriented', function()
        local state = lib[crypto_secretstream_init_pull](header,key)
        local m, tag

        m, tag = state:pull(message1)
        assert(m == 'message1')
        assert(tag == lib[TAG_MESSAGE])

        m, tag = state:pull(message2)
        assert(m == 'message2')
        assert(tag == lib[TAG_REKEY])

        m, tag = state:pull(message3)
        assert(m == 'message3')
        assert(tag == lib[TAG_PUSH])

        m, tag = state:pull(message4)
        assert(m == 'message4')
        assert(tag == lib[TAG_MESSAGE])

        state:rekey()

        m, tag = state:pull(message5)
        assert(m == 'message5')
        assert(tag == lib[TAG_MESSAGE])

        state:rekey()

        m, tag = state:pull(message6)
        assert(m == 'message6')
        assert(tag == lib[TAG_FINAL])
      end)

    end)
  end

end)
