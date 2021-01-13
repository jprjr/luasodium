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
    local crypto_secretstream_init_push = string.format('%s_init_push',f)
    local KEYBYTES = string.format('%s_KEYBYTES',f)
    local HEADERBYTES = string.format('%s_HEADERBYTES',f)

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
  end

end)
