require('busted.runner')()

local mode = os.getenv('TESTMODE')
if not mode then
  mode = 'core'
end

local lib = require('luasodium.' .. mode)

local expected_tag = {
  36, 166, 137, 74, 84, 118, 157, 225,
  136, 104, 231, 95, 232, 156, 215, 110,
  24, 95, 206, 127, 136, 148, 76, 35,
  192, 230, 240, 71, 202, 197, 133, 26,
}

describe('crypto_auth', function()
  it('should be a library', function()
    assert(type(lib) == 'table')
  end)

  it('should throw errors', function()
    assert(pcall(lib.crypto_auth) == false)
    assert(pcall(lib.crypto_auth,1) == false)
    assert(pcall(lib.crypto_auth,1,2) == false)
    assert(pcall(lib.crypto_auth_verify) == false)
    assert(pcall(lib.crypto_auth_verify,1) == false)
    assert(pcall(lib.crypto_auth_verify,1,2) == false)
    assert(pcall(lib.crypto_auth_verify,1,2,3) == false)
    assert(pcall(lib.crypto_auth_verify,'','','') == false)
    assert(pcall(lib.crypto_auth_verify,string.rep('\0',lib.crypto_auth_BYTES),'','') == false)
  end)

  describe('zero-byte key tests', function()
    local key = string.rep('\0',lib.crypto_auth_KEYBYTES)
    it('should generate the correct authentication tag', function()
      local tag = lib.crypto_auth('a message',key)
      assert(string.len(tag) == lib.crypto_auth_BYTES)

      for j=1,string.len(tag) do
        assert(string.byte(tag,j) == expected_tag[j])
      end
    end)
  end)

  describe('random byte key tests', function()
    it('should generate a key', function()
      local key = lib.crypto_auth_keygen()
      assert(string.len(key) == lib.crypto_auth_KEYBYTES)
      local tag = lib.crypto_auth('a message',key)
      assert(string.len(tag) == lib.crypto_auth_BYTES)
      assert(lib.crypto_auth_verify(tag,'a message',key) == true)
      assert(lib.crypto_auth_verify(tag,'another message',key) == false)
    end)
  end)
end)



