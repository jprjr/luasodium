require('busted.runner')()

local mode = os.getenv('TESTMODE')
if not mode then
  mode = 'core'
end

local lib = require('luasodium.' .. mode)

local expected_str = {
  186, 110, 38, 223, 75, 46, 162, 207,
  100, 210, 211, 99, 102, 35, 181, 244,
}

describe('crypto_stream', function()
  local nonce = string.rep('\0',lib.crypto_stream_NONCEBYTES)
  local key = string.rep('\0',lib.crypto_stream_KEYBYTES)


  it('should work', function()
    local str = lib.crypto_stream(16,nonce,key)
    assert(string.len(str) == 16)
    for i=1,16 do
      assert(expected_str[i] == string.byte(str,i))
    end

    local x = lib.crypto_stream_xor('message',nonce,key)
    assert(string.len(x) == string.len('message'))
    assert(lib.crypto_stream_xor(x,nonce,key) == 'message')

    local k = lib.crypto_stream_keygen()
    assert(string.len(k) == lib.crypto_stream_KEYBYTES)
  end)

  it('should reject bad calls', function()
    assert(pcall(lib.crypto_stream) == false)
    assert(pcall(lib.crypto_stream,0,'','') == false)
    assert(pcall(lib.crypto_stream,0,string.rep('\0',lib.crypto_stream_NONCEBYTES),'') == false)
    assert(pcall(lib.crypto_stream_xor) == false)
    assert(pcall(lib.crypto_stream_xor,'','','') == false)
    assert(pcall(lib.crypto_stream_xor,'',string.rep('\0',lib.crypto_stream_NONCEBYTES),'') == false)
  end)
end)
