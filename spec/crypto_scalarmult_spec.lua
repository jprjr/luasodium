require('busted.runner')()

local mode = os.getenv('TESTMODE')
if not mode then
  mode = 'core'
end

local lib = require('luasodium.' .. mode)

describe('crypto_scalarmult', function()
  it('should work', function()
    local n = string.rep('\0',lib.crypto_scalarmult_SCALARBYTES)
    local q = lib.crypto_scalarmult_base(n)
    assert(string.len(q) == lib.crypto_scalarmult_BYTES)
    local p = lib.crypto_scalarmult(n,q)
  end)

  it('should reject invalid input', function()
    assert(pcall(lib.crypto_scalarmult) == false)
    assert(pcall(lib.crypto_scalarmult_base) == false)

    assert(pcall(lib.crypto_scalarmult,'','') == false)
    assert(pcall(lib.crypto_scalarmult_base,'') == false)

    assert(pcall(lib.crypto_scalarmult,string.rep('\0',lib.crypto_scalarmult_SCALARBYTES),'') == false)
  end)
end)

