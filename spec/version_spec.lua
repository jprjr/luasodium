require('busted.runner')()

local mode = os.getenv('TESTMODE')
if not mode then
  mode = 'core'
end

local lib = require('luasodium.' .. mode)

describe('version', function()
  it('should work', function()
    assert(type(lib._VERSION) == 'string')
    assert(type(lib.sodium_version_string()) == 'string')
    assert(type(lib.sodium_library_version_major()) == 'number')
    assert(type(lib.sodium_library_version_minor()) == 'number')
    assert(type(lib.sodium_library_minimal()) == 'number')
  end)
end)

