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

describe('crypto_hash', function()
  it('should generate default hashes', function()
    local hash = lib.crypto_hash('a message')
    assert(string.len(hash) == lib.crypto_hash_BYTES)
    assert(pcall(lib.crypto_hash) == false)
  end)

  it('should generate sha256 hashes', function()
    local hash = lib.crypto_hash_sha256('a message')
    assert(string.len(hash) == lib.crypto_hash_sha256_BYTES)
    assert(pcall(lib.crypto_hash_sha256) == false)
  end)

  it('should generate sha512 hashes', function()
    local hash = lib.crypto_hash_sha512('a message')
    assert(string.len(hash) == lib.crypto_hash_sha512_BYTES)
    assert(pcall(lib.crypto_hash_sha512) == false)
  end)

  it('should generate multipart sha256 hashes', function()
    local state = lib.crypto_hash_sha256_init()
    assert(lib.crypto_hash_sha256_update(state,'a ') == true)
    assert(lib.crypto_hash_sha256_update(state,'message') == true)
    assert(lib.crypto_hash_sha256_final(state) == lib.crypto_hash_sha256('a message'))
  end)

  it('should generate multipart sha512 hashes', function()
    local state = lib.crypto_hash_sha512_init()
    assert(lib.crypto_hash_sha512_update(state,'a ') == true)
    assert(lib.crypto_hash_sha512_update(state,'message') == true)
    assert(lib.crypto_hash_sha512_final(state) == lib.crypto_hash_sha512('a message'))
  end)

  it('should support multipart, object-oriented sha256 hashes', function()
    local state = lib.crypto_hash_sha256_init()
    assert(state:update('a ') == true)
    assert(state:update('message') == true)
    assert(state:final() == lib.crypto_hash_sha256('a message'))
  end)

  it('should support multipart, object-oriented sha512 hashes', function()
    local state = lib.crypto_hash_sha512_init()
    assert(state:update('a ') == true)
    assert(state:update('message') == true)
    assert(state:final() == lib.crypto_hash_sha512('a message'))
  end)

  it('final sha256 empty message', function()
    local state = lib.crypto_hash_sha256_init()
    assert(pcall(state.update) == false)
    assert(pcall(state.update,state) == false)
    assert(pcall(state.update,'garbage') == false)
    assert(pcall(state.update,'garbage','garbage') == false)
    assert(state:update('') == true)
    assert(pcall(state.final,state) == true)
  end)

  it('final sha512 empty message', function()
    local state = lib.crypto_hash_sha512_init()
    assert(pcall(state.update) == false)
    assert(pcall(state.update,state) == false)
    assert(pcall(state.update,'garbage') == false)
    assert(pcall(state.update,'garbage','garbage') == false)
    assert(state:update('') == true)
    assert(pcall(state.final,state) == true)
  end)

  it('final sha256 no data', function()
    local state = lib.crypto_hash_sha256_init()
    assert(pcall(state.final) == false)
    assert(pcall(state.final,'garbage') == false)
    assert(pcall(state.final,state) == true)
  end)

  it('final sha512 no data', function()
    local state = lib.crypto_hash_sha512_init()
    assert(pcall(state.final) == false)
    assert(pcall(state.final,'garbage') == false)
    assert(pcall(state.final,state) == true)
  end)

end)

