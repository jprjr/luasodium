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

local function tbl_to_str(tbl)
  local c = {}
  for i=1,#tbl do
    c[i] = string.char(tbl[i])
  end
  return table.concat(c,'')
end

local message = "a message"

local expected_results = {
  ['crypto_hash'] = {
    ['hash'] = {
       53, 214, 85, 225, 199, 186, 132, 25,
       254, 176, 81, 13, 255, 201, 83, 195,
       110, 135, 181, 195, 93, 230, 167, 208,
       50, 17, 137, 122, 13, 78, 53, 37,
       21, 98, 98, 95, 183, 31, 186, 41,
       234, 209, 69, 59, 242, 134, 93, 0,
       255, 102, 143, 15, 152, 3, 24, 54,
       123, 35, 3, 248, 28, 58, 122, 38,
    },
  },
  ['crypto_hash_sha256'] = {
    ['hash'] = {
       245, 60, 9, 202, 57, 113, 122, 69,
       198, 45, 154, 202, 143, 129, 19, 237,
       219, 253, 95, 129, 220, 171, 11, 51,
       177, 193, 131, 64, 117, 34, 94, 104,
    },
  },
  ['crypto_hash_sha512'] = {
    ['hash'] = {
       53, 214, 85, 225, 199, 186, 132, 25,
       254, 176, 81, 13, 255, 201, 83, 195,
       110, 135, 181, 195, 93, 230, 167, 208,
       50, 17, 137, 122, 13, 78, 53, 37,
       21, 98, 98, 95, 183, 31, 186, 41,
       234, 209, 69, 59, 242, 134, 93, 0,
       255, 102, 143, 15, 152, 3, 24, 54,
       123, 35, 3, 248, 28, 58, 122, 38,
    },
  },
}

local expected_hash = tbl_to_str(expected_results['crypto_hash'].hash)
local expected_hash_sha256 = tbl_to_str(expected_results['crypto_hash_sha256'].hash)
local expected_hash_sha512 = tbl_to_str(expected_results['crypto_hash_sha512'].hash)

describe('crypto_hash', function()
  it('should generate default hashes', function()
    local hash = lib.crypto_hash('a message')
    assert(string.len(hash) == lib.crypto_hash_BYTES)
    assert(pcall(lib.crypto_hash) == false)
    assert(hash == expected_hash)
  end)

  it('should generate sha256 hashes', function()
    local hash = lib.crypto_hash_sha256('a message')
    assert(string.len(hash) == lib.crypto_hash_sha256_BYTES)
    assert(pcall(lib.crypto_hash_sha256) == false)
    assert(hash == expected_hash_sha256)
  end)

  it('should generate sha512 hashes', function()
    local hash = lib.crypto_hash_sha512('a message')
    assert(string.len(hash) == lib.crypto_hash_sha512_BYTES)
    assert(pcall(lib.crypto_hash_sha512) == false)
    assert(hash == expected_hash_sha512)
  end)

  it('should generate multipart sha256 hashes', function()
    local state = lib.crypto_hash_sha256_init()
    assert(lib.crypto_hash_sha256_update(state,'a ') == true)
    assert(lib.crypto_hash_sha256_update(state,'message') == true)
    assert(lib.crypto_hash_sha256_final(state) == expected_hash_sha256)
  end)

  it('should generate multipart sha512 hashes', function()
    local state = lib.crypto_hash_sha512_init()
    assert(lib.crypto_hash_sha512_update(state,'a ') == true)
    assert(lib.crypto_hash_sha512_update(state,'message') == true)
    assert(lib.crypto_hash_sha512_final(state) == expected_hash_sha512)
  end)

  it('should support multipart, object-oriented sha256 hashes', function()
    local state = lib.crypto_hash_sha256_init()
    assert(state:update('a ') == true)
    assert(state:update('message') == true)
    assert(state:final() == expected_hash_sha256)
  end)

  it('should support multipart, object-oriented sha512 hashes', function()
    local state = lib.crypto_hash_sha512_init()
    assert(state:update('a ') == true)
    assert(state:update('message') == true)
    assert(state:final() == expected_hash_sha512)
  end)

  it('some sha256 invalid call tests', function()
    local state = lib.crypto_hash_sha256_init()
    assert(pcall(state.update) == false)
    assert(pcall(state.update,state) == false)
    assert(pcall(state.update,'garbage') == false)
    assert(pcall(state.update,'garbage','garbage') == false)
    assert(state:update('') == true)
    assert(pcall(state.final,state) == true)
  end)

  it('some sha512 invalid call tests', function()
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

