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

local message = 'a message'

local expected_results = {
  ['crypto_shorthash'] = {
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
    },
    ['hash'] = {
       189, 212, 159, 244, 184, 161, 77, 130,
    },
  },
  ['crypto_shorthash_siphashx24'] = {
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
    },
    ['hash'] = {
       131, 228, 238, 99, 5, 150, 124, 194,
       186, 21, 232, 73, 133, 200, 22, 250,
    },
  },
}

describe('library crypto_shorthash', function()
  it('should be a library', function()
    assert(type(lib) == 'table')
  end)

  it('should have constants', function()
    assert(type(lib.crypto_shorthash_KEYBYTES) == 'number')
    assert(type(lib.crypto_shorthash_BYTES) == 'number')
    assert(type(lib.crypto_shorthash_siphashx24_KEYBYTES) == 'number')
    assert(type(lib.crypto_shorthash_siphashx24_BYTES) == 'number')
  end)

  describe('function crypto_shorthash_keygen', function()
    it('should produce a key', function()
      assert(string.len(lib.crypto_shorthash_keygen()) ==
        lib.crypto_shorthash_KEYBYTES)
    end)
  end)

  for _,f in ipairs({
    'crypto_shorthash',
    'crypto_shorthash_siphashx24',
  }) do
    local crypto_shorthash = string.format('%s',f)

    local BYTES = lib[string.format('%s_BYTES',f)]
    local KEYBYTES = lib[string.format('%s_KEYBYTES',f)]

    describe('function ' .. crypto_shorthash, function()
      it('should error on invalid input', function()
        assert(pcall(lib[crypto_shorthash]) == false)
        assert(pcall(lib[crypto_shorthash],'','') == false)
      end)

      it('should produce a known hash', function()
        local key = tbl_to_str(expected_results[f].key)
        local hash = tbl_to_str(expected_results[f].hash)
        assert(string.len(key) == KEYBYTES)
        assert(string.len(hash) == BYTES)
        assert(lib[crypto_shorthash](message,key) == hash)
      end)
    end)

  end
end)
