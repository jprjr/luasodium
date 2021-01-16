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
local message_part1 = "a "
local message_part2 = "message"

local expected_results = {
  ['crypto_generichash'] = {
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['hash'] = {
       222, 138, 247, 43, 250, 183, 108, 164,
       211, 183, 184, 74, 16, 225, 220, 141,
       54, 255, 248, 112, 128, 90, 92, 231,
       18, 116, 215, 249, 128, 120, 79, 60,
    },
    ['hash_min'] = {
       96, 93, 246, 145, 136, 137, 179, 47,
       123, 183, 118, 163, 182, 82, 218, 32,
    },
    ['hash_max'] = {
       48, 195, 71, 1, 89, 111, 124, 167,
       22, 242, 90, 50, 240, 148, 125, 254,
       10, 132, 154, 237, 47, 138, 13, 23,
       43, 138, 108, 254, 92, 15, 70, 156,
       161, 116, 239, 91, 128, 0, 167, 154,
       227, 200, 193, 184, 38, 40, 66, 190,
       178, 88, 187, 7, 14, 24, 20, 169,
       138, 12, 121, 196, 83, 162, 36, 30,
    },
    ['hash_nokey'] = {
       194, 175, 171, 129, 133, 113, 16, 89,
       190, 255, 235, 83, 28, 242, 29, 173,
       136, 160, 125, 100, 113, 170, 194, 170,
       89, 19, 242, 67, 84, 188, 174, 27,
    },
    ['hash_nokey_min'] = {
       193, 170, 197, 68, 14, 239, 60, 28,
       107, 60, 82, 181, 230, 243, 14, 34,
    },
    ['hash_nokey_max'] = {
       176, 167, 161, 47, 176, 9, 67, 94,
       16, 245, 123, 255, 34, 144, 245, 70,
       141, 251, 213, 6, 61, 160, 17, 51,
       206, 84, 42, 175, 229, 8, 246, 169,
       17, 11, 97, 2, 3, 44, 99, 239,
       8, 14, 134, 117, 97, 75, 149, 71,
       169, 32, 185, 245, 248, 96, 53, 246,
       13, 49, 42, 246, 32, 18, 210, 135,
    },
  },
}

describe('library crypto_generichash', function()
  it('is a library', function()
    assert(type(lib) == 'table')
  end)

  it('has constants', function()
    assert(type(lib.crypto_generichash_KEYBYTES) == 'number')
  end)

  for _,f in ipairs({
    'crypto_generichash'
  }) do
    local crypto_generichash_keygen = string.format('%s_keygen',f)
    local crypto_generichash = string.format('%s',f)
    local crypto_generichash_init = string.format('%s_init',f)
    local crypto_generichash_update = string.format('%s_update',f)
    local crypto_generichash_final = string.format('%s_final',f)

    local KEYBYTES = string.format('%s_KEYBYTES',f)
    local KEYBYTES_MIN = string.format('%s_KEYBYTES_MIN',f)
    local KEYBYTES_MAX = string.format('%s_KEYBYTES_MAX',f)
    local BYTES = string.format('%s_KEYBYTES',f)
    local BYTES_MIN = string.format('%s_KEYBYTES_MIN',f)
    local BYTES_MAX = string.format('%s_KEYBYTES_MAX',f)

    describe('function ' .. crypto_generichash_keygen, function()
      it('should return a random key', function()
        assert(string.len(lib[crypto_generichash_keygen]()) ==
          lib[KEYBYTES])
      end)
    end)

    describe('function ' .. crypto_generichash, function()
      it('should error on invalid calls', function()
        assert(pcall(lib[crypto_generichash]) == false)
        assert(pcall(lib[crypto_generichash],'',string.rep('\0',lib[KEYBYTES_MIN] - 1)) == false)
        assert(pcall(lib[crypto_generichash],'',string.rep('\0',lib[KEYBYTES_MAX] + 1)) == false)
        assert(pcall(lib[crypto_generichash],'',string.rep('\0',lib[KEYBYTES]),lib[BYTES_MIN]-1) == false)
        assert(pcall(lib[crypto_generichash],'',string.rep('\0',lib[KEYBYTES]),lib[BYTES_MAX]+1) == false)
      end)

      it('should return correct results for keyless calls', function()
        local hash_nokey = tbl_to_str(expected_results[f].hash_nokey)
        local hash_nokey_min = tbl_to_str(expected_results[f].hash_nokey_min)
        local hash_nokey_max = tbl_to_str(expected_results[f].hash_nokey_max)

        assert(string.len(lib[crypto_generichash](message)) == lib[BYTES])
        assert(lib[crypto_generichash](message) == hash_nokey)
        assert(lib[crypto_generichash](message,nil,lib[BYTES_MIN]) == hash_nokey_min)
        assert(lib[crypto_generichash](message,nil,lib[BYTES_MAX]) == hash_nokey_max)
      end)

      it('should return correct results for a keyed call', function()
        local key      = tbl_to_str(expected_results[f].key)
        local hash     = tbl_to_str(expected_results[f].hash)
        local hash_min = tbl_to_str(expected_results[f].hash_min)
        local hash_max = tbl_to_str(expected_results[f].hash_max)

        assert(string.len(lib[crypto_generichash](message),key) == lib[BYTES])
        assert(lib[crypto_generichash](message,key) == hash)
        assert(lib[crypto_generichash](message,key,lib[BYTES_MIN]) == hash_min)
        assert(lib[crypto_generichash](message,key,lib[BYTES_MAX]) == hash_max)
      end)
    end)

    describe('function ' .. crypto_generichash_init, function()
      it('should return a state', function()
        assert(type(lib[crypto_generichash_init]()) == 'table')
      end)

      it('should return a state with a key', function()
        local key      = tbl_to_str(expected_results[f].key)
        assert(type(lib[crypto_generichash_init](key)) == 'table')
      end)

      it('should return a state with a key and a size', function()
        local key      = tbl_to_str(expected_results[f].key)
        assert(type(lib[crypto_generichash_init](key,lib[BYTES])) == 'table')
      end)

      it('should reject invalid hash sizes', function()
        assert(pcall(lib[crypto_generichash_init],nil,lib[BYTES_MIN]-1) == false)
        assert(pcall(lib[crypto_generichash_init],nil,lib[BYTES_MAX]+1) == false)
      end)

      it('should reject invalid key sizes', function()
        assert(pcall(lib[crypto_generichash_init],string.rep('\0',lib[KEYBYTES_MIN]-1)) == false)
        assert(pcall(lib[crypto_generichash_init],string.rep('\0',lib[KEYBYTES_MAX]+1)) == false)
      end)
    end)

    describe('function ' .. crypto_generichash_update, function()
      it('should reject invalid calls', function()
        local state = lib[crypto_generichash_init]()
        assert(pcall(lib[crypto_generichash_update]) == false)
        assert(pcall(lib[crypto_generichash_update],'','') == false)
        assert(pcall(lib[crypto_generichash_update],state,nil) == false)
      end)

      it('should accept updates', function()
        local state = lib[crypto_generichash_init]()
        assert(lib[crypto_generichash_update](state,message) == true)
      end)
    end)

    describe('function ' .. crypto_generichash_final, function()
      it('should reject invalid calls', function()
        assert(pcall(lib[crypto_generichash_final]) == false)
        assert(pcall(lib[crypto_generichash_final],'','') == false)
      end)

      it('should return a hash made without a key or given a size', function()
        local state = lib[crypto_generichash_init]()
        local hash = tbl_to_str(expected_results[f].hash_nokey)
        lib[crypto_generichash_update](state,message)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made without a key, minimum size', function()
        local state = lib[crypto_generichash_init](nil,lib[BYTES_MIN])
        local hash = tbl_to_str(expected_results[f].hash_nokey_min)
        lib[crypto_generichash_update](state,message)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made without a key, maximum size', function()
        local state = lib[crypto_generichash_init](nil,lib[BYTES_MAX])
        local hash = tbl_to_str(expected_results[f].hash_nokey_max)
        lib[crypto_generichash_update](state,message)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made without a key, maximum size, 2', function()
        local state = lib[crypto_generichash_init](nil,lib[BYTES_MAX])
        local hash = tbl_to_str(expected_results[f].hash_nokey_max)
        lib[crypto_generichash_update](state,message)
        assert(lib[crypto_generichash_final](state,lib[BYTES_MAX]) == hash)
      end)

      it('should return a hash made with a key, without a size', function()
        local key      = tbl_to_str(expected_results[f].key)
        local state = lib[crypto_generichash_init](key)
        local hash = tbl_to_str(expected_results[f].hash)
        lib[crypto_generichash_update](state,message)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made with a key, minimum size', function()
        local key      = tbl_to_str(expected_results[f].key)
        local state = lib[crypto_generichash_init](key,lib[BYTES_MIN])
        local hash = tbl_to_str(expected_results[f].hash_min)
        lib[crypto_generichash_update](state,message)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made with a key, maximum size', function()
        local key      = tbl_to_str(expected_results[f].key)
        local state = lib[crypto_generichash_init](key,lib[BYTES_MAX])
        local hash = tbl_to_str(expected_results[f].hash_max)
        lib[crypto_generichash_update](state,message)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made with a key, maximum size, 2', function()
        local key      = tbl_to_str(expected_results[f].key)
        local state = lib[crypto_generichash_init](key,lib[BYTES_MAX])
        local hash = tbl_to_str(expected_results[f].hash_max)
        lib[crypto_generichash_update](state,message)
        assert(lib[crypto_generichash_final](state,lib[BYTES_MAX]) == hash)
      end)

      it('should support object-oriented methods', function()
        local state = lib[crypto_generichash_init]()
        local hash = tbl_to_str(expected_results[f].hash_nokey)
        state:update(message)
        assert(state:final() == hash)
      end)

      it('should return a hash made without a key or given a size, multiple parts', function()
        local state = lib[crypto_generichash_init]()
        local hash = tbl_to_str(expected_results[f].hash_nokey)
        lib[crypto_generichash_update](state,message_part1)
        lib[crypto_generichash_update](state,message_part2)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made without a key, minimum size, multiple parts', function()
        local state = lib[crypto_generichash_init](nil,lib[BYTES_MIN])
        local hash = tbl_to_str(expected_results[f].hash_nokey_min)
        lib[crypto_generichash_update](state,message_part1)
        lib[crypto_generichash_update](state,message_part2)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made without a key, maximum size, multiple parts', function()
        local state = lib[crypto_generichash_init](nil,lib[BYTES_MAX])
        local hash = tbl_to_str(expected_results[f].hash_nokey_max)
        lib[crypto_generichash_update](state,message_part1)
        lib[crypto_generichash_update](state,message_part2)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made without a key, maximum size, 2, multiple parts', function()
        local state = lib[crypto_generichash_init](nil,lib[BYTES_MAX])
        local hash = tbl_to_str(expected_results[f].hash_nokey_max)
        lib[crypto_generichash_update](state,message_part1)
        lib[crypto_generichash_update](state,message_part2)
        assert(lib[crypto_generichash_final](state,lib[BYTES_MAX]) == hash)
      end)

      it('should return a hash made with a key, without a size, multiple parts', function()
        local key      = tbl_to_str(expected_results[f].key)
        local state = lib[crypto_generichash_init](key)
        local hash = tbl_to_str(expected_results[f].hash)
        lib[crypto_generichash_update](state,message_part1)
        lib[crypto_generichash_update](state,message_part2)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made with a key, minimum size, multiple parts', function()
        local key      = tbl_to_str(expected_results[f].key)
        local state = lib[crypto_generichash_init](key,lib[BYTES_MIN])
        local hash = tbl_to_str(expected_results[f].hash_min)
        lib[crypto_generichash_update](state,message_part1)
        lib[crypto_generichash_update](state,message_part2)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made with a key, maximum size, multiple parts', function()
        local key      = tbl_to_str(expected_results[f].key)
        local state = lib[crypto_generichash_init](key,lib[BYTES_MAX])
        local hash = tbl_to_str(expected_results[f].hash_max)
        lib[crypto_generichash_update](state,message_part1)
        lib[crypto_generichash_update](state,message_part2)
        assert(lib[crypto_generichash_final](state) == hash)
      end)

      it('should return a hash made with a key, maximum size, 2, multiple parts', function()
        local key      = tbl_to_str(expected_results[f].key)
        local state = lib[crypto_generichash_init](key,lib[BYTES_MAX])
        local hash = tbl_to_str(expected_results[f].hash_max)
        lib[crypto_generichash_update](state,message_part1)
        lib[crypto_generichash_update](state,message_part2)
        assert(lib[crypto_generichash_final](state,lib[BYTES_MAX]) == hash)
      end)

      it('should support object-oriented methods, multiple parts', function()
        local state = lib[crypto_generichash_init]()
        local hash = tbl_to_str(expected_results[f].hash_nokey)
        state:update(message_part1)
        state:update(message_part2)
        assert(state:final() == hash)
      end)

    end)
  end
end)
