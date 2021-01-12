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

local message = 'hello'

local expected_results = {
  ['crypto_stream'] = {
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['cipher'] = {
       117, 32, 29, 14, 104,
    },
    ['stream'] = {
       29, 69, 113, 98, 7, 197, 74, 154,
       206, 229, 243, 230, 111, 205, 231, 24,
       218, 137, 195, 112, 2, 246, 68, 49,
       102, 141, 163, 132, 237, 123, 231, 233,
    },
  },
  ['crypto_stream_xsalsa20'] = {
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['cipher'] = {
       117, 32, 29, 14, 104,
    },
    ['stream'] = {
       29, 69, 113, 98, 7, 197, 74, 154,
       206, 229, 243, 230, 111, 205, 231, 24,
       218, 137, 195, 112, 2, 246, 68, 49,
       102, 141, 163, 132, 237, 123, 231, 233,
    },
  },
  ['crypto_stream_salsa20'] = {
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['cipher'] = {
       229, 77, 208, 65, 122,
    },
    ['stream'] = {
       141, 40, 188, 45, 21, 54, 150, 25,
       179, 255, 49, 128, 123, 202, 174, 38,
       124, 1, 32, 43, 11, 154, 162, 130,
       221, 100, 244, 229, 254, 57, 253, 250,
    },
  },
  ['crypto_stream_salsa2012'] = {
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['cipher'] = {
       255, 236, 190, 192, 226,
    },
    ['stream'] = {
       151, 137, 210, 172, 141, 216, 72, 88,
       197, 53, 11, 180, 34, 100, 228, 44,
       71, 117, 118, 157, 249, 248, 69, 89,
       229, 144, 163, 89, 99, 72, 123, 229,
    },
  },
}

describe('library crypto_stream', function()
  it('should be a library', function()
    assert(type(lib) == 'table')
  end)

  it('should have constants', function()
    assert(type(lib.crypto_stream_NONCEBYTES) == 'number')
    assert(type(lib.crypto_stream_KEYBYTES) == 'number')
  end)

  for _,f in ipairs({
    'crypto_stream',
    'crypto_stream_xsalsa20',
  }) do
    local crypto_stream = string.format('%s',f)
    local crypto_stream_xor = string.format('%s_xor',f)
    local crypto_stream_keygen = string.format('%s_keygen',f)

    local NONCEBYTES = lib[string.format('%s_NONCEBYTES',f)]
    local KEYBYTES = lib[string.format('%s_KEYBYTES',f)]

    local nonce = string.rep('\0',NONCEBYTES)
    local key = tbl_to_str(expected_results[f].key)
    local cipher = tbl_to_str(expected_results[f].cipher)
    local stream = tbl_to_str(expected_results[f].stream)

    describe('function ' .. crypto_stream, function()
      it('should reject bad calls', function()
        assert(pcall(lib[crypto_stream]) == false)
        assert(pcall(lib[crypto_stream],0,'','') == false)
        assert(pcall(lib[crypto_stream],0,nonce,'') == false)
      end)

      it('should make a stream', function()
        assert(lib[crypto_stream](32,nonce,key) == stream)
      end)
    end)

    describe('function ' .. crypto_stream_xor, function()
      it('should reject bad calls', function()
        assert(pcall(lib[crypto_stream_xor]) == false)
        assert(pcall(lib[crypto_stream_xor],'','','') == false)
        assert(pcall(lib[crypto_stream_xor],'',nonce,'') == false)
      end)

      it('should produce a known xor', function()
        assert(lib[crypto_stream_xor](message,nonce,key) == cipher)
      end)
    end)

    describe('function ' .. crypto_stream_keygen, function()
      it('should generate a key', function()
        assert(string.len(lib[crypto_stream_keygen]()) == KEYBYTES)
      end)
    end)
  end
end)
