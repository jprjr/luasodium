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
  ['crypto_auth'] = {
    ['mac'] = {
       1, 54, 95, 186, 201, 138, 132, 61,
       46, 125, 81, 247, 94, 161, 115, 6,
       205, 216, 176, 18, 139, 118, 46, 181,
       109, 237, 102, 0, 101, 111, 114, 165,
    },
  },
  ['crypto_auth_hmacsha256'] = {
    ['mac'] = {
       67, 82, 178, 110, 51, 254, 13, 118,
       154, 137, 34, 166, 186, 41, 0, 65,
       9, 240, 22, 136, 226, 106, 204, 158,
       108, 179, 71, 229, 165, 175, 196, 218,
    },
  },
  ['crypto_auth_hmacsha512256'] = {
    ['mac'] = {
       1, 54, 95, 186, 201, 138, 132, 61,
       46, 125, 81, 247, 94, 161, 115, 6,
       205, 216, 176, 18, 139, 118, 46, 181,
       109, 237, 102, 0, 101, 111, 114, 165,
    },
  },
  ['crypto_auth_hmacsha512'] = {
    ['mac'] = {
       1, 54, 95, 186, 201, 138, 132, 61,
       46, 125, 81, 247, 94, 161, 115, 6,
       205, 216, 176, 18, 139, 118, 46, 181,
       109, 237, 102, 0, 101, 111, 114, 165,
       157, 20, 137, 146, 105, 16, 234, 95,
       168, 18, 88, 231, 36, 142, 104, 61,
       235, 197, 142, 76, 79, 8, 244, 53,
       33, 179, 254, 122, 77, 44, 10, 123,
    },
  },
}


describe('crypto_auth', function()
  it('should be a library', function()
    assert(type(lib) == 'table')
  end)

  it('should have constants', function()
    assert(type(lib.crypto_auth_BYTES) == 'number')
    assert(type(lib.crypto_auth_KEYBYTES) == 'number')
    assert(type(lib.crypto_auth_hmacsha256_BYTES) == 'number')
    assert(type(lib.crypto_auth_hmacsha256_KEYBYTES) == 'number')
    assert(type(lib.crypto_auth_hmacsha512256_BYTES) == 'number')
    assert(type(lib.crypto_auth_hmacsha512256_KEYBYTES) == 'number')
    assert(type(lib.crypto_auth_hmacsha512_BYTES) == 'number')
    assert(type(lib.crypto_auth_hmacsha512_KEYBYTES) == 'number')
  end)

  for _,f in ipairs({
    'crypto_auth',
    'crypto_auth_hmacsha256',
    'crypto_auth_hmacsha512256',
    'crypto_auth_hmacsha512',
  }) do
    local crypto_auth = string.format('%s',f)
    local crypto_auth_keygen = string.format('%s_keygen',f)
    local crypto_auth_verify = string.format('%s_verify',f)
    local crypto_auth_KEYBYTES = string.format('%s_KEYBYTES',f)
    local crypto_auth_BYTES = string.format('%s_BYTES',f)
    local key = string.rep('\0',lib[crypto_auth_KEYBYTES])

    describe('function ' .. crypto_auth_keygen, function()
      it('should generate a key', function()
        assert(string.len(lib[crypto_auth_keygen]()) == lib[crypto_auth_KEYBYTES])
      end)
    end)

    describe('function ' .. crypto_auth, function()
      it('should error on invalid calls', function()
        assert(pcall(lib[crypto_auth]) == false)
        assert(pcall(lib[crypto_auth],1) == false)
        assert(pcall(lib[crypto_auth],1,2) == false)
        assert(pcall(lib[crypto_auth],message,'') == false)
      end)

      it('should generate a tag', function()
        local tag = lib[crypto_auth](message,key)
        assert(string.len(tag) == lib[crypto_auth_BYTES])
        assert(tbl_to_str(expected_results[crypto_auth].mac) == tag)
      end)
    end)

    describe('function ' .. crypto_auth_verify, function()
      it('should error on invalid calls', function()
        assert(pcall(lib[crypto_auth_verify]) == false)
        assert(pcall(lib[crypto_auth_verify],1) == false)
        assert(pcall(lib[crypto_auth_verify],1,2) == false)
        assert(pcall(lib[crypto_auth_verify],1,2,3) == false)
        assert(pcall(lib[crypto_auth_verify],'','','') == false)
        assert(pcall(lib[crypto_auth_verify],string.rep('\0',lib[crypto_auth_BYTES]),'','') == false)
      end)

      it('should verify a valid tag', function()
        local mac = tbl_to_str(expected_results[crypto_auth].mac)
        assert(lib[crypto_auth_verify](mac,message,key) == true)
      end)

      it('should reject an invalid tag', function()
        local mac = string.rep('\0',lib[crypto_auth_BYTES])
        assert(lib[crypto_auth_verify](mac,message,key) == false)
      end)

    end)
  end

end)



