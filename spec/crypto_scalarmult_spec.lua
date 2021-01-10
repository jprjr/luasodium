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

local expected_results = {
  ['crypto_scalarmult'] = {
    ['n'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['p'] = {
       4, 6, 155, 95, 55, 232, 47, 145,
       220, 55, 253, 94, 185, 159, 26, 65,
       36, 177, 110, 141, 18, 42, 0, 207,
       111, 115, 2, 236, 76, 120, 234, 132,
    },
    ['pk'] = {
       238, 89, 13, 96, 184, 128, 245, 17,
       22, 168, 218, 52, 141, 128, 57, 171,
       102, 101, 61, 230, 17, 227, 7, 15,
       15, 204, 15, 27, 15, 26, 143, 25,
    },
    ['q'] = {
       1, 196, 158, 143, 4, 228, 101, 58,
       67, 90, 123, 94, 102, 239, 102, 229,
       197, 187, 238, 111, 239, 66, 189, 163,
       242, 231, 41, 34, 211, 78, 78, 112,
    },
  },
  ['crypto_scalarmult_curve25519'] = {
    ['n'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['p'] = {
       4, 6, 155, 95, 55, 232, 47, 145,
       220, 55, 253, 94, 185, 159, 26, 65,
       36, 177, 110, 141, 18, 42, 0, 207,
       111, 115, 2, 236, 76, 120, 234, 132,
    },
    ['pk'] = {
       238, 89, 13, 96, 184, 128, 245, 17,
       22, 168, 218, 52, 141, 128, 57, 171,
       102, 101, 61, 230, 17, 227, 7, 15,
       15, 204, 15, 27, 15, 26, 143, 25,
    },
    ['q'] = {
       1, 196, 158, 143, 4, 228, 101, 58,
       67, 90, 123, 94, 102, 239, 102, 229,
       197, 187, 238, 111, 239, 66, 189, 163,
       242, 231, 41, 34, 211, 78, 78, 112,
    },
  },
}

describe('crypto_scalarmult', function()
  it('should be a library', function()
    assert(type(lib) == 'table')
  end)

  it('should have constants', function()
    assert(type(lib.crypto_scalarmult_BYTES) == 'number')
    assert(type(lib.crypto_scalarmult_SCALARBYTES) == 'number')
    assert(type(lib.crypto_scalarmult_curve25519_BYTES) == 'number')
    assert(type(lib.crypto_scalarmult_curve25519_SCALARBYTES) == 'number')
  end)

  for _,basename in ipairs({
    'crypto_scalarmult',
    'crypto_scalarmult_curve25519',
  }) do
    local crypto_scalarmult = string.format('%s',basename)
    local crypto_scalarmult_base = string.format('%s_base',basename)
    local SCALARBYTES = lib[string.format('%s_SCALARBYTES',basename)]
    local BYTES = lib[string.format('%s_BYTES',basename)]

    local n = tbl_to_str(expected_results[basename].n)
    local p = tbl_to_str(expected_results[basename].p)
    local pk = tbl_to_str(expected_results[basename].pk)
    local q = tbl_to_str(expected_results[basename].q)

    describe('function ' .. crypto_scalarmult_base, function()
      it('should reject invalid input', function()
        assert(pcall(lib[crypto_scalarmult_base]) == false)
        assert(pcall(lib[crypto_scalarmult_base],'') == false)
      end)

      it('should reject a public key from a given private key', function()
        assert(lib[crypto_scalarmult_base](n) == pk)
      end)
    end)

    describe('function ' .. crypto_scalarmult, function()
      it('should reject invalid input', function()
        assert(pcall(lib[crypto_scalarmult]) == false)
        assert(pcall(lib[crypto_scalarmult],'','') == false)
        assert(pcall(lib[crypto_scalarmult],string.rep('\0',SCALARBYTES),'') == false)
      end)

      it('should generate a shared secret from given keys', function()
        assert(lib[crypto_scalarmult](n,p) == q)
      end)
    end)
  end
end)
