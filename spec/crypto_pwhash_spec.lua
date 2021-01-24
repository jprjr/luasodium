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

local passwd = "Correct horse battery staple"

describe('library crypto_generichash', function()
  it('is a library', function()
    assert(type(lib) == 'table')
  end)

  it('has constants', function()
    assert(type(lib.crypto_pwhash_ALG_ARGON2I13) == 'number')
    assert(type(lib.crypto_pwhash_ALG_ARGON2ID13) == 'number')
    assert(type(lib.crypto_pwhash_ALG_DEFAULT) == 'number')
    assert(type(lib.crypto_pwhash_BYTES_MAX) == 'number')
    assert(type(lib.crypto_pwhash_BYTES_MIN) == 'number')
    assert(type(lib.crypto_pwhash_MEMLIMIT_INTERACTIVE) == 'number')
    assert(type(lib.crypto_pwhash_MEMLIMIT_MAX) == 'number')
    assert(type(lib.crypto_pwhash_MEMLIMIT_MIN) == 'number')
    assert(type(lib.crypto_pwhash_MEMLIMIT_MODERATE) == 'number')
    assert(type(lib.crypto_pwhash_MEMLIMIT_SENSITIVE) == 'number')
    assert(type(lib.crypto_pwhash_OPSLIMIT_INTERACTIVE) == 'number')
    assert(type(lib.crypto_pwhash_OPSLIMIT_MAX) == 'number')
    assert(type(lib.crypto_pwhash_OPSLIMIT_MIN) == 'number')
    assert(type(lib.crypto_pwhash_OPSLIMIT_MODERATE) == 'number')
    assert(type(lib.crypto_pwhash_OPSLIMIT_SENSITIVE) == 'number')
    assert(type(lib.crypto_pwhash_PASSWD_MAX) == 'number')
    assert(type(lib.crypto_pwhash_PASSWD_MIN) == 'number')
    assert(type(lib.crypto_pwhash_SALTBYTES) == 'number')
    assert(type(lib.crypto_pwhash_STRBYTES) == 'number')
    assert(type(lib.crypto_pwhash_STRPREFIX) == 'string')
  end)
end)
