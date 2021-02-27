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

  for _,f in ipairs({
    'crypto_pwhash',
    'crypto_pwhash_argon2i',
    'crypto_pwhash_argon2id',
  }) do
    local crypto_pwhash = string.format('%s',f)
    local crypto_pwhash_str = string.format('%s_str',f)
    local crypto_pwhash_str_verify = string.format('%s_str_verify',f)
    local crypto_pwhash_str_needs_rehash = string.format('%s_str_needs_rehash',f)

    local SALTBYTES = lib[string.format('%s_SALTBYTES',f)]
    local STRBYTES = lib[string.format('%s_STRBYTES',f)]
    local BYTES_MIN = lib[string.format('%s_BYTES_MIN',f)]
    local BYTES_MAX = lib[string.format('%s_BYTES_MAX',f)]
    local PASSWD_MIN = lib[string.format('%s_PASSWD_MIN',f)]
    local PASSWD_MAX = lib[string.format('%s_PASSWD_MAX',f)]
    local OPSLIMIT_MIN = lib[string.format('%s_OPSLIMIT_MIN',f)]
    local OPSLIMIT_MAX = lib[string.format('%s_OPSLIMIT_MAX',f)]
    local OPSLIMIT_MODERATE = lib[string.format('%s_OPSLIMIT_MODERATE',f)]
    local MEMLIMIT_MIN = lib[string.format('%s_MEMLIMIT_MIN',f)]
    local MEMLIMIT_MAX = lib[string.format('%s_MEMLIMIT_MAX',f)]
    local MEMLIMIT_MODERATE = lib[string.format('%s_MEMLIMIT_MODERATE',f)]

    describe('function ' .. crypto_pwhash, function()
      it('rejects invalid calls', function()
        assert(pcall(lib[crypto_pwhash]) == false)
        assert(pcall(lib[crypto_pwhash],BYTES_MIN-1,'','',0,0) == false)
        assert(pcall(lib[crypto_pwhash],BYTES_MAX+1,'','',0,0) == false)
        assert(pcall(lib[crypto_pwhash],BYTES_MIN,'','',0,0) == false)
        assert(pcall(lib[crypto_pwhash],BYTES_MIN,'',string.rep('\0',SALTBYTES),OPSLIMIT_MIN-1,0) == false)
        assert(pcall(lib[crypto_pwhash],BYTES_MIN,'',string.rep('\0',SALTBYTES),OPSLIMIT_MAX+1,0) == false)
        assert(pcall(lib[crypto_pwhash],BYTES_MIN,'',string.rep('\0',SALTBYTES),OPSLIMIT_MIN,MEMLIMIT_MIN-1) == false)
        assert(pcall(lib[crypto_pwhash],BYTES_MIN,'',string.rep('\0',SALTBYTES),OPSLIMIT_MIN,MEMLIMIT_MAX+1) == false)
      end)

      it('derives keys', function()
        local salt = string.rep('\0',SALTBYTES)
        local out = lib[crypto_pwhash](BYTES_MIN,passwd,salt,OPSLIMIT_MODERATE,MEMLIMIT_MODERATE)
        assert(string.len(out) == BYTES_MIN)
      end)

      if f == 'crypto_pwhash' then
        it('allows setting an algorithm', function()
          local salt = string.rep('\0',SALTBYTES)
          local out = lib[crypto_pwhash](BYTES_MIN,passwd,salt,OPSLIMIT_MODERATE,MEMLIMIT_MODERATE,lib.crypto_pwhash_ALG_ARGON2I13)
          assert(string.len(out) == BYTES_MIN)
        end)

        it('returns nil if we choose a bad opslimit for a given algo', function()
          local salt = string.rep('\0',SALTBYTES)
          -- ARGON2I13 requires 3 ops, we'll set this to 1, which is still OPSLIMIT_MIN
          assert(lib[crypto_pwhash](BYTES_MIN,passwd,salt,1,MEMLIMIT_MODERATE,lib.crypto_pwhash_ALG_ARGON2I13) == nil)
        end)
      end
    end)

    describe('function ' .. crypto_pwhash_str, function()
      it('rejects invalid calls', function()
        assert(pcall(lib[crypto_pwhash_str]) == false)
        assert(pcall(lib[crypto_pwhash_str],'',OPSLIMIT_MIN-1,0) == false)
        assert(pcall(lib[crypto_pwhash_str],'',OPSLIMIT_MAX+1,0) == false)
        assert(pcall(lib[crypto_pwhash_str],'',OPSLIMIT_MIN,MEMLIMIT_MIN-1) == false)
        assert(pcall(lib[crypto_pwhash_str],'',OPSLIMIT_MIN,MEMLIMIT_MAX+1) == false)
      end)

      it('hashes passwords', function()
        local out = lib[crypto_pwhash_str](passwd,OPSLIMIT_MIN,MEMLIMIT_MIN)
        assert(string.len(out) <= STRBYTES)
      end)
    end)

    describe('function ' .. crypto_pwhash_str_verify, function()
      it('rejects invalid calls', function()
        assert(pcall(lib[crypto_pwhash_str_verify]) == false)
      end)

      it('returns true for a valid hash', function()
        local out = lib[crypto_pwhash_str](passwd,OPSLIMIT_MIN,MEMLIMIT_MIN)
        assert(lib[crypto_pwhash_str_verify](out,passwd) == true)
        assert(lib[crypto_pwhash_str_verify]('',passwd) == false)
      end)
    end)

    describe('function ' .. crypto_pwhash_str_needs_rehash, function()
      it('rejects invalid calls', function()
        assert(pcall(lib[crypto_pwhash_str_needs_rehash]) == false)
        assert(pcall(lib[crypto_pwhash_str_needs_rehash],'',OPSLIMIT_MIN-1,0) == false)
        assert(pcall(lib[crypto_pwhash_str_needs_rehash],'',OPSLIMIT_MAX+1,0) == false)
        assert(pcall(lib[crypto_pwhash_str_needs_rehash],'',OPSLIMIT_MIN,MEMLIMIT_MIN-1) == false)
        assert(pcall(lib[crypto_pwhash_str_needs_rehash],'',OPSLIMIT_MIN,MEMLIMIT_MAX+1) == false)
      end)

      it('returns booleans if something needs rehashing', function()
        local out = lib[crypto_pwhash_str](passwd,OPSLIMIT_MIN,MEMLIMIT_MIN)
        assert(lib[crypto_pwhash_str_needs_rehash](out,OPSLIMIT_MIN,MEMLIMIT_MIN) == false)
        assert(lib[crypto_pwhash_str_needs_rehash](out,OPSLIMIT_MIN+1,MEMLIMIT_MIN) == true)
      end)
    end)
  end
end)
