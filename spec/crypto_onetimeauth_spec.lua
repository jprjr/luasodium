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
  ['crypto_onetimeauth'] = {
    ['premade_key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['auth'] = {
       65, 101, 104, 124, 211, 222, 164, 222,
       14, 18, 11, 124, 223, 178, 185, 143,
    },
  },
  ['crypto_onetimeauth_poly1305'] = {
    ['premade_key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['auth'] = {
       65, 101, 104, 124, 211, 222, 164, 222,
       14, 18, 11, 124, 223, 178, 185, 143,
    },
  },
}

describe('crypto_onetimeauth library', function()
  it('should have constants', function()
    assert(type(lib.crypto_onetimeauth_BYTES) == 'number')
    assert(type(lib.crypto_onetimeauth_KEYBYTES) == 'number')
    --assert(type(lib.crypto_onetimeauth_poly1305_BYTES) == 'number')
    --assert(type(lib.crypto_onetimeauth_poly1305_KEYBYTES) == 'number')
  end)

  for _,f in ipairs({
    'crypto_onetimeauth',
    'crypto_onetimeauth_poly1305',
  }) do
    local crypto_onetimeauth = string.format('%s',f)
    local crypto_onetimeauth_verify = string.format('%s_verify',f)
    local crypto_onetimeauth_keygen = string.format('%s_keygen',f)
    local crypto_onetimeauth_init = string.format('%s_init',f)
    local crypto_onetimeauth_update = string.format('%s_update',f)
    local crypto_onetimeauth_final = string.format('%s_final',f)

    local BYTES = lib[string.format('%s_BYTES',f)]
    local KEYBYTES = lib[string.format('%s_KEYBYTES',f)]

    local key = tbl_to_str(expected_results[f].premade_key)
    local auth = tbl_to_str(expected_results[f].auth)

    describe('function ' .. crypto_onetimeauth_keygen, function()
      it('should generate keys', function()
        local k = lib[crypto_onetimeauth_keygen]()
        assert(string.len(k) == KEYBYTES)
      end)
    end)

    describe('function ' .. crypto_onetimeauth, function()
      it('should reject invalid calls', function()
        assert(pcall(lib[crypto_onetimeauth]) == false)
        assert(pcall(lib[crypto_onetimeauth],'','') == false)
      end)

      it('should generate an expected tag', function()
        assert(lib[crypto_onetimeauth](message,key) == auth)
      end)
    end)

    describe('function ' .. crypto_onetimeauth_verify, function()
      it('should reject invalid calls', function()
        assert(pcall(lib[crypto_onetimeauth_verify]) == false)
        assert(pcall(lib[crypto_onetimeauth_verify],'','','') == false)
        assert(pcall(lib[crypto_onetimeauth_verify],string.rep('\0',BYTES),'','') == false)

      end)

      it('should validate a known good tag', function()
        assert(lib[crypto_onetimeauth_verify](auth,message,key) == true)
      end)

      it('should return false on a bad tag', function()
        local tag = string.rep('\0',BYTES)
        assert(lib[crypto_onetimeauth_verify](tag,message,key) == false)
      end)
    end)

    describe('chunked tags', function()
      it('should reject bad calls for chunked functions', function()
        assert(pcall(lib[crypto_onetimeauth_init]) == false)
        assert(pcall(lib[crypto_onetimeauth_update]) == false)
        assert(pcall(lib[crypto_onetimeauth_final]) == false)
        assert(pcall(lib[crypto_onetimeauth_init],'') == false)
        assert(pcall(lib[crypto_onetimeauth_update],'') == false)
        assert(pcall(lib[crypto_onetimeauth_update],'','') == false)
        assert(pcall(lib[crypto_onetimeauth_final],'') == false)
      end)

      it('should generate the same results as non-chunked version', function()
        local state = lib[crypto_onetimeauth_init](key)
        assert(lib[crypto_onetimeauth_update](state,message) == true)
        assert(lib[crypto_onetimeauth_final](state) == auth)
      end)

      it('should support object-oriented usage', function()
        local state = lib[crypto_onetimeauth_init](key)
        assert(state:update(message) == true)
        assert(state:final() == auth)
      end)

    end)
  end
end)

