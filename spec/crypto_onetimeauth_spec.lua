local libs = {}

-- these should always load, regardless of Lua interpreter
do
  local lib = require'luasodium'
  assert(type(lib) == 'table')
  libs.luasodium = lib
  lib = require'luasodium.crypto_onetimeauth'
  assert(type(lib) == 'table')
  libs['luasodium.crypto_onetimeauth'] = lib
end

-- these won't load in the ffi-only mode
-- and regular lua won't load the ffi versions
for _,m in ipairs({'luasodium.core', 'luasodium.ffi', 'luasodium.crypto_onetimeauth.core', 'luasodium.crypto_onetimeauth.ffi'}) do
  local ok, lib = pcall(require,m)
  if ok then
    libs[m] = lib
  end
end

local premade_key = {
  83, 21, 59, 40, 150, 103, 152, 168,
  130, 18, 221, 36, 241, 86, 169, 91,
  85, 174, 114, 181, 18, 171, 243, 28,
  6, 19, 73, 97, 201, 154, 165, 112,
}

local expected_auth = {
  16, 113, 131, 16, 241, 219, 80, 253,
  90, 136, 14, 219, 255, 174, 234, 189,
}

local key_bytes = {}
for i,v in ipairs(premade_key) do
  key_bytes[i] = string.char(v)
end

local key = table.concat(key_bytes,'')
local message = 'a message'

for m,lib in pairs(libs) do
  describe('crypto_onetimeauth: ' .. m, function()
    it('should generate the expected auth tag', function()
      local auth = lib.crypto_onetimeauth(message,key)
      assert(string.len(auth) == lib.crypto_onetimeauth_BYTES)
      for i=1,lib.crypto_onetimeauth_BYTES do
        assert(string.byte(auth,i) == expected_auth[i])
      end
    end)

    it('should support chunked auth tags', function()
      local state = lib.crypto_onetimeauth_init(key)
      assert(lib.crypto_onetimeauth_update(state,message) == true)
      local auth = lib.crypto_onetimeauth_final(state)

      for i=1,lib.crypto_onetimeauth_BYTES do
        assert(string.byte(auth,i) == expected_auth[i])
      end

      local state2 = lib.crypto_onetimeauth_init(key)
      assert(state2:update(message) == true)
      assert(state2:final() == auth)
    end)
  end)
end



