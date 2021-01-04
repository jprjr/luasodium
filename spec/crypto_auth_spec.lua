local libs = {}

-- these should always load, regardless of Lua interpreter
do
  local lib = require'luasodium'
  assert(type(lib) == 'table')
  libs.luasodium = lib
  lib = require'luasodium.crypto_auth'
  assert(type(lib) == 'table')
  libs['luasodium.crypto_auth'] = lib
end

-- these won't load in the ffi-only mode
-- and regular lua won't load the ffi versions
for _,m in ipairs({'luasodium.core', 'luasodium.ffi', 'luasodium.crypto_auth.core', 'luasodium.crypto_auth.ffi'}) do
  local ok, lib = pcall(require,m)
  if ok then
    libs[m] = lib
  end
end

local expected_tag = {
  36, 166, 137, 74, 84, 118, 157, 225,
  136, 104, 231, 95, 232, 156, 215, 110,
  24, 95, 206, 127, 136, 148, 76, 35,
  192, 230, 240, 71, 202, 197, 133, 26,
}

for m,lib in pairs(libs) do
  describe('crypto_auth: ' .. m, function()
    it('should be a library', function()
      assert(type(lib) == 'table')
    end)

    describe('zero-byte key tests', function()
      local key = string.rep('\0',lib.crypto_auth_KEYBYTES)
      it('should generate the correct authentication tag', function()
        local tag = lib.crypto_auth('a message',key)
        assert(string.len(tag) == lib.crypto_auth_BYTES)

        for j=1,string.len(tag) do
          assert(string.byte(tag,j) == expected_tag[j])
        end
      end)
    end)

    describe('random byte key tests', function()
      it('should generate a key', function()
        local key = lib.crypto_auth_keygen()
        assert(string.len(key) == lib.crypto_auth_KEYBYTES)
        local tag = lib.crypto_auth('a message',key)
        assert(string.len(tag) == lib.crypto_auth_BYTES)
        assert(lib.crypto_auth_verify(tag,'a message',key) == true)
        assert(lib.crypto_auth_verify(tag,'another message',key) == false)
      end)
    end)
  end)

end


