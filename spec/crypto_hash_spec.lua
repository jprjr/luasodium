local libs = {}

-- these should always load, regardless of Lua interpreter
do
  local lib = require'luasodium'
  assert(type(lib) == 'table')
  libs.luasodium = lib
  lib = require'luasodium.crypto_hash'
  assert(type(lib) == 'table')
  libs['luasodium.crypto_hash'] = lib
end

-- these won't load in the ffi-only mode
-- and regular lua won't load the ffi versions
for _,m in ipairs({'luasodium.core', 'luasodium.ffi', 'luasodium.crypto_hash.core', 'luasodium.crypto_hash.ffi'}) do
  local ok, lib = pcall(require,m)
  if ok then
    libs[m] = lib
  end
end


for m,lib in pairs(libs) do
  describe('crypto_hash: ' .. m, function()
    it('should generate default hashes', function()
      local hash = lib.crypto_hash('a message')
      assert(string.len(hash) == lib.crypto_hash_BYTES)
    end)

    it('should generate sha256 hashes', function()
      local hash = lib.crypto_hash_sha256('a message')
      assert(string.len(hash) == lib.crypto_hash_sha256_BYTES)
    end)

    it('should generate sha512 hashes', function()
      local hash = lib.crypto_hash_sha512('a message')
      assert(string.len(hash) == lib.crypto_hash_sha512_BYTES)
    end)

    it('should generate multipart sha256 hashes', function()
      local state = lib.crypto_hash_sha256_init()
      assert(lib.crypto_hash_sha256_update(state,'a ') == true)
      assert(lib.crypto_hash_sha256_update(state,'message') == true)
      assert(lib.crypto_hash_sha256_final(state) == lib.crypto_hash_sha256('a message'))
    end)

    it('should generate multipart sha512 hashes', function()
      local state = lib.crypto_hash_sha512_init()
      assert(lib.crypto_hash_sha512_update(state,'a ') == true)
      assert(lib.crypto_hash_sha512_update(state,'message') == true)
      assert(lib.crypto_hash_sha512_final(state) == lib.crypto_hash_sha512('a message'))
    end)

    it('should support multipart, object-oriented sha256 hashes', function()
      local state = lib.crypto_hash_sha256_init()
      assert(state:update('a ') == true)
      assert(state:update('message') == true)
      assert(state:final() == lib.crypto_hash_sha256('a message'))
    end)

    it('should support multipart, object-oriented sha512 hashes', function()
      local state = lib.crypto_hash_sha512_init()
      assert(state:update('a ') == true)
      assert(state:update('message') == true)
      assert(state:final() == lib.crypto_hash_sha512('a message'))
    end)

  end)
end

