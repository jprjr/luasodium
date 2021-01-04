local libs = {}

local function describe_stub(_,cb)
  cb()
end

local function it_stub(_,cb)
  cb()
end

do
  local ok, runner = pcall(require,'busted.runner')
  if ok then
    runner()
  end
end

if not describe then
  describe = describe_stub
  it = it_stub
end

-- these should always load, regardless of Lua interpreter
do
  local lib = require'luasodium'
  assert(type(lib) == 'table')
  libs.luasodium = lib
  lib = require'luasodium.crypto_secretbox'
  assert(type(lib) == 'table')
  libs['luasodium.crypto_secretbox'] = lib
end

-- these won't load in the ffi-only mode
-- and regular lua won't load the ffi versions
for _,m in ipairs({'luasodium.core', 'luasodium.ffi', 'luasodium.crypto_secretbox.core', 'luasodium.crypto_secretbox.ffi'}) do
  local ok, lib = pcall(require,m)
  if ok then
    libs[m] = lib
  end
end

for m,lib in pairs(libs) do
  describe('crypto_secretbox: ' .. m, function()

  local nonce = string.rep('\0',lib.crypto_secretbox_NONCEBYTES)
  local key = string.rep('\0',lib.crypto_secretbox_KEYBYTES)

    it('should produce results for a known nonce/key', function()
      local encrypted = lib.crypto_secretbox_easy('yay',nonce,key)
      assert(string.len(encrypted) == 19)
      local result = {
        84,
        131,
        248,
        12,
        139,
        116,
        241,
        128,
        234,
        239,
        195,
        4,
        159,
        62,
        44,
        3,
        191,
        95,
        194,
      }
      for i=1,#encrypted do
        assert(string.byte(encrypted,i) == result[i])
      end
      assert(lib.crypto_secretbox_open_easy(encrypted,nonce,key) == 'yay')

      local non_easy = lib.crypto_secretbox('yay',nonce,key)
      assert(string.len(non_easy) == 19)
      for i=1,#non_easy do
        assert(string.byte(non_easy,i) == result[i])
      end
      assert(lib.crypto_secretbox_open(encrypted,nonce,key) == 'yay')
    end)

    it('should produce detached results for a known nonce/key', function()
      local encrypted, mac = lib.crypto_secretbox_detached('yay',nonce,key)
      assert(string.len(encrypted) == 3)
      local mac_result = {
        84,
        131,
        248,
        12,
        139,
        116,
        241,
        128,
        234,
        239,
        195,
        4,
        159,
        62,
        44,
        3,
      }
      local enc_result = {
        191,
        95,
        194,
      }
      for i=1,#mac do
        assert(string.byte(mac,i) == mac_result[i])
      end
      for i=1,#encrypted do
        assert(string.byte(encrypted,i) == enc_result[i])
      end

      assert(lib.crypto_secretbox_open_detached(encrypted,mac,nonce,key) == 'yay')
      assert(lib.crypto_secretbox_open_easy(mac .. encrypted,nonce,key) == 'yay')
      assert(lib.crypto_secretbox_open(mac .. encrypted,nonce,key) == 'yay')

      local badmac = string.rep('\0',lib.crypto_secretbox_MACBYTES)
      assert(pcall(lib.crypto_secretbox_open_detached,encrypted,badmac,nonce,key) == false)

      assert(pcall(lib.crypto_secretbox_open_easy,badmac .. encrypted,nonce,key) == false)
      assert(pcall(lib.crypto_secretbox_open,badmac .. encrypted,nonce,key) == false)
    end)

    it('should generate random keys', function()
      assert(string.len(lib.crypto_secretbox_keygen()) == lib.crypto_secretbox_KEYBYTES)
    end)

    it('should reject invalid calls', function()
      assert(pcall(lib.crypto_secretbox) == false)
      assert(pcall(lib.crypto_secretbox_open) == false)
      assert(pcall(lib.crypto_secretbox_easy) == false)
      assert(pcall(lib.crypto_secretbox_open_easy) == false)
      assert(pcall(lib.crypto_secretbox_detached) == false)
      assert(pcall(lib.crypto_secretbox_open_detached) == false)

      assert(pcall(lib.crypto_secretbox,'','','') == false)
      assert(pcall(lib.crypto_secretbox,'',string.rep('\0',lib.crypto_secretbox_NONCEBYTES),'') == false)

      assert(pcall(lib.crypto_secretbox_easy,'','','') == false)
      assert(pcall(lib.crypto_secretbox_easy,'',string.rep('\0',lib.crypto_secretbox_NONCEBYTES),'') == false)

      assert(pcall(lib.crypto_secretbox_detached,'','','') == false)
      assert(pcall(lib.crypto_secretbox_detached,'',string.rep('\0',lib.crypto_secretbox_NONCEBYTES),'') == false)

      assert(pcall(lib.crypto_secretbox_open,'','','') == false)
      assert(pcall(lib.crypto_secretbox_open,string.rep('\0',lib.crypto_secretbox_MACBYTES+1),'','') == false)
      assert(pcall(lib.crypto_secretbox_open,string.rep('\0',lib.crypto_secretbox_MACBYTES+1),string.rep('\0',lib.crypto_secretbox_NONCEBYTES),'') == false)

      assert(pcall(lib.crypto_secretbox_open_easy,'','','') == false)
      assert(pcall(lib.crypto_secretbox_open_easy,string.rep('\0',lib.crypto_secretbox_MACBYTES+1),'','') == false)
      assert(pcall(lib.crypto_secretbox_open_easy,string.rep('\0',lib.crypto_secretbox_MACBYTES+1),string.rep('\0',lib.crypto_secretbox_NONCEBYTES),'') == false)

      assert(pcall(lib.crypto_secretbox_open_detached,'','','','') == false)
      assert(pcall(lib.crypto_secretbox_open_detached,'',string.rep('\0',lib.crypto_secretbox_MACBYTES),'','') == false)
      assert(pcall(lib.crypto_secretbox_open_detached,'',string.rep('\0',lib.crypto_secretbox_MACBYTES),string.rep('\0',lib.crypto_secretbox_NONCEBYTES),'') == false)

    end)

  end)
end

