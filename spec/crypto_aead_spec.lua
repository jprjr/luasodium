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

local function str_to_tbl(str)
  local buf = { '{' }
  for b=1,string.len(str),8 do
    local chunk = str:sub(b,b+7)
    local c = chunk:gsub('.',function(c)
      return string.format('%d, ',string.byte(c))
    end)
    table.insert(buf,'  ' .. c)
  end
  table.insert(buf, '}')
  return table.concat(buf,'\n')
end

local message = 'hello'
local ad = 'ad-data'

local expected_results = {
  ['crypto_aead_chacha20poly1305'] = {
    ['nonce'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
    },
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['cipher'] = {
       201, 68, 199, 226, 83, 242, 65, 88,
       0, 143, 123, 222, 222, 79, 236, 122,
       76, 220, 108, 1, 131,
    },
    ['cipher_noad'] = {
       201, 68, 199, 226, 83, 11, 254, 12,
       11, 46, 24, 51, 234, 152, 0, 219,
       44, 125, 105, 140, 231,
    },
    ['cipher_detached'] = {
       201, 68, 199, 226, 83,
    },
    ['mac'] = {
       242, 65, 88, 0, 143, 123, 222, 222,
       79, 236, 122, 76, 220, 108, 1, 131,
    },
    ['cipher_noad_detached'] = {
       201, 68, 199, 226, 83,
    },
    ['mac_noad'] = {
       11, 254, 12, 11, 46, 24, 51, 234,
       152, 0, 219, 44, 125, 105, 140, 231,
    },
  },
  ['crypto_aead_chacha20poly1305_ietf'] = {
    ['nonce'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210,
    },
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['cipher'] = {
       42, 243, 219, 92, 179, 34, 224, 253,
       133, 87, 211, 102, 194, 114, 219, 113,
       92, 4, 195, 164, 234,
    },
    ['cipher_noad'] = {
       42, 243, 219, 92, 179, 52, 233, 220,
       88, 89, 112, 79, 191, 67, 130, 119,
       134, 39, 218, 126, 130,
    },
    ['cipher_detached'] = {
       42, 243, 219, 92, 179,
    },
    ['mac'] = {
       34, 224, 253, 133, 87, 211, 102, 194,
       114, 219, 113, 92, 4, 195, 164, 234,
    },
    ['cipher_noad_detached'] = {
       42, 243, 219, 92, 179,
    },
    ['mac_noad'] = {
       52, 233, 220, 88, 89, 112, 79, 191,
       67, 130, 119, 134, 39, 218, 126, 130,
    },
  },
  ['crypto_aead_xchacha20poly1305_ietf'] = {
    ['nonce'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
    },
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['cipher'] = {
       239, 216, 24, 214, 186, 55, 48, 83,
       183, 95, 55, 45, 73, 62, 82, 203,
       141, 204, 66, 16, 40,
    },
    ['cipher_noad'] = {
       239, 216, 24, 214, 186, 143, 160, 249,
       144, 111, 239, 184, 159, 248, 216, 48,
       196, 157, 44, 154, 146,
    },
    ['cipher_detached'] = {
       239, 216, 24, 214, 186,
    },
    ['mac'] = {
       55, 48, 83, 183, 95, 55, 45, 73,
       62, 82, 203, 141, 204, 66, 16, 40,
    },
    ['cipher_noad_detached'] = {
       239, 216, 24, 214, 186,
    },
    ['mac_noad'] = {
       143, 160, 249, 144, 111, 239, 184, 159,
       248, 216, 48, 196, 157, 44, 154, 146,
    },
  },
  ['crypto_aead_aes256gcm'] = {
    ['nonce'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210,
    },
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['cipher'] = {
       79, 163, 237, 114, 60, 43, 14, 164,
       132, 247, 203, 19, 8, 36, 118, 176,
       177, 1, 113, 48, 156,
    },
    ['cipher_noad'] = {
       79, 163, 237, 114, 60, 247, 227, 154,
       164, 166, 62, 107, 151, 92, 251, 1,
       226, 82, 37, 211, 191,
    },
    ['cipher_detached'] = {
       79, 163, 237, 114, 60,
    },
    ['mac'] = {
       43, 14, 164, 132, 247, 203, 19, 8,
       36, 118, 176, 177, 1, 113, 48, 156,
    },
    ['cipher_noad_detached'] = {
       79, 163, 237, 114, 60,
    },
    ['mac_noad'] = {
       247, 227, 154, 164, 166, 62, 107, 151,
       92, 251, 1, 226, 82, 37, 211, 191,
    },
  },
}


describe('crypto_aead', function()
  it('should be a library', function()
    assert(type(lib) == 'table')
  end)

  it('should have constants', function()
    assert(type(lib.crypto_aead_chacha20poly1305_KEYBYTES) == 'number')
    assert(type(lib.crypto_aead_chacha20poly1305_NPUBBYTES) == 'number')
    assert(type(lib.crypto_aead_chacha20poly1305_ABYTES) == 'number')

    assert(type(lib.crypto_aead_chacha20poly1305_IETF_KEYBYTES) == 'number')
    assert(type(lib.crypto_aead_chacha20poly1305_IETF_NPUBBYTES) == 'number')
    assert(type(lib.crypto_aead_chacha20poly1305_IETF_ABYTES) == 'number')

    assert(type(lib.crypto_aead_chacha20poly1305_ietf_KEYBYTES) == 'number')
    assert(type(lib.crypto_aead_chacha20poly1305_ietf_NPUBBYTES) == 'number')
    assert(type(lib.crypto_aead_chacha20poly1305_ietf_ABYTES) == 'number')

    assert(type(lib.crypto_aead_xchacha20poly1305_IETF_KEYBYTES) == 'number')
    assert(type(lib.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES) == 'number')
    assert(type(lib.crypto_aead_xchacha20poly1305_IETF_ABYTES) == 'number')

    assert(type(lib.crypto_aead_xchacha20poly1305_ietf_KEYBYTES) == 'number')
    assert(type(lib.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) == 'number')
    assert(type(lib.crypto_aead_xchacha20poly1305_ietf_ABYTES) == 'number')

    assert(type(lib.crypto_aead_aes256gcm_KEYBYTES) == 'number')
    assert(type(lib.crypto_aead_aes256gcm_NPUBBYTES) == 'number')
    assert(type(lib.crypto_aead_aes256gcm_ABYTES) == 'number')
  end)

  local funcs = {
    'chacha20poly1305',
    'chacha20poly1305_ietf',
    'xchacha20poly1305_ietf',
  }

  if lib.crypto_aead_aes256gcm_is_available() == true then
    table.insert(funcs,'aes256gcm')
  end

  for _,f in ipairs(funcs) do
    f = 'crypto_aead_' .. f
    local crypto_aead_keygen = string.format('%s_keygen',f)
    local crypto_aead_encrypt = string.format('%s_encrypt',f)
    local crypto_aead_decrypt = string.format('%s_decrypt',f)
    local crypto_aead_encrypt_detached = string.format('%s_encrypt_detached',f)
    local crypto_aead_decrypt_detached = string.format('%s_decrypt_detached',f)
    local KEYBYTES = string.format('%s_KEYBYTES',f)
    local NPUBBYTES = string.format('%s_NPUBBYTES',f)
    local ABYTES = string.format('%s_ABYTES',f)

    local nonce = tbl_to_str(expected_results[f].nonce)
    local key = tbl_to_str(expected_results[f].key)
    local cipher = tbl_to_str(expected_results[f].cipher)
    local cipher_noad = tbl_to_str(expected_results[f].cipher_noad)

    local cipher_detached = tbl_to_str(expected_results[f].cipher_detached)
    local cipher_noad_detached = tbl_to_str(expected_results[f].cipher_noad_detached)

    local mac = tbl_to_str(expected_results[f].mac)
    local mac_noad = tbl_to_str(expected_results[f].mac_noad)

    describe('function ' .. crypto_aead_keygen, function()
      it('should generate a random key', function()
        local k = lib[crypto_aead_keygen]()
        assert(string.len(k) == lib[KEYBYTES])
      end)
    end)


    describe('function ' .. crypto_aead_encrypt, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_aead_encrypt]) == false)
        assert(pcall(lib[crypto_aead_encrypt],'','','') == false)
        assert(pcall(lib[crypto_aead_encrypt],key,'','') == false)
      end)

      it('should produce the correct cipher', function()
        local c
        c = lib[crypto_aead_encrypt](key,message,nonce)
        assert(c == cipher_noad, str_to_tbl(c))
        c = lib[crypto_aead_encrypt](key,message,nonce,ad)
        assert(c == cipher, str_to_tbl(c))
      end)
    end)

    describe('function ' .. crypto_aead_decrypt, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_aead_decrypt]) == false)
        assert(pcall(lib[crypto_aead_decrypt],'','','') == false)
        assert(pcall(lib[crypto_aead_decrypt],key,'','') == false)
        assert(pcall(lib[crypto_aead_decrypt],key,cipher,'') == false)
      end)

      it('should produce the correct message', function()
        local m
        m = lib[crypto_aead_decrypt](key,cipher_noad,nonce)
        assert(m == message, str_to_tbl(m))
        m = lib[crypto_aead_decrypt](key,cipher,nonce,ad)
        assert(m == message, str_to_tbl(m))
      end)

      it('should return nil when given a wrong cipher', function()
        assert(lib[crypto_aead_decrypt](key,cipher,nonce) == nil)
      end)
    end)

    describe('function ' .. crypto_aead_encrypt_detached, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_aead_encrypt_detached]) == false)
        assert(pcall(lib[crypto_aead_encrypt_detached],'','','') == false)
        assert(pcall(lib[crypto_aead_encrypt_detached],key,'','') == false)
      end)

      it('should produce the correct cipher and mac', function()
        local c, m
        c, m = lib[crypto_aead_encrypt_detached](key,message,nonce)
        assert(c == cipher_noad_detached, str_to_tbl(c))
        assert(m == mac_noad, str_to_tbl(m))
        c, m = lib[crypto_aead_encrypt_detached](key,message,nonce,ad)
        assert(c == cipher_detached, str_to_tbl(c))
        assert(m == mac, str_to_tbl(m))
      end)
    end)

    describe('function ' .. crypto_aead_decrypt_detached, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_aead_decrypt_detached]) == false)
        assert(pcall(lib[crypto_aead_decrypt_detached],'','','','') == false)
        assert(pcall(lib[crypto_aead_decrypt_detached],key,'','','') == false)
        assert(pcall(lib[crypto_aead_decrypt_detached],key,cipher_detached,'','') == false)
        assert(pcall(lib[crypto_aead_decrypt_detached],key,cipher_detached,mac,'') == false)
      end)

      it('should produce the correct message', function()
        local m
        m = lib[crypto_aead_decrypt_detached](key,cipher_noad_detached,mac_noad,nonce)
        assert(m == message, str_to_tbl(m))
        m = lib[crypto_aead_decrypt_detached](key,cipher_detached,mac,nonce,ad)
        assert(m == message, str_to_tbl(m))
      end)

      it('should return nil when given a wrong cipher', function()
        assert(lib[crypto_aead_decrypt_detached](key,cipher_detached,mac,nonce) == nil)
      end)

    end)
  end

  -- only test the pre-computation thing if it's available
  if lib.crypto_aead_aes256gcm_is_available() == true then
    for _,f in ipairs({'aes256gcm'}) do
      f = 'crypto_aead_' .. f

      local crypto_aead_beforenm = string.format('%s_beforenm',f)
      local crypto_aead_encrypt_afternm = string.format('%s_encrypt_afternm',f)
      local crypto_aead_decrypt_afternm = string.format('%s_decrypt_afternm',f)
      local crypto_aead_encrypt_detached_afternm = string.format('%s_encrypt_detached_afternm',f)
      local crypto_aead_decrypt_detached_afternm = string.format('%s_decrypt_detached_afternm',f)
      local KEYBYTES = string.format('%s_KEYBYTES',f)
      local NPUBBYTES = string.format('%s_NPUBBYTES',f)
      local ABYTES = string.format('%s_ABYTES',f)

      local nonce = tbl_to_str(expected_results[f].nonce)
      local key = tbl_to_str(expected_results[f].key)
      local cipher = tbl_to_str(expected_results[f].cipher)
      local cipher_noad = tbl_to_str(expected_results[f].cipher_noad)

      local cipher_detached = tbl_to_str(expected_results[f].cipher_detached)
      local cipher_noad_detached = tbl_to_str(expected_results[f].cipher_noad_detached)

      local mac = tbl_to_str(expected_results[f].mac)
      local mac_noad = tbl_to_str(expected_results[f].mac_noad)

      describe('function ' .. crypto_aead_beforenm, function()
        it('should throw errors on invalid calls', function()
          assert(pcall(lib[crypto_aead_beforenm]) == false)
          assert(pcall(lib[crypto_aead_beforenm],'') == false)
        end)

        it('should return an object', function()
          local ctx = lib[crypto_aead_beforenm](key)
          assert(type(ctx) == 'userdata' or type(ctx) == 'table')
        end)

        it('should have the correct metatable', function()
          local ctx = lib[crypto_aead_beforenm](key)
          assert(ctx.encrypt == lib[crypto_aead_encrypt_afternm])
          assert(ctx.decrypt == lib[crypto_aead_decrypt_afternm])

          assert(ctx.encrypt_detached == lib[crypto_aead_encrypt_detached_afternm])
          assert(ctx.decrypt_detached == lib[crypto_aead_decrypt_detached_afternm])

          assert(lib[crypto_aead_encrypt_afternm](ctx,message,nonce) ==
                ctx:encrypt(message,nonce))

          assert(lib[crypto_aead_decrypt_afternm](ctx,cipher,nonce) ==
                ctx:decrypt(cipher,nonce))

          assert(lib[crypto_aead_encrypt_detached_afternm](ctx,message,nonce) ==
                ctx:encrypt_detached(message,nonce))

          assert(lib[crypto_aead_decrypt_detached_afternm](ctx,cipher_detached,mac,nonce) ==
                ctx:decrypt_detached(cipher_detached,mac,nonce))
        end)
      end)

      describe('function ' .. crypto_aead_encrypt_afternm, function()
        it('should throw errors on invalid calls', function()
          local ctx = lib[crypto_aead_beforenm](key)
          assert(pcall(lib[crypto_aead_encrypt_afternm]) == false)
          assert(pcall(lib[crypto_aead_encrypt_afternm],'','','') == false)
          assert(pcall(lib[crypto_aead_encrypt_afternm],ctx) == false)
          assert(pcall(lib[crypto_aead_encrypt_afternm],ctx,'','') == false)
        end)

        it('should return the correct cipher', function()
          local ctx = lib[crypto_aead_beforenm](key)
          local c = lib[crypto_aead_encrypt_afternm](ctx,message,nonce)
          assert(c == cipher_noad, str_to_tbl(c))
          c = lib[crypto_aead_encrypt_afternm](ctx,message,nonce,ad)
          assert(c == cipher, str_to_tbl(c))
        end)
      end)

      describe('function ' .. crypto_aead_decrypt_afternm, function()
        it('should throw errors on invalid calls', function()
          local ctx = lib[crypto_aead_beforenm](key)
          assert(pcall(lib[crypto_aead_decrypt_afternm]) == false)
          assert(pcall(lib[crypto_aead_decrypt_afternm],'','','') == false)
          assert(pcall(lib[crypto_aead_decrypt_afternm],ctx,'','') == false)
          assert(pcall(lib[crypto_aead_decrypt_afternm],ctx,cipher,'') == false)
        end)

        it('should produce the correct message', function()
          local ctx = lib[crypto_aead_beforenm](key)
          local m
          m = lib[crypto_aead_decrypt_afternm](ctx,cipher_noad,nonce)
          assert(m == message, str_to_tbl(m))
          m = lib[crypto_aead_decrypt_afternm](ctx,cipher,nonce,ad)
          assert(m == message, str_to_tbl(m))
        end)

        it('should return nil when given a wrong cipher', function()
          local ctx = lib[crypto_aead_beforenm](key)
          assert(lib[crypto_aead_decrypt_afternm](ctx,cipher,nonce) == nil)
        end)
      end)

      describe('function ' .. crypto_aead_encrypt_detached_afternm, function()
        it('should throw errors on invalid calls', function()
          local ctx = lib[crypto_aead_beforenm](key)
          assert(pcall(lib[crypto_aead_encrypt_detached_afternm]) == false)
          assert(pcall(lib[crypto_aead_encrypt_detached_afternm],'','','') == false)
          assert(pcall(lib[crypto_aead_encrypt_detached_afternm],ctx,'','') == false)
        end)

        it('should produce the correct cipher and mac', function()
          local ctx = lib[crypto_aead_beforenm](key)
          local c, m
          c, m = lib[crypto_aead_encrypt_detached_afternm](ctx,message,nonce)
          assert(c == cipher_noad_detached, str_to_tbl(c))
          assert(m == mac_noad, str_to_tbl(m))
          c, m = lib[crypto_aead_encrypt_detached_afternm](ctx,message,nonce,ad)
          assert(c == cipher_detached, str_to_tbl(c))
          assert(m == mac, str_to_tbl(m))
        end)
      end)

      describe('function ' .. crypto_aead_decrypt_detached_afternm, function()
        it('should throw errors on invalid calls', function()
          local ctx = lib[crypto_aead_beforenm](key)
          assert(pcall(lib[crypto_aead_decrypt_detached_afternm]) == false)
          assert(pcall(lib[crypto_aead_decrypt_detached_afternm],'','','','') == false)
          assert(pcall(lib[crypto_aead_decrypt_detached_afternm],ctx,'','','') == false)
          assert(pcall(lib[crypto_aead_decrypt_detached_afternm],ctx,cipher_detached,'','') == false)
          assert(pcall(lib[crypto_aead_decrypt_detached_afternm],ctx,cipher_detached,mac,'') == false)
        end)

        it('should produce the correct message', function()
          local m
          local ctx = lib[crypto_aead_beforenm](key)
          m = lib[crypto_aead_decrypt_detached_afternm](ctx,cipher_noad_detached,mac_noad,nonce)
          assert(m == message, str_to_tbl(m))
          m = lib[crypto_aead_decrypt_detached_afternm](ctx,cipher_detached,mac,nonce,ad)
          assert(m == message, str_to_tbl(m))
        end)

        it('should return nil when given a wrong cipher', function()
          local ctx = lib[crypto_aead_beforenm](key)
          assert(lib[crypto_aead_decrypt_detached_afternm](ctx,cipher_detached,mac,nonce) == nil)
        end)
      end)

    end
  end
end)
