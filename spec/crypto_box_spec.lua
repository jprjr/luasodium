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

local message = 'hello'

local expected_sender_pk = {
  91, 245, 92, 115, 184, 46, 190, 34,
  190, 128, 243, 67, 6, 103, 175, 87,
  15, 174, 37, 86, 166, 65, 94, 107,
  48, 212, 6, 83, 0, 170, 148, 125,
}

local expected_sender_sk = {
  80, 70, 173, 193, 219, 168, 56, 134,
  123, 43, 187, 253, 208, 195, 66, 62,
  88, 181, 121, 112, 181, 38, 122, 144,
  245, 121, 96, 146, 74, 135, 241, 150,
}

local expected_receiver_pk = {
  209, 250, 63, 1, 130, 107, 216, 183,
  142, 5, 124, 8, 108, 123, 34, 199,
  173, 67, 88, 202, 145, 128, 153, 205,
  123, 126, 93, 58, 205, 126, 40, 91,
}

local expected_receiver_sk = {
  39, 205, 105, 53, 134, 71, 22, 167,
  157, 116, 221, 95, 171, 189, 137, 100,
  48, 64, 81, 202, 65, 163, 28, 70,
  89, 21, 142, 187, 124, 61, 11, 151,
}

local expected_encryption_key = {
  84, 120, 45, 227, 119, 175, 42, 125,
  37, 36, 242, 247, 145, 123, 75, 191,
  102, 101, 8, 172, 56, 216, 58, 13,
  151, 53, 5, 228, 46, 148, 133, 246,
}

local expected_decryption_key = {
  84, 120, 45, 227, 119, 175, 42, 125,
  37, 36, 242, 247, 145, 123, 75, 191,
  102, 101, 8, 172, 56, 216, 58, 13,
  151, 53, 5, 228, 46, 148, 133, 246,
}

local expected_mac = {
  34, 189, 69, 142, 159, 103, 169, 18,
  185, 43, 180, 114, 77, 226, 0, 175,
}

local expected_cipher = {
  16, 97, 18, 38, 131,
}

local expected_mac_str = ''
local expected_cipher_str = ''

for i=1,#expected_mac do
  expected_mac_str = expected_mac_str .. string.char(expected_mac[i])
end

for i=1,#expected_cipher do
  expected_cipher_str = expected_cipher_str .. string.char(expected_cipher[i])
end

describe('library crypto_box', function()
  it('should be a library', function()
    assert(type(lib) == 'table')
  end)

  it('should have constants', function()
    assert(type(lib.crypto_box_MACBYTES) == 'number')
    assert(type(lib.crypto_box_NONCEBYTES) == 'number')
    assert(type(lib.crypto_box_SEEDBYTES) == 'number')
    assert(type(lib.crypto_box_PUBLICKEYBYTES) == 'number')
    assert(type(lib.crypto_box_SECRETKEYBYTES) == 'number')
    assert(type(lib.crypto_box_BEFORENMBYTES) == 'number')
    assert(type(lib.crypto_box_curve25519xsalsa20poly1305_MACBYTES) == 'number')
    assert(type(lib.crypto_box_curve25519xsalsa20poly1305_NONCEBYTES) == 'number')
    assert(type(lib.crypto_box_curve25519xsalsa20poly1305_SEEDBYTES) == 'number')
    assert(type(lib.crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES) == 'number')
    assert(type(lib.crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES) == 'number')
    assert(type(lib.crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES) == 'number')
  end)

  for _,f in ipairs({'crypto_box','crypto_box_curve25519xsalsa20poly1305'}) do
    local keypair = string.format('%s_keypair',f)
    local seed_keypair = string.format('%s_seed_keypair',f)
    local beforenm = string.format('%s_beforenm',f)

    local MACBYTES = string.format('%s_MACBYTES',f)
    local NONCEBYTES = string.format('%s_NONCEBYTES',f)
    local PUBLICKEYBYTES = string.format('%s_PUBLICKEYBYTES',f)
    local SECRETKEYBYTES = string.format('%s_SECRETKEYBYTES',f)
    local BEFORENMBYTES = string.format('%s_BEFORENMBYTES',f)
    local SEEDBYTES = string.format('%s_SEEDBYTES',f)

    describe('function ' .. keypair, function()
      it('should return a keypair', function()
        local pk, sk = lib[keypair]()
        assert(string.len(pk) == lib[PUBLICKEYBYTES])
        assert(string.len(sk) == lib[SECRETKEYBYTES])
      end)
    end)

    describe('function ' .. beforenm, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[beforenm]) == false)
        assert(pcall(lib[beforenm],'','') == false)
        assert(pcall(lib[beforenm],string.rep('\0',lib[PUBLICKEYBYTES]),'') == false)
      end)
    end)

    describe('function ' .. seed_keypair, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[seed_keypair]) == false)
        assert(pcall(lib[seed_keypair],'') == false)
      end)

      it('should return keys for some known seeds', function()
        local sender_pk, sender_sk = lib[seed_keypair](string.rep(string.char(0),lib[SEEDBYTES]))
        local receiver_pk, receiver_sk = lib[seed_keypair](string.rep(string.char(255),lib[SEEDBYTES]))
        local beforenm_ekey = lib[beforenm](sender_pk,receiver_sk)
        local beforenm_dkey = lib[beforenm](receiver_pk,sender_sk)
        assert(string.len(sender_pk) == lib[PUBLICKEYBYTES])
        assert(string.len(sender_sk) == lib[SECRETKEYBYTES])
        assert(string.len(receiver_pk) == lib[PUBLICKEYBYTES])
        assert(string.len(receiver_sk) == lib[SECRETKEYBYTES])
        assert(string.len(beforenm_ekey) == lib[BEFORENMBYTES])
        assert(string.len(beforenm_dkey) == lib[BEFORENMBYTES])

        for i=1,lib[PUBLICKEYBYTES] do
          assert(string.byte(sender_pk,i) == expected_sender_pk[i])
          assert(string.byte(receiver_pk,i) == expected_receiver_pk[i])
        end

        for i=1,lib[SECRETKEYBYTES] do
          assert(string.byte(sender_sk,i) == expected_sender_sk[i])
          assert(string.byte(receiver_sk,i) == expected_receiver_sk[i])
        end

        for i=1,lib[BEFORENMBYTES] do
          assert(string.byte(beforenm_ekey,i) == expected_encryption_key[i])
          assert(string.byte(beforenm_dkey,i) == expected_decryption_key[i])
        end
      end)
    end)

    describe(f .. ' functions', function()
      local open = string.format('%s_open',f)
      local afternm = string.format('%s_afternm',f)
      local open_afternm = string.format('%s_open_afternm',f)

      local sender_pk, sender_sk =
        lib[seed_keypair](string.rep(string.char(0),lib[SEEDBYTES]))

      local receiver_pk, receiver_sk =
        lib[seed_keypair](string.rep(string.char(255),lib[SEEDBYTES]))

      local nonce = string.rep(string.char(0),lib[NONCEBYTES])

      local encryption_k =
        lib[beforenm](receiver_pk,sender_sk)
      local decryption_k =
        lib[beforenm](sender_pk,receiver_sk)


      describe('function ' ..f, function()
        it('should throw errors on invalid calls', function()
          assert(pcall(lib[f]) == false)
          assert(pcall(lib[f],'','','','') == false)
          assert(pcall(lib[f],'',string.rep('\0',lib[NONCEBYTES]),'','') == false)
          assert(pcall(lib[f],'',string.rep('\0',lib[NONCEBYTES]),string.rep('\0',lib[PUBLICKEYBYTES]),'') == false)
        end)

        it('should encrypt messages', function()
          local encrypted = lib[f](message,nonce,receiver_pk,sender_sk)
          assert(string.len(encrypted) == (string.len(message) + lib[MACBYTES]))
          for i=1,lib[MACBYTES] do
            assert(string.byte(encrypted,i) == expected_mac[i])
          end
          for i=lib[MACBYTES]+1,lib[MACBYTES]+string.len(message) do
            assert(string.byte(encrypted,i) == expected_cipher[i - lib[MACBYTES]])
          end
        end)
      end)

      describe('function ' .. open, function()
        it('should throw errors on invalid calls', function()
          assert(pcall(lib[open]) == false)
          assert(pcall(lib[open],'','','','') == false)
          assert(pcall(lib[open],string.rep('\0',lib[MACBYTES]),'','','') == false)
          assert(pcall(lib[open],string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),'','') == false)
          assert(pcall(lib[open],string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)
        end)

        it('should decrypt messages', function()
          local encrypted = expected_mac_str .. expected_cipher_str
          local decrypted = lib[open](encrypted,nonce,sender_pk,receiver_sk)
          assert(string.len(decrypted) == string.len(message))
          assert(decrypted == message)
        end)

        it('should error on decryption failure', function()
          local encrypted = string.rep('\0',lib[MACBYTES]) .. expected_cipher_str
          assert(pcall(lib[open],encrypted,nonce,sender_pk,receiver_sk) == false)
        end)
      end)

      describe('function ' .. afternm, function()
        it('should throw errors on invalid calls', function()
          assert(pcall(lib[afternm]) == false)
          assert(pcall(lib[afternm],'','','') == false)
          assert(pcall(lib[afternm],'',string.rep('\0',lib[NONCEBYTES]),'') == false)
        end)

        it('should encrypt messages', function()
          local encrypted = lib[afternm](message,nonce,encryption_k)
          assert(string.len(encrypted) == (string.len(message) + lib[MACBYTES]))
          for i=1,lib[MACBYTES] do
            assert(string.byte(encrypted,i) == expected_mac[i])
          end
          for i=lib[MACBYTES]+1,lib[MACBYTES]+string.len(message) do
            assert(string.byte(encrypted,i) == expected_cipher[i - lib[MACBYTES]])
          end
        end)
      end)

      describe('function crypto_box_open_afternm', function()
        it('should throw errors on invalid calls', function()
          assert(pcall(lib[open_afternm]) == false)
          assert(pcall(lib[open_afternm],'','','') == false)
          assert(pcall(lib[open_afternm],string.rep('\0',lib[MACBYTES]),'','') == false)
          assert(pcall(lib[open_afternm],string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),'') == false)
        end)

        it('should decrypt messages', function()
          local encrypted = expected_mac_str .. expected_cipher_str
          local decrypted = lib[open_afternm](encrypted,nonce,decryption_k)
          assert(string.len(decrypted) == string.len(message))
          assert(decrypted == message)
        end)

        it('should error on decryption failure', function()
          local encrypted = string.rep('\0',lib[MACBYTES]) .. expected_cipher_str
          assert(pcall(lib[open_afternm],encrypted,nonce,decryption_k) == false)
        end)
      end)

    end)
  end


  describe('crypto_box functions', function()
    local sender_pk, sender_sk =
      lib.crypto_box_seed_keypair(string.rep(string.char(0),lib.crypto_box_SEEDBYTES))
    local receiver_pk, receiver_sk =
      lib.crypto_box_seed_keypair(string.rep(string.char(255),lib.crypto_box_SEEDBYTES))
    local nonce = string.rep(string.char(0),lib.crypto_box_NONCEBYTES)

    describe('function crypto_box', function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib.crypto_box) == false)
        assert(pcall(lib.crypto_box,'','','','') == false)
        assert(pcall(lib.crypto_box,'',string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
        assert(pcall(lib.crypto_box,'',string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)
      end)

      it('should encrypt messages', function()
        local encrypted = lib.crypto_box(message,nonce,receiver_pk,sender_sk)
        assert(string.len(encrypted) == (string.len(message) + lib.crypto_box_MACBYTES))
        for i=1,lib.crypto_box_MACBYTES do
          assert(string.byte(encrypted,i) == expected_mac[i])
        end
        for i=lib.crypto_box_MACBYTES+1,lib.crypto_box_MACBYTES+string.len(message) do
          assert(string.byte(encrypted,i) == expected_cipher[i - lib.crypto_box_MACBYTES])
        end
      end)
    end)

    describe('function crypto_box_open', function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib.crypto_box_open) == false)
        assert(pcall(lib.crypto_box_open,'','','','') == false)
        assert(pcall(lib.crypto_box_open,string.rep('\0',lib.crypto_box_MACBYTES),'','','') == false)
        assert(pcall(lib.crypto_box_open,string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
        assert(pcall(lib.crypto_box_open,string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)
      end)

      it('should decrypt messages', function()
        local encrypted = expected_mac_str .. expected_cipher_str
        local decrypted = lib.crypto_box_open(encrypted,nonce,sender_pk,receiver_sk)
        assert(string.len(decrypted) == string.len(message))
        assert(decrypted == message)
      end)

      it('should error on decryption failure', function()
        local encrypted = string.rep('\0',lib.crypto_box_MACBYTES) .. expected_cipher_str
        assert(pcall(lib.crypto_box_open,encrypted,nonce,sender_pk,receiver_sk) == false)
      end)
    end)

    describe('function crypto_box_easy', function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib.crypto_box_easy) == false)
        assert(pcall(lib.crypto_box_easy,'','','','') == false)
        assert(pcall(lib.crypto_box_easy,'',string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
        assert(pcall(lib.crypto_box_easy,'',string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)
      end)

      it('should encrypt messages', function()
        local encrypted = lib.crypto_box_easy(message,nonce,receiver_pk,sender_sk)
        assert(string.len(encrypted) == (string.len(message) + lib.crypto_box_MACBYTES))
        for i=1,lib.crypto_box_MACBYTES do
          assert(string.byte(encrypted,i) == expected_mac[i])
        end
        for i=lib.crypto_box_MACBYTES+1,lib.crypto_box_MACBYTES+string.len(message) do
          assert(string.byte(encrypted,i) == expected_cipher[i - lib.crypto_box_MACBYTES])
        end
      end)
    end)

    describe('function crypto_box_open_easy', function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib.crypto_box_open_easy) == false)
        assert(pcall(lib.crypto_box_open_easy,'','','','') == false)
        assert(pcall(lib.crypto_box_open_easy,string.rep('\0',lib.crypto_box_MACBYTES),'','','') == false)
        assert(pcall(lib.crypto_box_open_easy,string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
        assert(pcall(lib.crypto_box_open_easy,string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)
      end)

      it('should decrypt messages', function()
        local encrypted = expected_mac_str .. expected_cipher_str
        local decrypted = lib.crypto_box_open_easy(encrypted,nonce,sender_pk,receiver_sk)
        assert(string.len(decrypted) == string.len(message))
        assert(decrypted == message)
      end)

      it('should error on a decryption failure', function()
        local encrypted = string.rep('\0',lib.crypto_box_MACBYTES) .. expected_cipher_str
        assert(pcall(lib.crypto_box_open_easy,encrypted,nonce,sender_pk,receiver_sk) == false)
      end)
    end)

    describe('function crypto_box_detached', function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib.crypto_box_detached) == false)
        assert(pcall(lib.crypto_box_detached,'','','','') == false)
        assert(pcall(lib.crypto_box_detached,'',string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
        assert(pcall(lib.crypto_box_detached,'',string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)
      end)

      it('should encrypt messages', function()
        local encrypted, mac = lib.crypto_box_detached(message,nonce,receiver_pk,sender_sk)
        assert(string.len(encrypted) == string.len(message))
        assert(string.len(mac) == string.len(expected_mac_str))
        for i=1,lib.crypto_box_MACBYTES do
          assert(string.byte(mac,i) == expected_mac[i])
        end
        for i=1,string.len(message) do
          assert(string.byte(encrypted,i) == expected_cipher[i])
        end
      end)
    end)

    describe('function crypto_box_open_detached', function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib.crypto_box_open_detached) == false)
        assert(pcall(lib.crypto_box_open_detached,'','','','','') == false)
        assert(pcall(lib.crypto_box_open_detached,'',string.rep('\0',lib.crypto_box_MACBYTES),'','','') == false)
        assert(pcall(lib.crypto_box_open_detached,'',string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
        assert(pcall(lib.crypto_box_open_detached,'',string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)
      end)

      it('should decrypt messages', function()
        local decrypted = lib.crypto_box_open_detached(expected_cipher_str,expected_mac_str,nonce,sender_pk,receiver_sk)
        assert(string.len(decrypted) == string.len(message))
        assert(decrypted == message)
      end)

      it('should error on a decryption failure', function()
        local mac = string.rep('\0',lib.crypto_box_MACBYTES)
        assert(pcall(lib.crypto_box_open_detached,expected_cipher_str,mac,nonce,sender_pk,receiver_sk) == false)
      end)
    end)
  end)

  describe('crypto_box_before/afternm functions', function()

    local sender_pk, sender_sk =
      lib.crypto_box_seed_keypair(string.rep(string.char(0),lib.crypto_box_SEEDBYTES))
    local receiver_pk, receiver_sk =
      lib.crypto_box_seed_keypair(string.rep(string.char(255),lib.crypto_box_SEEDBYTES))
    local nonce = string.rep(string.char(0),lib.crypto_box_NONCEBYTES)
    local encryption_k =
      lib.crypto_box_beforenm(receiver_pk,sender_sk)
    local decryption_k =
      lib.crypto_box_beforenm(sender_pk,receiver_sk)


    describe('function crypto_box_easy_afternm', function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib.crypto_box_easy_afternm) == false)
        assert(pcall(lib.crypto_box_easy_afternm,'','','') == false)
        assert(pcall(lib.crypto_box_easy_afternm,'',string.rep('\0',lib.crypto_box_NONCEBYTES),'') == false)
      end)

      it('should encrypt messages', function()
        local encrypted = lib.crypto_box_easy_afternm(message,nonce,encryption_k)
        assert(string.len(encrypted) == (string.len(message) + lib.crypto_box_MACBYTES))
        for i=1,lib.crypto_box_MACBYTES do
          assert(string.byte(encrypted,i) == expected_mac[i])
        end
        for i=lib.crypto_box_MACBYTES+1,lib.crypto_box_MACBYTES+string.len(message) do
          assert(string.byte(encrypted,i) == expected_cipher[i - lib.crypto_box_MACBYTES])
        end
      end)
    end)


    describe('function crypto_box_open_easy_afternm', function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib.crypto_box_open_easy_afternm) == false)
        assert(pcall(lib.crypto_box_open_easy_afternm,'','','') == false)
        assert(pcall(lib.crypto_box_open_easy_afternm,string.rep('\0',lib.crypto_box_MACBYTES),'','') == false)
        assert(pcall(lib.crypto_box_open_easy_afternm,string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),'') == false)
      end)

      it('should decrypt messages', function()
        local encrypted = expected_mac_str .. expected_cipher_str
        local decrypted = lib.crypto_box_open_easy_afternm(encrypted,nonce,decryption_k)
        assert(string.len(decrypted) == string.len(message))
        assert(decrypted == message)
      end)

      it('should error on decryption failure', function()
        local encrypted = string.rep('\0',lib.crypto_box_MACBYTES) .. expected_cipher_str
        assert(pcall(lib.crypto_box_open_easy_afternm,encrypted,nonce,decryption_k) == false)
      end)
    end)

    describe('function crypto_box_detached_afternm', function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib.crypto_box_detached_afternm) == false)
        assert(pcall(lib.crypto_box_detached_afternm,'','','','','') == false)
        assert(pcall(lib.crypto_box_detached_afternm,'',string.rep('\0',lib.crypto_box_NONCEBYTES),'') == false)
      end)

      it('should encrypt messages', function()
        local encrypted, mac = lib.crypto_box_detached_afternm(message,nonce,encryption_k)
        assert(string.len(encrypted) == string.len(message))
        assert(string.len(mac) == string.len(expected_mac_str))
        for i=1,lib.crypto_box_MACBYTES do
          assert(string.byte(mac,i) == expected_mac[i])
        end
        for i=1,string.len(message) do
          assert(string.byte(encrypted,i) == expected_cipher[i])
        end
      end)
    end)

    describe('function crypto_box_open_detached_afternm', function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib.crypto_box_open_detached_afternm) == false)
        assert(pcall(lib.crypto_box_open_detached_afternm,'','','','') == false)
        assert(pcall(lib.crypto_box_open_detached_afternm,'',string.rep('\0',lib.crypto_box_MACBYTES),'','') == false)
        assert(pcall(lib.crypto_box_open_detached_afternm,'',string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),'') == false)
      end)

      it('should decrypt messages', function()
        local decrypted = lib.crypto_box_open_detached_afternm(expected_cipher_str,expected_mac_str,nonce,decryption_k)
        assert(string.len(decrypted) == string.len(message))
        assert(decrypted == message)
      end)

      it('should error on decryption failure', function()
        local mac = string.rep('\0',lib.crypto_box_MACBYTES)
        assert(pcall(lib.crypto_box_open_detached,expected_cipher_str,mac,nonce,decryption_k) == false)
      end)
    end)
  end)
end)


