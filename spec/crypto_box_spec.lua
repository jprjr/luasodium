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

local message = 'hello'

local expected_results = {
  ['crypto_box'] = {
    ['sender_pk'] = {
       91, 245, 92, 115, 184, 46, 190, 34,
       190, 128, 243, 67, 6, 103, 175, 87,
       15, 174, 37, 86, 166, 65, 94, 107,
       48, 212, 6, 83, 0, 170, 148, 125,
    },
    ['sender_sk'] = {
       80, 70, 173, 193, 219, 168, 56, 134,
       123, 43, 187, 253, 208, 195, 66, 62,
       88, 181, 121, 112, 181, 38, 122, 144,
       245, 121, 96, 146, 74, 135, 241, 150,
    },
    ['receiver_pk'] = {
       209, 250, 63, 1, 130, 107, 216, 183,
       142, 5, 124, 8, 108, 123, 34, 199,
       173, 67, 88, 202, 145, 128, 153, 205,
       123, 126, 93, 58, 205, 126, 40, 91,
    },
    ['receiver_sk'] = {
       39, 205, 105, 53, 134, 71, 22, 167,
       157, 116, 221, 95, 171, 189, 137, 100,
       48, 64, 81, 202, 65, 163, 28, 70,
       89, 21, 142, 187, 124, 61, 11, 151,
    },
    ['beforenm_encrypt'] = {
       84, 120, 45, 227, 119, 175, 42, 125,
       37, 36, 242, 247, 145, 123, 75, 191,
       102, 101, 8, 172, 56, 216, 58, 13,
       151, 53, 5, 228, 46, 148, 133, 246,
    },
    ['beforenm_decrypt'] = {
       84, 120, 45, 227, 119, 175, 42, 125,
       37, 36, 242, 247, 145, 123, 75, 191,
       102, 101, 8, 172, 56, 216, 58, 13,
       151, 53, 5, 228, 46, 148, 133, 246,
    },
    ['mac'] = {
       34, 189, 69, 142, 159, 103, 169, 18,
       185, 43, 180, 114, 77, 226, 0, 175,
    },
    ['cipher'] = {
       16, 97, 18, 38, 131,
    },
  },
  ['crypto_box_curve25519xsalsa20poly1305'] = {
    ['sender_pk'] = {
       91, 245, 92, 115, 184, 46, 190, 34,
       190, 128, 243, 67, 6, 103, 175, 87,
       15, 174, 37, 86, 166, 65, 94, 107,
       48, 212, 6, 83, 0, 170, 148, 125,
    },
    ['sender_sk'] = {
       80, 70, 173, 193, 219, 168, 56, 134,
       123, 43, 187, 253, 208, 195, 66, 62,
       88, 181, 121, 112, 181, 38, 122, 144,
       245, 121, 96, 146, 74, 135, 241, 150,
    },
    ['receiver_pk'] = {
       209, 250, 63, 1, 130, 107, 216, 183,
       142, 5, 124, 8, 108, 123, 34, 199,
       173, 67, 88, 202, 145, 128, 153, 205,
       123, 126, 93, 58, 205, 126, 40, 91,
    },
    ['receiver_sk'] = {
       39, 205, 105, 53, 134, 71, 22, 167,
       157, 116, 221, 95, 171, 189, 137, 100,
       48, 64, 81, 202, 65, 163, 28, 70,
       89, 21, 142, 187, 124, 61, 11, 151,
    },
    ['beforenm_encrypt'] = {
       84, 120, 45, 227, 119, 175, 42, 125,
       37, 36, 242, 247, 145, 123, 75, 191,
       102, 101, 8, 172, 56, 216, 58, 13,
       151, 53, 5, 228, 46, 148, 133, 246,
    },
    ['beforenm_decrypt'] = {
       84, 120, 45, 227, 119, 175, 42, 125,
       37, 36, 242, 247, 145, 123, 75, 191,
       102, 101, 8, 172, 56, 216, 58, 13,
       151, 53, 5, 228, 46, 148, 133, 246,
    },
    ['mac'] = {
       34, 189, 69, 142, 159, 103, 169, 18,
       185, 43, 180, 114, 77, 226, 0, 175,
    },
    ['cipher'] = {
       16, 97, 18, 38, 131,
    },
  },
  ['crypto_box_easy'] = {
    ['sender_pk'] = {
       91, 245, 92, 115, 184, 46, 190, 34,
       190, 128, 243, 67, 6, 103, 175, 87,
       15, 174, 37, 86, 166, 65, 94, 107,
       48, 212, 6, 83, 0, 170, 148, 125,
    },
    ['sender_sk'] = {
       80, 70, 173, 193, 219, 168, 56, 134,
       123, 43, 187, 253, 208, 195, 66, 62,
       88, 181, 121, 112, 181, 38, 122, 144,
       245, 121, 96, 146, 74, 135, 241, 150,
    },
    ['receiver_pk'] = {
       209, 250, 63, 1, 130, 107, 216, 183,
       142, 5, 124, 8, 108, 123, 34, 199,
       173, 67, 88, 202, 145, 128, 153, 205,
       123, 126, 93, 58, 205, 126, 40, 91,
    },
    ['receiver_sk'] = {
       39, 205, 105, 53, 134, 71, 22, 167,
       157, 116, 221, 95, 171, 189, 137, 100,
       48, 64, 81, 202, 65, 163, 28, 70,
       89, 21, 142, 187, 124, 61, 11, 151,
    },
    ['beforenm_encrypt'] = {
       84, 120, 45, 227, 119, 175, 42, 125,
       37, 36, 242, 247, 145, 123, 75, 191,
       102, 101, 8, 172, 56, 216, 58, 13,
       151, 53, 5, 228, 46, 148, 133, 246,
    },
    ['beforenm_decrypt'] = {
       84, 120, 45, 227, 119, 175, 42, 125,
       37, 36, 242, 247, 145, 123, 75, 191,
       102, 101, 8, 172, 56, 216, 58, 13,
       151, 53, 5, 228, 46, 148, 133, 246,
    },
    ['mac'] = {
       34, 189, 69, 142, 159, 103, 169, 18,
       185, 43, 180, 114, 77, 226, 0, 175,
    },
    ['cipher'] = {
       16, 97, 18, 38, 131,
    },
  },
}

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
    local crypto_box_keypair = string.format('%s_keypair',f)
    local crypto_box_seed_keypair = string.format('%s_seed_keypair',f)
    local crypto_box_beforenm = string.format('%s_beforenm',f)
    local crypto_box = string.format('%s',f)
    local crypto_box_open = string.format('%s_open',f)
    local crypto_box_afternm = string.format('%s_afternm',f)
    local crypto_box_open_afternm = string.format('%s_open_afternm',f)

    local MACBYTES = string.format('%s_MACBYTES',f)
    local NONCEBYTES = string.format('%s_NONCEBYTES',f)
    local PUBLICKEYBYTES = string.format('%s_PUBLICKEYBYTES',f)
    local SECRETKEYBYTES = string.format('%s_SECRETKEYBYTES',f)
    local BEFORENMBYTES = string.format('%s_BEFORENMBYTES',f)
    local SEEDBYTES = string.format('%s_SEEDBYTES',f)
    local nonce = string.rep('\0',lib[NONCEBYTES])

    local sender_pk = tbl_to_str(expected_results[f].sender_pk)
    local sender_sk = tbl_to_str(expected_results[f].sender_sk)
    local receiver_pk = tbl_to_str(expected_results[f].receiver_pk)
    local receiver_sk = tbl_to_str(expected_results[f].receiver_sk)
    local beforenm_encrypt = tbl_to_str(expected_results[f].beforenm_encrypt)
    local beforenm_decrypt = tbl_to_str(expected_results[f].beforenm_decrypt)
    local mac    = tbl_to_str(expected_results[f].mac)
    local cipher = tbl_to_str(expected_results[f].cipher)

    describe('function ' .. crypto_box_keypair, function()
      it('should return a crypto_box_keypair', function()
        local pk, sk = lib[crypto_box_keypair]()
        assert(string.len(pk) == lib[PUBLICKEYBYTES])
        assert(string.len(sk) == lib[SECRETKEYBYTES])
      end)
    end)

    describe('function ' .. crypto_box_beforenm, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_beforenm]) == false)
        assert(pcall(lib[crypto_box_beforenm],'','') == false)
        assert(pcall(lib[crypto_box_beforenm],string.rep('\0',lib[PUBLICKEYBYTES]),'') == false)
      end)
    end)

    describe('function ' .. crypto_box_seed_keypair, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_seed_keypair]) == false)
        assert(pcall(lib[crypto_box_seed_keypair],'') == false)
      end)

      it('should return keys for some known seeds', function()
        local s_pk, s_sk = lib[crypto_box_seed_keypair](string.rep(string.char(0),lib[SEEDBYTES]))
        local r_pk, r_sk = lib[crypto_box_seed_keypair](string.rep(string.char(255),lib[SEEDBYTES]))
        local crypto_box_beforenm_ekey = lib[crypto_box_beforenm](s_pk,r_sk)
        local crypto_box_beforenm_dkey = lib[crypto_box_beforenm](r_pk,s_sk)
        assert(string.len(s_pk) == lib[PUBLICKEYBYTES])
        assert(string.len(s_sk) == lib[SECRETKEYBYTES])
        assert(string.len(r_pk) == lib[PUBLICKEYBYTES])
        assert(string.len(r_sk) == lib[SECRETKEYBYTES])
        assert(string.len(crypto_box_beforenm_ekey) == lib[BEFORENMBYTES])
        assert(string.len(crypto_box_beforenm_dkey) == lib[BEFORENMBYTES])

        assert(s_pk == sender_pk)
        assert(r_pk == receiver_pk)

        assert(s_sk == sender_sk)
        assert(r_sk == receiver_sk)

        assert(crypto_box_beforenm_ekey == beforenm_encrypt)
        assert(crypto_box_beforenm_dkey == beforenm_decrypt)
      end)
    end)

    describe('function ' .. crypto_box, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[f]) == false)
        assert(pcall(lib[f],'','','','') == false)
        assert(pcall(lib[f],'',string.rep('\0',lib[NONCEBYTES]),'','') == false)
        assert(pcall(lib[f],'',string.rep('\0',lib[NONCEBYTES]),string.rep('\0',lib[PUBLICKEYBYTES]),'') == false)
      end)

      it('should encrypt messages', function()
        local encrypted = lib[f](message,nonce,receiver_pk,sender_sk)
        assert(string.len(encrypted) == (string.len(message) + lib[MACBYTES]))
        assert( (mac .. cipher) == encrypted)
      end)
    end)

    describe('function ' .. crypto_box_open, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_open]) == false)
        assert(pcall(lib[crypto_box_open],'','','','') == false)
        assert(pcall(lib[crypto_box_open],string.rep('\0',lib[MACBYTES]),'','','') == false)
        assert(pcall(lib[crypto_box_open],string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),'','') == false)
        assert(pcall(lib[crypto_box_open],string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),string.rep('\0',lib[PUBLICKEYBYTES]),'') == false)
      end)

      it('should decrypt messages', function()
        local encrypted = mac .. cipher
        local decrypted = lib[crypto_box_open](encrypted,nonce,sender_pk,receiver_sk)
        assert(string.len(decrypted) == string.len(message))
        assert(decrypted == message)
      end)

      it('should error on decryption failure', function()
        local encrypted = string.rep('\0',lib[MACBYTES]) .. cipher
        assert(pcall(lib[crypto_box_open],encrypted,nonce,sender_pk,receiver_sk) == false)
      end)
    end)

    describe('function ' .. crypto_box_afternm, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_afternm]) == false)
        assert(pcall(lib[crypto_box_afternm],'','','') == false)
        assert(pcall(lib[crypto_box_afternm],'',string.rep('\0',lib[NONCEBYTES]),'') == false)
      end)

      it('should encrypt messages', function()
        local encrypted = lib[crypto_box_afternm](message,nonce,beforenm_encrypt)
        assert(string.len(encrypted) == (string.len(message) + lib[MACBYTES]))
        assert( (mac .. cipher) == encrypted)
      end)
    end)

    describe('function ' .. crypto_box_open_afternm, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_open_afternm]) == false)
        assert(pcall(lib[crypto_box_open_afternm],'','','') == false)
        assert(pcall(lib[crypto_box_open_afternm],string.rep('\0',lib[MACBYTES]),'','') == false)
        assert(pcall(lib[crypto_box_open_afternm],string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),'') == false)
      end)

      it('should decrypt messages', function()
        local encrypted = mac .. cipher
        local decrypted = lib[crypto_box_open_afternm](encrypted,nonce,beforenm_decrypt)
        assert(string.len(decrypted) == string.len(message))
        assert(decrypted == message)
      end)

      it('should error on decryption failure', function()
        local encrypted = string.rep('\0',lib[MACBYTES]) .. cipher
        assert(pcall(lib[crypto_box_open_afternm],encrypted,nonce,beforenm_decrypt) == false)
      end)
    end)
  end

  for _,f in ipairs({
    'crypto_box',
  }) do
    local crypto_box_keypair = string.format('%s_keypair',f)
    local crypto_box_seed_keypair = string.format('%s_seed_keypair',f)
    local crypto_box_beforenm = string.format('%s_beforenm',f)

    local crypto_box_easy = string.format('%s_easy',f)
    local crypto_box_open_easy = string.format('%s_open_easy',f)
    local crypto_box_detached = string.format('%s_detached',f)
    local crypto_box_open_detached = string.format('%s_open_detached',f)

    local crypto_box_easy_afternm = string.format('%s_easy_afternm',f)
    local crypto_box_open_easy_afternm = string.format('%s_open_easy_afternm',f)
    local crypto_box_detached_afternm = string.format('%s_detached_afternm',f)
    local crypto_box_open_detached_afternm = string.format('%s_open_detached_afternm',f)

    local MACBYTES = string.format('%s_MACBYTES',f)
    local NONCEBYTES = string.format('%s_NONCEBYTES',f)
    local PUBLICKEYBYTES = string.format('%s_PUBLICKEYBYTES',f)
    local SECRETKEYBYTES = string.format('%s_SECRETKEYBYTES',f)
    local BEFORENMBYTES = string.format('%s_BEFORENMBYTES',f)
    local SEEDBYTES = string.format('%s_SEEDBYTES',f)
    local nonce = string.rep('\0',lib[NONCEBYTES])

    local sender_pk = tbl_to_str(expected_results[crypto_box_easy].sender_pk)
    local sender_sk = tbl_to_str(expected_results[crypto_box_easy].sender_sk)
    local receiver_pk = tbl_to_str(expected_results[crypto_box_easy].receiver_pk)
    local receiver_sk = tbl_to_str(expected_results[crypto_box_easy].receiver_sk)
    local beforenm_encrypt = tbl_to_str(expected_results[crypto_box_easy].beforenm_encrypt)
    local beforenm_decrypt = tbl_to_str(expected_results[crypto_box_easy].beforenm_decrypt)
    local mac    = tbl_to_str(expected_results[crypto_box_easy].mac)
    local cipher = tbl_to_str(expected_results[crypto_box_easy].cipher)

    describe('function ' .. crypto_box_keypair, function()
      it('should return a crypto_box_keypair', function()
        local pk, sk = lib[crypto_box_keypair]()
        assert(string.len(pk) == lib[PUBLICKEYBYTES])
        assert(string.len(sk) == lib[SECRETKEYBYTES])
      end)
    end)

    describe('function ' .. crypto_box_beforenm, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_beforenm]) == false)
        assert(pcall(lib[crypto_box_beforenm],'','') == false)
        assert(pcall(lib[crypto_box_beforenm],string.rep('\0',lib[PUBLICKEYBYTES]),'') == false)
      end)
    end)

    describe('function ' .. crypto_box_seed_keypair, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_seed_keypair]) == false)
        assert(pcall(lib[crypto_box_seed_keypair],'') == false)
      end)

      it('should return keys for some known seeds', function()
        local s_pk, s_sk = lib[crypto_box_seed_keypair](string.rep(string.char(0),lib[SEEDBYTES]))
        local r_pk, r_sk = lib[crypto_box_seed_keypair](string.rep(string.char(255),lib[SEEDBYTES]))
        local crypto_box_beforenm_ekey = lib[crypto_box_beforenm](s_pk,r_sk)
        local crypto_box_beforenm_dkey = lib[crypto_box_beforenm](r_pk,s_sk)
        assert(string.len(s_pk) == lib[PUBLICKEYBYTES])
        assert(string.len(s_sk) == lib[SECRETKEYBYTES])
        assert(string.len(r_pk) == lib[PUBLICKEYBYTES])
        assert(string.len(r_sk) == lib[SECRETKEYBYTES])
        assert(string.len(crypto_box_beforenm_ekey) == lib[BEFORENMBYTES])
        assert(string.len(crypto_box_beforenm_dkey) == lib[BEFORENMBYTES])

        assert(s_pk == sender_pk)
        assert(r_pk == receiver_pk)

        assert(s_sk == sender_sk)
        assert(r_sk == receiver_sk)

        assert(crypto_box_beforenm_ekey == beforenm_encrypt)
        assert(crypto_box_beforenm_dkey == beforenm_decrypt)
      end)
    end)

    describe('function ' .. crypto_box_easy, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_easy]) == false)
        assert(pcall(lib[crypto_box_easy],'','','','') == false)
        assert(pcall(lib[crypto_box_easy],'',string.rep('\0',lib[NONCEBYTES]),'','') == false)
        assert(pcall(lib[crypto_box_easy],'',string.rep('\0',lib[NONCEBYTES]),string.rep('\0',lib[PUBLICKEYBYTES]),'') == false)
      end)

      it('should encrypt messages', function()
        local encrypted = lib[crypto_box_easy](message,nonce,receiver_pk,sender_sk)
        assert(string.len(encrypted) == (string.len(message) + lib[MACBYTES]))
        assert( (mac .. cipher) == encrypted)
      end)
    end)

    describe('function ' .. crypto_box_open_easy, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_open_easy]) == false)
        assert(pcall(lib[crypto_box_open_easy],'','','','') == false)
        assert(pcall(lib[crypto_box_open_easy],string.rep('\0',lib[MACBYTES]),'','','') == false)
        assert(pcall(lib[crypto_box_open_easy],string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),'','') == false)
        assert(pcall(lib[crypto_box_open_easy],string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),string.rep('\0',lib[PUBLICKEYBYTES]),'') == false)
      end)

      it('should decrypt messages', function()
        local encrypted = mac .. cipher
        local decrypted = lib[crypto_box_open_easy](encrypted,nonce,sender_pk,receiver_sk)
        assert(string.len(decrypted) == string.len(message))
        assert(decrypted == message)
      end)

      it('should error on decryption failure', function()
        local encrypted = string.rep('\0',lib[MACBYTES]) .. cipher
        assert(pcall(lib[crypto_box_open_easy],encrypted,nonce,sender_pk,receiver_sk) == false)
      end)
    end)

    describe('function ' .. crypto_box_detached, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_detached]) == false)
        assert(pcall(lib[crypto_box_detached],'','','','') == false)
        assert(pcall(lib[crypto_box_detached],'',string.rep('\0',lib[NONCEBYTES]),'','') == false)
        assert(pcall(lib[crypto_box_detached],'',string.rep('\0',lib[NONCEBYTES]),string.rep('\0',lib[PUBLICKEYBYTES]),'') == false)
      end)

      it('should encrypt messages', function()
        local encrypted, tag = lib[crypto_box_detached](message,nonce,receiver_pk,sender_sk)
        assert(string.len(encrypted) == string.len(message))
        assert(tag == mac)
        assert(encrypted == cipher)
      end)
    end)

    describe('function ' .. crypto_box_open_detached, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_open_detached]) == false)
        assert(pcall(lib[crypto_box_open_detached],'','','','','') == false)
        assert(pcall(lib[crypto_box_open_detached],'',string.rep('\0',lib[MACBYTES]),'','','') == false)
        assert(pcall(lib[crypto_box_open_detached],'',string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),'','') == false)
        assert(pcall(lib[crypto_box_open_detached],'',string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),string.rep('\0',lib[PUBLICKEYBYTES]),'') == false)
      end)

      it('should decrypt messages', function()
        local decrypted = lib[crypto_box_open_detached](cipher,mac,nonce,sender_pk,receiver_sk)
        assert(string.len(decrypted) == string.len(message))
        assert(decrypted == message)
      end)

      it('should error on decryption failure', function()
        local tag = string.rep('\0',lib[MACBYTES])
        assert(pcall(lib[crypto_box_open_detached],cipher,tag,nonce,sender_pk,receiver_sk) == false)
      end)
    end)

    describe('function ' .. crypto_box_easy_afternm, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_easy_afternm]) == false)
        assert(pcall(lib[crypto_box_easy_afternm],'','','') == false)
        assert(pcall(lib[crypto_box_easy_afternm],'',string.rep('\0',lib[NONCEBYTES]),'') == false)
      end)

      it('should encrypt messages', function()
        local encrypted = lib[crypto_box_easy_afternm](message,nonce,beforenm_encrypt)
        assert(string.len(encrypted) == (string.len(message) + lib[MACBYTES]))
        assert( (mac .. cipher) == encrypted)
      end)
    end)

    describe('function ' .. crypto_box_open_easy_afternm, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_open_easy_afternm]) == false)
        assert(pcall(lib[crypto_box_open_easy_afternm],'','','') == false)
        assert(pcall(lib[crypto_box_open_easy_afternm],string.rep('\0',lib[MACBYTES]),'','') == false)
        assert(pcall(lib[crypto_box_open_easy_afternm],string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),'') == false)
      end)

      it('should decrypt messages', function()
        local encrypted = mac .. cipher
        local decrypted = lib[crypto_box_open_easy_afternm](encrypted,nonce,beforenm_decrypt)
        assert(string.len(decrypted) == string.len(message))
        assert(decrypted == message)
      end)

      it('should error on decryption failure', function()
        local encrypted = string.rep('\0',lib[MACBYTES]) .. cipher
        assert(pcall(lib[crypto_box_open_easy_afternm],encrypted,nonce,beforenm_decrypt) == false)
      end)
    end)

    describe('function ' .. crypto_box_detached_afternm, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_detached_afternm]) == false)
        assert(pcall(lib[crypto_box_detached_afternm],'','','') == false)
        assert(pcall(lib[crypto_box_detached_afternm],'',string.rep('\0',lib[NONCEBYTES]),'') == false)
      end)

      it('should encrypt messages', function()
        local encrypted, tag = lib[crypto_box_detached_afternm](message,nonce,beforenm_encrypt)
        assert(string.len(cipher) == string.len(encrypted))
        assert(string.len(message) == string.len(encrypted))
        assert(string.len(tag) == string.len(mac))
        assert(string.len(tag) == lib[MACBYTES])
        assert(tag == mac)
        assert(encrypted == cipher)
      end)
    end)

    describe('function ' .. crypto_box_open_detached_afternm, function()
      it('should throw errors on invalid calls', function()
        assert(pcall(lib[crypto_box_open_detached_afternm]) == false)
        assert(pcall(lib[crypto_box_open_detached_afternm],'','','','') == false)
        assert(pcall(lib[crypto_box_open_detached_afternm],'',string.rep('\0',lib[MACBYTES]),'','') == false)
        assert(pcall(lib[crypto_box_open_detached_afternm],'',string.rep('\0',lib[MACBYTES]),string.rep('\0',lib[NONCEBYTES]),'') == false)
      end)

      it('should decrypt messages', function()
        local decrypted = lib[crypto_box_open_detached_afternm](cipher,mac,nonce,beforenm_decrypt)
        assert(string.len(decrypted) == string.len(message))
        assert(decrypted == message)
      end)

      it('should error on decryption failure', function()
        local tag = string.rep('\0',lib[MACBYTES])
        assert(pcall(lib[crypto_box_open_detached_afternm],cipher,tag,nonce,beforenm_decrypt) == false)
      end)
    end)
  end
end)

