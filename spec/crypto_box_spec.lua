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

describe('crypto_box', function()
  it('should be a library', function()
    assert(type(lib) == 'table')
  end)

  it('should throw errors on invalid calls', function()
    assert(pcall(lib.crypto_box_seed_keypair) == false)
    assert(pcall(lib.crypto_box_seed_keypair,'') == false)

    assert(pcall(lib.crypto_box) == false)
    assert(pcall(lib.crypto_box,'','','','') == false)
    assert(pcall(lib.crypto_box,'',string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
    assert(pcall(lib.crypto_box,'',string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)

    assert(pcall(lib.crypto_box_open) == false)
    assert(pcall(lib.crypto_box_open,'','','','') == false)
    assert(pcall(lib.crypto_box_open,string.rep('\0',lib.crypto_box_MACBYTES),'','','') == false)
    assert(pcall(lib.crypto_box_open,string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
    assert(pcall(lib.crypto_box_open,string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)

    assert(pcall(lib.crypto_box_easy) == false)
    assert(pcall(lib.crypto_box_easy,'','','','') == false)
    assert(pcall(lib.crypto_box_easy,'',string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
    assert(pcall(lib.crypto_box_easy,'',string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)

    assert(pcall(lib.crypto_box_open_easy) == false)
    assert(pcall(lib.crypto_box_open_easy,'','','','') == false)
    assert(pcall(lib.crypto_box_open_easy,string.rep('\0',lib.crypto_box_MACBYTES),'','','') == false)
    assert(pcall(lib.crypto_box_open_easy,string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
    assert(pcall(lib.crypto_box_open_easy,string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)

    assert(pcall(lib.crypto_box_detached) == false)
    assert(pcall(lib.crypto_box_detached,'','','','') == false)
    assert(pcall(lib.crypto_box_detached,'',string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
    assert(pcall(lib.crypto_box_detached,'',string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)

    assert(pcall(lib.crypto_box_open_detached) == false)
    assert(pcall(lib.crypto_box_open_detached,'','','','','') == false)
    assert(pcall(lib.crypto_box_open_detached,'',string.rep('\0',lib.crypto_box_MACBYTES),'','','') == false)
    assert(pcall(lib.crypto_box_open_detached,'',string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),'','') == false)
    assert(pcall(lib.crypto_box_open_detached,'',string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)

    assert(pcall(lib.crypto_box_beforenm) == false)
    assert(pcall(lib.crypto_box_beforenm,'','') == false)
    assert(pcall(lib.crypto_box_beforenm,string.rep('\0',lib.crypto_box_PUBLICKEYBYTES),'') == false)

    assert(pcall(lib.crypto_box_easy_afternm) == false)
    assert(pcall(lib.crypto_box_easy_afternm,'','','') == false)
    assert(pcall(lib.crypto_box_easy_afternm,'',string.rep('\0',lib.crypto_box_NONCEBYTES),'') == false)

    assert(pcall(lib.crypto_box_afternm) == false)
    assert(pcall(lib.crypto_box_afternm,'','','') == false)
    assert(pcall(lib.crypto_box_afternm,'',string.rep('\0',lib.crypto_box_NONCEBYTES),'') == false)

    assert(pcall(lib.crypto_box_open_easy_afternm) == false)
    assert(pcall(lib.crypto_box_open_easy_afternm,'','','') == false)
    assert(pcall(lib.crypto_box_open_easy_afternm,string.rep('\0',lib.crypto_box_MACBYTES),'','') == false)
    assert(pcall(lib.crypto_box_open_easy_afternm,string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),'') == false)

    assert(pcall(lib.crypto_box_open_afternm) == false)
    assert(pcall(lib.crypto_box_open_afternm,'','','') == false)
    assert(pcall(lib.crypto_box_open_afternm,string.rep('\0',lib.crypto_box_MACBYTES),'','') == false)
    assert(pcall(lib.crypto_box_open_afternm,string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),'') == false)

    assert(pcall(lib.crypto_box_detached_afternm) == false)
    assert(pcall(lib.crypto_box_detached_afternm,'','','','','') == false)
    assert(pcall(lib.crypto_box_detached_afternm,'',string.rep('\0',lib.crypto_box_NONCEBYTES),'') == false)

    assert(pcall(lib.crypto_box_open_detached_afternm) == false)
    assert(pcall(lib.crypto_box_open_detached_afternm,'','','','') == false)
    assert(pcall(lib.crypto_box_open_detached_afternm,'',string.rep('\0',lib.crypto_box_MACBYTES),'','') == false)
    assert(pcall(lib.crypto_box_open_detached_afternm,'',string.rep('\0',lib.crypto_box_MACBYTES),string.rep('\0',lib.crypto_box_NONCEBYTES),'') == false)


  end)

  it('keypair tests', function()
    local pk, sk = lib.crypto_box_keypair()
    assert(string.len(pk) == lib.crypto_box_PUBLICKEYBYTES)
    assert(string.len(sk) == lib.crypto_box_SECRETKEYBYTES)
  end)

  it('encrypt/decrypt tests', function()
    local seed = string.rep('\0',lib.crypto_box_SEEDBYTES)
    local pk, sk = lib.crypto_box_seed_keypair(seed)
    assert(string.len(pk) == lib.crypto_box_PUBLICKEYBYTES)
    assert(string.len(sk) == lib.crypto_box_SECRETKEYBYTES)

    local expected_pk = {
      91, 245, 92, 115, 184, 46, 190, 34,
      190, 128, 243, 67, 6, 103, 175, 87,
      15, 174, 37, 86, 166, 65, 94, 107,
      48, 212, 6, 83, 0, 170, 148, 125,
    }

    local expected_sk = {
      80, 70, 173, 193, 219, 168, 56, 134,
      123, 43, 187, 253, 208, 195, 66, 62,
      88, 181, 121, 112, 181, 38, 122, 144,
      245, 121, 96, 146, 74, 135, 241, 150,
    }

    for i=1,string.len(pk) do
      assert(string.byte(pk,i) == expected_pk[i])
    end

    for i=1,string.len(sk) do
      assert(string.byte(sk,i) == expected_sk[i])
    end
  end)

  describe('known seed tests', function()

    local sender_seed   = string.rep(string.char(0)  ,lib.crypto_box_SEEDBYTES)
    local receiver_seed = string.rep(string.char(255),lib.crypto_box_SEEDBYTES)
    local nonce = string.rep(string.char(0),lib.crypto_box_NONCEBYTES)
    local sender_pk, sender_sk = lib.crypto_box_seed_keypair(sender_seed)
    local receiver_pk, receiver_sk = lib.crypto_box_seed_keypair(receiver_seed)
    local message = 'hello there'

    it('should encrypt/decrypt messages', function()
      local encrypted = lib.crypto_box_easy(message,nonce,receiver_pk,sender_sk)
      local decrypted = lib.crypto_box_open_easy(encrypted,nonce,sender_pk,receiver_sk)
      assert(decrypted == message)
      assert(lib.crypto_box(message,nonce,receiver_pk,sender_sk) == encrypted)
      assert(lib.crypto_box_open(encrypted,nonce,sender_pk,receiver_sk) == message)
      local em = string.sub(encrypted,lib.crypto_box_MACBYTES+1)
      assert(string.len(em) == string.len(message))
      assert(pcall(lib.crypto_box_open,string.rep('\0',lib.crypto_box_MACBYTES) .. em,nonce, sender_pk,receiver_pk) == false)
      assert(pcall(lib.crypto_box_open_easy,string.rep('\0',lib.crypto_box_MACBYTES) .. em,nonce, sender_pk,receiver_pk) == false)
    end)

    it('should encrypt/decrypt detached messages', function()
      local message = 'hello there detached'
      local encrypted, mac = lib.crypto_box_detached(message,nonce,receiver_pk,sender_sk)
      local decrypted = lib.crypto_box_open_detached(encrypted,mac,nonce,sender_pk,receiver_sk)
      assert(decrypted == message)
      assert(pcall(lib.crypto_box_open_detached,encrypted,string.rep('\0',lib.crypto_box_MACBYTES),nonce,sender_pk,receiver_sk)
        == false)
    end)

    it('should encrypt/decrypt before/afternm messages', function()
      local message, k, ok, encrypted, decrypted, mac
      message = 'hello there'
      k = lib.crypto_box_beforenm(receiver_pk,sender_sk)
      ok = lib.crypto_box_beforenm(sender_pk,receiver_sk)

      encrypted = lib.crypto_box_easy_afternm(message,nonce,k)
      decrypted = lib.crypto_box_open_easy(encrypted,nonce,sender_pk,receiver_sk)
      assert(decrypted == message)

      decrypted = lib.crypto_box_open_easy_afternm(encrypted,nonce,k)
      assert(decrypted == message)

      assert(lib.crypto_box_afternm(message,nonce,k) == encrypted)
      assert(lib.crypto_box_open_afternm(encrypted,nonce,k) == message)

      decrypted = lib.crypto_box_open_easy_afternm(encrypted,nonce,ok)
      assert(decrypted == message)

      assert(pcall(lib.crypto_box_open_afternm,encrypted,nonce,string.rep('\0',lib.crypto_box_BEFORENMBYTES)) == false)
      assert(pcall(lib.crypto_box_open_easy_afternm,encrypted,nonce,string.rep('\0',lib.crypto_box_BEFORENMBYTES)) == false)

      encrypted, mac = lib.crypto_box_detached_afternm(message,nonce,k)

      decrypted = lib.crypto_box_open_detached(encrypted,mac,nonce,sender_pk,receiver_sk)
      assert(decrypted == message)

      decrypted = lib.crypto_box_open_detached_afternm(encrypted,mac,nonce,ok)
      assert(decrypted == message)


    end)
  end)
end)

