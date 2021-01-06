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
  lib = require'luasodium.crypto_sign'
  assert(type(lib) == 'table')
  libs['luasodium.crypto_sign'] = lib
end

for _,t in ipairs({'core','ffi','pureffi'}) do
  for _,m in ipairs({'luasodium.' .. t, 'luasodium.crypto_sign.' .. t}) do
    local ok, lib = pcall(require,m)
    if ok then
      libs[m] = lib
    end
  end
end


local expected_pk = {
  59,106,39,188,206,182,164,45,
  98,163,168,208,42,111,13,115,
  101,50,21,119,29,226,67,166,
  58,192,72,161,139,89,218,41,
}

local expected_sk = {
  0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,
  59,106,39,188,206,182,164,45,
  98,163,168,208,42,111,13,115,
  101,50,21,119,29,226,67,166,
  58,192,72,161,139,89,218,41,
}

local expected_sm = {
  226,92,135,35,208,57,254,143,
  69,214,201,214,168,145,127,169,
  27,199,84,145,60,213,150,253,
  53,138,73,58,33,163,203,89,
  10,101,55,186,188,125,240,64,
  10,182,26,5,88,156,156,54,
  182,90,20,56,120,203,3,65,
  212,233,228,132,25,196,55,13,
  104,101,108,108,111,
}

local expected_sig = {
  226,92,135,35,208,57,254,143,
  69,214,201,214,168,145,127,169,
  27,199,84,145,60,213,150,253,
  53,138,73,58,33,163,203,89,
  10,101,55,186,188,125,240,64,
  10,182,26,5,88,156,156,54,
  182,90,20,56,120,203,3,65,
  212,233,228,132,25,196,55,13,
}

local expected_ph_sig = {
  218,45,42,84,141,139,111,248,
  177,117,181,10,109,91,169,124,
  8,104,182,83,222,73,209,224,
  232,53,147,194,248,130,59,97,
  234,183,111,240,235,155,89,60,
  82,215,197,184,147,71,187,146,
  85,86,24,157,32,151,25,163,
  16,118,32,107,201,55,68,8,
}

local m = 'hello'

for name,lib in pairs(libs) do
  describe('crypto_sign_sec: ' .. name, function()
    local seed = string.rep('\0',lib.crypto_sign_SEEDBYTES)

    it('should generate keypairs', function()
      local pk, sk = lib.crypto_sign_keypair()

      assert(string.len(pk) == lib.crypto_sign_PUBLICKEYBYTES)
      assert(string.len(sk) == lib.crypto_sign_SECRETKEYBYTES)
    end)

    it('should generate signatures', function()
      local pk, sk = lib.crypto_sign_seed_keypair(seed)
      local sm = lib.crypto_sign(m,sk)

      for i=1,lib.crypto_sign_PUBLICKEYBYTES do
        assert(string.byte(pk,i) == expected_pk[i])
      end

      for i=1,lib.crypto_sign_SECRETKEYBYTES do
        assert(string.byte(sk,i) == expected_sk[i])
      end

      for i=1,lib.crypto_sign_BYTES + 5 do
        assert(string.byte(sm,i) == expected_sm[i])
      end

      assert(lib.crypto_sign_open(sm,pk) == m)
      assert(lib.crypto_sign_open(sm,string.rep('\1',lib.crypto_sign_PUBLICKEYBYTES)) == nil)

      local sig = lib.crypto_sign_detached(m,sk)

      for i=1,lib.crypto_sign_BYTES do
        assert(string.byte(sig,i) == expected_sm[i])
        assert(string.byte(sig,i) == expected_sig[i])
      end

      assert(lib.crypto_sign_verify_detached(sig,m,pk) == true)
      assert(lib.crypto_sign_verify_detached(sig,'other',pk) == false)

      local state = lib.crypto_sign_init()
      lib.crypto_sign_update(state,m)
      local ph_sig = lib.crypto_sign_final_create(state,sk)

      for i=1,lib.crypto_sign_BYTES do
        assert(string.byte(ph_sig,i) == expected_ph_sig[i])
      end

      state = lib.crypto_sign_init()
      lib.crypto_sign_update(state,m)
      assert(lib.crypto_sign_final_verify(state,ph_sig,pk) == true)

      assert(lib.crypto_sign_ed25519_sk_to_seed(sk) == seed)
      assert(lib.crypto_sign_ed25519_sk_to_pk(sk) == pk)

      assert(pcall(lib.crypto_sign_update,'garbage','garbage') == false)

      state = lib.crypto_sign_init()
      state:update(m)
      assert(state:final_verify(ph_sig,pk) == true)
    end)

    it('should reject bad calls', function()
      assert(pcall(lib.crypto_sign_seed_keypair) == false)
      assert(pcall(lib.crypto_sign_seed_keypair,'') == false)

      assert(pcall(lib.crypto_sign) == false)
      assert(pcall(lib.crypto_sign,'','') == false)

      assert(pcall(lib.crypto_sign_open) == false)
      assert(pcall(lib.crypto_sign_open,'','') == false)

      assert(pcall(lib.crypto_sign_detached) == false)
      assert(pcall(lib.crypto_sign_detached,'','') == false)

      assert(pcall(lib.crypto_sign_verify_detached) == false)
      assert(pcall(lib.crypto_sign_verify_detached,'','','') == false)

      local state = lib.crypto_sign_init()

      assert(pcall(lib.crypto_sign_update) == false)
      assert(pcall(lib.crypto_sign_update,'','') == false)

      assert(pcall(lib.crypto_sign_final_create) == false)
      assert(pcall(lib.crypto_sign_final_create,'','') == false)
      assert(pcall(lib.crypto_sign_final_create,state,'') == false)

      assert(pcall(lib.crypto_sign_final_verify) == false)
      assert(pcall(lib.crypto_sign_final_verify,'','','') == false)
      assert(pcall(lib.crypto_sign_final_verify,state,'','') == false)

      assert(pcall(lib.crypto_sign_ed25519_sk_to_seed) == false)
      assert(pcall(lib.crypto_sign_ed25519_sk_to_pk) == false)
      assert(pcall(lib.crypto_sign_ed25519_sk_to_seed,'') == false)
      assert(pcall(lib.crypto_sign_ed25519_sk_to_pk,'') == false)
    end)

  end)
end
