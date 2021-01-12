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

local message = "a message"
local message1 = 'a '
local message2 = 'message'

local expected_results = {
  ['crypto_sign'] = {
    ['pk'] = {
       59, 106, 39, 188, 206, 182, 164, 45,
       98, 163, 168, 208, 42, 111, 13, 115,
       101, 50, 21, 119, 29, 226, 67, 166,
       58, 192, 72, 161, 139, 89, 218, 41,
    },
    ['sk'] = {
       0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0,
       59, 106, 39, 188, 206, 182, 164, 45,
       98, 163, 168, 208, 42, 111, 13, 115,
       101, 50, 21, 119, 29, 226, 67, 166,
       58, 192, 72, 161, 139, 89, 218, 41,
    },
    ['sm'] = {
       74, 87, 231, 126, 216, 216, 233, 216,
       0, 153, 22, 88, 17, 2, 29, 219,
       255, 95, 71, 63, 59, 55, 234, 110,
       232, 213, 18, 111, 34, 144, 142, 60,
       183, 247, 14, 105, 79, 3, 155, 12,
       17, 115, 166, 164, 160, 169, 34, 57,
       0, 203, 11, 69, 221, 96, 96, 83,
       110, 98, 46, 111, 1, 65, 81, 11,
       97, 32, 109, 101, 115, 115, 97, 103,
       101,
    },
    ['sig'] = {
       74, 87, 231, 126, 216, 216, 233, 216,
       0, 153, 22, 88, 17, 2, 29, 219,
       255, 95, 71, 63, 59, 55, 234, 110,
       232, 213, 18, 111, 34, 144, 142, 60,
       183, 247, 14, 105, 79, 3, 155, 12,
       17, 115, 166, 164, 160, 169, 34, 57,
       0, 203, 11, 69, 221, 96, 96, 83,
       110, 98, 46, 111, 1, 65, 81, 11,
    },
  },
  ['crypto_sign_mp'] = {
    ['sig'] = {
       213, 152, 97, 56, 57, 203, 241, 78,
       185, 156, 160, 116, 45, 50, 54, 214,
       95, 5, 92, 210, 239, 86, 18, 105,
       127, 113, 67, 173, 66, 63, 169, 150,
       61, 122, 144, 182, 17, 204, 12, 196,
       43, 117, 13, 39, 162, 103, 134, 197,
       74, 14, 6, 66, 111, 59, 127, 93,
       60, 35, 126, 191, 71, 133, 215, 0,
    },
  },
  ['crypto_sign_ed25519'] = {
    ['pk'] = {
       59, 106, 39, 188, 206, 182, 164, 45,
       98, 163, 168, 208, 42, 111, 13, 115,
       101, 50, 21, 119, 29, 226, 67, 166,
       58, 192, 72, 161, 139, 89, 218, 41,
    },
    ['sk'] = {
       0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0,
       59, 106, 39, 188, 206, 182, 164, 45,
       98, 163, 168, 208, 42, 111, 13, 115,
       101, 50, 21, 119, 29, 226, 67, 166,
       58, 192, 72, 161, 139, 89, 218, 41,
    },
    ['sm'] = {
       74, 87, 231, 126, 216, 216, 233, 216,
       0, 153, 22, 88, 17, 2, 29, 219,
       255, 95, 71, 63, 59, 55, 234, 110,
       232, 213, 18, 111, 34, 144, 142, 60,
       183, 247, 14, 105, 79, 3, 155, 12,
       17, 115, 166, 164, 160, 169, 34, 57,
       0, 203, 11, 69, 221, 96, 96, 83,
       110, 98, 46, 111, 1, 65, 81, 11,
       97, 32, 109, 101, 115, 115, 97, 103,
       101,
    },
    ['sig'] = {
       74, 87, 231, 126, 216, 216, 233, 216,
       0, 153, 22, 88, 17, 2, 29, 219,
       255, 95, 71, 63, 59, 55, 234, 110,
       232, 213, 18, 111, 34, 144, 142, 60,
       183, 247, 14, 105, 79, 3, 155, 12,
       17, 115, 166, 164, 160, 169, 34, 57,
       0, 203, 11, 69, 221, 96, 96, 83,
       110, 98, 46, 111, 1, 65, 81, 11,
    },
  },
  ['crypto_sign_ed25519_mp'] = {
    ['sig'] = {
       213, 152, 97, 56, 57, 203, 241, 78,
       185, 156, 160, 116, 45, 50, 54, 214,
       95, 5, 92, 210, 239, 86, 18, 105,
       127, 113, 67, 173, 66, 63, 169, 150,
       61, 122, 144, 182, 17, 204, 12, 196,
       43, 117, 13, 39, 162, 103, 134, 197,
       74, 14, 6, 66, 111, 59, 127, 93,
       60, 35, 126, 191, 71, 133, 215, 0,
    },
  },
}


describe('library crypto_sign', function()
  it('should be a library', function()
    assert(type(lib) == 'table')
  end)

  it('should have constants', function()
    assert(type(lib.crypto_sign_PUBLICKEYBYTES) == 'number')
    assert(type(lib.crypto_sign_SECRETKEYBYTES) == 'number')
    assert(type(lib.crypto_sign_SEEDBYTES) == 'number')
    assert(type(lib.crypto_sign_BYTES) == 'number')
    assert(type(lib.crypto_sign_ed25519_PUBLICKEYBYTES) == 'number')
    assert(type(lib.crypto_sign_ed25519_SECRETKEYBYTES) == 'number')
    assert(type(lib.crypto_sign_ed25519_SEEDBYTES) == 'number')
    assert(type(lib.crypto_sign_ed25519_BYTES) == 'number')
  end)

  for _,f in ipairs({
    'crypto_sign',
    'crypto_sign_ed25519',
  }) do

    local crypto_sign_keypair = string.format('%s_keypair',f)
    local crypto_sign_open = string.format('%s_open',f)
    local crypto_sign = string.format('%s',f)

    local PUBLICKEYBYTES = lib[string.format('%s_PUBLICKEYBYTES',f)]
    local SECRETKEYBYTES = lib[string.format('%s_SECRETKEYBYTES',f)]
    local BYTES = lib[string.format('%s_BYTES',f)]
    local SEEDBYTES = lib[string.format('%s_SEEDBYTES',f)]

    local pk = tbl_to_str(expected_results[f].pk)
    local sk = tbl_to_str(expected_results[f].sk)
    local sm = tbl_to_str(expected_results[f].sm)
    local sig = tbl_to_str(expected_results[f].sig)

    describe('function ' .. crypto_sign_keypair, function()
      it('should generate keys', function()
        local test_pk, test_sk = lib[crypto_sign_keypair]()
        assert(string.len(test_pk) == PUBLICKEYBYTES)
        assert(string.len(test_sk) == SECRETKEYBYTES)
      end)
    end)

    describe('function ' .. crypto_sign, function()
      it('should error on bad calls', function()
        assert(pcall(lib[crypto_sign]) == false)
        assert(pcall(lib[crypto_sign],'','') == false)
      end)

      it('should generate a known signed message', function()
        local tsm = lib[crypto_sign](message,sk)
        assert(sm == tsm)
      end)
    end)

    describe('function ' .. crypto_sign_open, function()
      it('should error on bad calls', function()
        assert(pcall(lib[crypto_sign_open]) == false)
        assert(pcall(lib[crypto_sign_open],'','') == false)
      end)

      it('should return a message on a valid signature', function()
        local tmessage = lib[crypto_sign_open](sm,pk)
        assert(tmessage == message)
      end)

      it('should return nil on an invalid signature', function()
        local tsig = string.rep('\0',BYTES)
        assert(lib[crypto_sign_open](tsig .. message,pk) == nil)
      end)
    end)
  end

  for _,f in ipairs({
    'crypto_sign',
    'crypto_sign_ed25519',
  }) do
    local crypto_sign_seed_keypair = string.format('%s_seed_keypair',f)

    local PUBLICKEYBYTES = lib[string.format('%s_PUBLICKEYBYTES',f)]
    local SECRETKEYBYTES = lib[string.format('%s_SECRETKEYBYTES',f)]
    local BYTES = lib[string.format('%s_BYTES',f)]
    local SEEDBYTES = lib[string.format('%s_SEEDBYTES',f)]

    local pk = tbl_to_str(expected_results[f].pk)
    local sk = tbl_to_str(expected_results[f].sk)
    local sm = tbl_to_str(expected_results[f].sm)
    local sig = tbl_to_str(expected_results[f].sig)

    describe('function ' .. crypto_sign_seed_keypair, function()
      it('should error on bad calls', function()
        assert(pcall(lib[crypto_sign_seed_keypair]) == false)
        assert(pcall(lib[crypto_sign_seed_keypair],'') == false)
      end)

      it('should generate a keypair from a known seed', function()
        local seed = string.rep('\0',SEEDBYTES)
        local tpk, tsk = lib[crypto_sign_seed_keypair](seed)
        assert(tpk == pk)
        assert(tsk == sk)
      end)
    end)
  end

  for _,f in ipairs({
    'crypto_sign',
  }) do

    local crypto_sign_detached = string.format('%s_detached',f)
    local crypto_sign_verify_detached = string.format('%s_verify_detached',f)

    local BYTES = lib[string.format('%s_BYTES',f)]

    local pk = tbl_to_str(expected_results[f].pk)
    local sk = tbl_to_str(expected_results[f].sk)
    local sig = tbl_to_str(expected_results[f].sig)

    describe('function ' .. crypto_sign_detached, function()
      it('should error on bad calls', function()
        assert(pcall(lib[crypto_sign_detached]) == false)
        assert(pcall(lib[crypto_sign_detached],'','') == false)
      end)

      it('should produce a signature', function()
        assert(lib[crypto_sign_detached](message,sk) == sig)
      end)

    end)

    describe('function ' .. crypto_sign_verify_detached, function()
      it('should error on bad calls', function()
        assert(pcall(lib[crypto_sign_verify_detached]) == false)
        assert(pcall(lib[crypto_sign_verify_detached],'','','') == false)
      end)

      it('should validate a good signature', function()
        assert(lib[crypto_sign_verify_detached](sig,message,pk) == true)
      end)

      it('should invalidate a bad signature', function()
        local bad_sig = string.rep('\0',BYTES)
        assert(lib[crypto_sign_verify_detached](bad_sig,message,pk) == false)
      end)

    end)
  end

  local function test_mp(params)
    local crypto_sign_init = params.crypto_sign_init
    local crypto_sign_update = params.crypto_sign_update
    local crypto_sign_final_create = params.crypto_sign_final_create
    local crypto_sign_final_verify = params.crypto_sign_final_verify

    local pk = params.pk
    local sk = params.sk
    local sig = params.sig
    local BYTES = params.BYTES

    describe('function ' .. crypto_sign_init, function()
      it('should return a state object', function()
        assert(lib[crypto_sign_init]() ~= nil)
      end)
    end)

    describe('function ' .. crypto_sign_update, function()
      it('should reject invalid calls', function()
        assert(pcall(lib[crypto_sign_update]) == false)
        assert(pcall(lib[crypto_sign_update],'','') == false)
      end)

      it('should allow updates', function()
        local state = lib[crypto_sign_init]()
        assert(lib[crypto_sign_update](state,message) == true)
      end)
    end)

    describe('function ' .. crypto_sign_final_create, function()
      it('should error on invalid calls', function()
        local state = lib[crypto_sign_init]()
        assert(pcall(lib[crypto_sign_final_create]) == false)
        assert(pcall(lib[crypto_sign_final_create],'','') == false)
        assert(pcall(lib[crypto_sign_final_create],state,'') == false)
      end)

      it('should produce valid signatures in a single pass', function()
        local state = lib[crypto_sign_init]()
        assert(lib[crypto_sign_update](state,message) == true)
        assert(lib[crypto_sign_final_create](state,sk) == sig)
      end)

      it('should produce valid signatures in a single pass', function()
        local state = lib[crypto_sign_init]()
        assert(lib[crypto_sign_update](state,message) == true)
        assert(lib[crypto_sign_final_create](state,sk) == sig)
      end)

      it('should produce valid signatures with multiple passes', function()
        local state = lib[crypto_sign_init]()
        assert(lib[crypto_sign_update](state,message1) == true)
        assert(lib[crypto_sign_update](state,message2) == true)
        assert(lib[crypto_sign_final_create](state,sk) == sig)
      end)
    end)

    describe('function ' .. crypto_sign_final_verify, function()
      it('should error on invalid calls', function()
        local state = lib[crypto_sign_init]()
        assert(pcall(lib[crypto_sign_final_verify]) == false)
        assert(pcall(lib[crypto_sign_final_verify],'','','') == false)
        assert(pcall(lib[crypto_sign_final_verify],state,'','') == false)
      end)

      it('should validate signatures in a single pass', function()
        local state = lib[crypto_sign_init]()
        assert(lib[crypto_sign_update](state,message) == true)
        assert(lib[crypto_sign_final_verify](state,sig,pk) == true)
      end)

      it('should validate signatures in multiple passes', function()
        local state = lib[crypto_sign_init]()
        assert(lib[crypto_sign_update](state,message1) == true)
        assert(lib[crypto_sign_update](state,message2) == true)
        assert(lib[crypto_sign_final_verify](state,sig,pk) == true)
      end)

      it('should invalidate bad signatures', function()
        local state = lib[crypto_sign_init]()
        assert(lib[crypto_sign_update](state,message1) == true)
        assert(lib[crypto_sign_update](state,message2) == true)
        assert(lib[crypto_sign_final_verify](state,string.rep('\0',BYTES),pk) == false)
      end)
    end)

    describe('object-oriented ' .. crypto_sign_init, function()
      it('should support object-oriented create', function()
        local state = lib[crypto_sign_init]()
        assert(state:update(message1) == true)
        assert(state:update(message2) == true)
        assert(state:final_create(sk) == sig)
      end)

      it('should support object-oriented verify', function()
        local state = lib[crypto_sign_init]()
        assert(state:update(message1) == true)
        assert(state:update(message2) == true)
        assert(state:final_verify(sig,pk) == true)
      end)
    end)
  end

  test_mp({
    crypto_sign_init = 'crypto_sign_init',
    crypto_sign_update = 'crypto_sign_update',
    crypto_sign_final_create = 'crypto_sign_final_create',
    crypto_sign_final_verify = 'crypto_sign_final_verify',
    pk = tbl_to_str(expected_results['crypto_sign'].pk),
    sk = tbl_to_str(expected_results['crypto_sign'].sk),
    sig = tbl_to_str(expected_results['crypto_sign_mp'].sig),
    BYTES = lib.crypto_sign_BYTES,
  })

  test_mp({
    crypto_sign_init = 'crypto_sign_ed25519ph_init',
    crypto_sign_update = 'crypto_sign_ed25519ph_update',
    crypto_sign_final_create = 'crypto_sign_ed25519ph_final_create',
    crypto_sign_final_verify = 'crypto_sign_ed25519ph_final_verify',
    pk = tbl_to_str(expected_results['crypto_sign_ed25519'].pk),
    sk = tbl_to_str(expected_results['crypto_sign_ed25519'].sk),
    sig = tbl_to_str(expected_results['crypto_sign_ed25519_mp'].sig),
    BYTES = lib.crypto_sign_ed25519_BYTES,
  })

  describe('function crypto_sign_ed25519_sk_to_seed', function()
    it('should error on invalid calls', function()
      assert(pcall(lib.crypto_sign_ed25519_sk_to_seed) == false)
      assert(pcall(lib.crypto_sign_ed25519_sk_to_seed,'') == false)
    end)
    it('should reproduce the seed', function()
      local sk = tbl_to_str(expected_results['crypto_sign_ed25519'].sk)
      local seed = string.rep('\0',lib.crypto_sign_ed25519_SEEDBYTES)
      assert(lib.crypto_sign_ed25519_sk_to_seed(sk) == seed)
    end)
  end)

  describe('function crypto_sign_ed25519_sk_to_pk', function()
    it('should error on invalid calls', function()
      assert(pcall(lib.crypto_sign_ed25519_sk_to_pk) == false)
      assert(pcall(lib.crypto_sign_ed25519_sk_to_pk,'') == false)
    end)
    it('should reproduce the pk', function()
      local sk = tbl_to_str(expected_results['crypto_sign_ed25519'].sk)
      local pk = tbl_to_str(expected_results['crypto_sign_ed25519'].pk)
      assert(lib.crypto_sign_ed25519_sk_to_pk(sk) == pk)
    end)
  end)

end)

