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

local expected_results = {
  ['crypto_kx'] = {
    ['client_pk'] = {
       85, 126, 35, 215, 52, 111, 33, 62,
       197, 162, 55, 19, 178, 162, 73, 126,
       239, 53, 53, 77, 91, 82, 8, 138,
       198, 165, 153, 58, 95, 219, 9, 30,
    },
    ['client_sk'] = {
       137, 235, 13, 106, 138, 105, 29, 174,
       44, 209, 94, 208, 54, 153, 49, 206,
       10, 148, 158, 202, 250, 92, 63, 147,
       248, 18, 24, 51, 100, 110, 21, 195,
    },
    ['client_rx'] = {
       6, 82, 223, 10, 48, 69, 100, 247,
       48, 53, 102, 145, 46, 50, 93, 72,
       203, 205, 86, 96, 190, 143, 185, 130,
       87, 213, 187, 152, 136, 220, 39, 42,
    },
    ['client_tx'] = {
       28, 201, 19, 111, 14, 56, 35, 179,
       87, 186, 152, 226, 60, 81, 141, 97,
       18, 123, 57, 72, 129, 136, 70, 159,
       92, 120, 59, 149, 44, 217, 111, 255,
    },
    ['server_pk'] = {
       208, 171, 149, 114, 210, 148, 166, 14,
       250, 253, 1, 144, 101, 8, 4, 203,
       163, 217, 144, 115, 125, 183, 222, 209,
       37, 121, 4, 131, 250, 106, 230, 24,
    },
    ['server_sk'] = {
       175, 188, 28, 5, 60, 47, 39, 142,
       60, 189, 68, 9, 193, 192, 148, 241,
       132, 170, 69, 157, 210, 247, 252, 169,
       109, 96, 119, 115, 10, 185, 255, 227,
    },
    ['server_rx'] = {
       28, 201, 19, 111, 14, 56, 35, 179,
       87, 186, 152, 226, 60, 81, 141, 97,
       18, 123, 57, 72, 129, 136, 70, 159,
       92, 120, 59, 149, 44, 217, 111, 255,
    },
    ['server_tx'] = {
       6, 82, 223, 10, 48, 69, 100, 247,
       48, 53, 102, 145, 46, 50, 93, 72,
       203, 205, 86, 96, 190, 143, 185, 130,
       87, 213, 187, 152, 136, 220, 39, 42,
    },
  },
}

describe('library crypto_kx', function()
  it('should be a library', function()
    assert(type(lib) == 'table')
  end)

  it('should have constants', function()
    assert(type(lib.crypto_kx_PUBLICKEYBYTES) == 'number')
    assert(type(lib.crypto_kx_SECRETKEYBYTES) == 'number')
    assert(type(lib.crypto_kx_SEEDBYTES) == 'number')
    assert(type(lib.crypto_kx_SESSIONKEYBYTES) == 'number')
    assert(type(lib.crypto_kx_PRIMITIVE) == 'string')
  end)

  for _,f in ipairs({ 'crypto_kx' }) do
    local crypto_kx_keypair = string.format('%s_keypair', f)
    local crypto_kx_seed_keypair = string.format('%s_seed_keypair', f)
    local crypto_kx_client_session_keys = string.format('%s_client_session_keys', f)
    local crypto_kx_server_session_keys = string.format('%s_server_session_keys', f)
    local PUBLICKEYBYTES = lib[string.format('%s_PUBLICKEYBYTES',f)]
    local SECRETKEYBYTES = lib[string.format('%s_SECRETKEYBYTES',f)]
    local SEEDBYTES = lib[string.format('%s_SEEDBYTES',f)]
    local SESSIONKEYBYTES = lib[string.format('%s_SESSIONKEYBYTES',f)]

    local client_pk = tbl_to_str(expected_results[f].client_pk)
    local client_sk = tbl_to_str(expected_results[f].client_sk)
    local server_pk = tbl_to_str(expected_results[f].server_pk)
    local server_sk = tbl_to_str(expected_results[f].server_sk)

    local client_rx = tbl_to_str(expected_results[f].client_rx)
    local client_tx = tbl_to_str(expected_results[f].client_tx)
    local server_rx = tbl_to_str(expected_results[f].server_rx)
    local server_tx = tbl_to_str(expected_results[f].server_tx)

    describe('function ' .. crypto_kx_keypair, function()
      it('should return a public key and secret key', function()
        local pk, sk = lib[crypto_kx_keypair]()
        assert(string.len(pk) == PUBLICKEYBYTES)
        assert(string.len(sk) == SECRETKEYBYTES)
      end)
    end)

    describe('function ' .. crypto_kx_seed_keypair, function()
      it('should return a public key and secret key for known seeds', function()
        local client_seed = string.rep('\0', SEEDBYTES)
        local c_pk, c_sk = lib[crypto_kx_seed_keypair](client_seed)
        assert(string.len(c_pk) == PUBLICKEYBYTES)
        assert(string.len(c_sk) == SECRETKEYBYTES)
        assert(c_pk == client_pk)
        assert(c_sk == client_sk)

        local server_seed = '\1' .. string.rep('\0', SEEDBYTES - 1)
        local s_pk, s_sk = lib[crypto_kx_seed_keypair](server_seed)
        assert(string.len(s_pk) == PUBLICKEYBYTES)
        assert(string.len(s_sk) == SECRETKEYBYTES)
        assert(s_pk == server_pk)
        assert(s_sk == server_sk)
      end)
    end)

    describe('function ' .. crypto_kx_client_session_keys, function()
       it('should produce known client session keys', function()
         local rx, tx = lib[crypto_kx_client_session_keys](client_pk,client_sk,server_pk)
         assert(string.len(rx) == SESSIONKEYBYTES)
         assert(string.len(tx) == SESSIONKEYBYTES)
         assert(rx == client_rx)
         assert(tx == client_tx)
      end)
    end)

    describe('function ' .. crypto_kx_server_session_keys, function()
       it('should produce known server session keys', function()
         local rx, tx = lib[crypto_kx_server_session_keys](server_pk,server_sk,client_pk)
         assert(string.len(rx) == SESSIONKEYBYTES)
         assert(string.len(tx) == SESSIONKEYBYTES)
         assert(rx == server_rx)
         assert(tx == server_tx)
      end)
    end)
  end
end)


