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
  ['crypto_secretbox'] = {
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['mac'] = {
       66, 125, 99, 178, 205, 62, 244, 23,
       217, 26, 120, 213, 176, 201, 8, 94,
    },
    ['cipher'] = {
       154, 120, 53, 144, 228,
    },
  },
  ['crypto_secretbox_xsalsa20poly1305'] = {
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['mac'] = {
       66, 125, 99, 178, 205, 62, 244, 23,
       217, 26, 120, 213, 176, 201, 8, 94,
    },
    ['cipher'] = {
       154, 120, 53, 144, 228,
    },
  },
  ['crypto_secretbox_easy'] = {
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['mac'] = {
       66, 125, 99, 178, 205, 62, 244, 23,
       217, 26, 120, 213, 176, 201, 8, 94,
    },
    ['cipher'] = {
       154, 120, 53, 144, 228,
    },
  },
  ['crypto_secretbox_xchacha20poly1305_easy'] = {
    ['key'] = {
       161, 31, 143, 18, 208, 135, 111, 115,
       109, 45, 143, 210, 110, 20, 194, 222,
       136, 241, 99, 227, 39, 23, 16, 198,
       118, 199, 56, 76, 179, 98, 18, 121,
    },
    ['mac'] = {
       32, 60, 201, 28, 161, 218, 113, 190,
       48, 239, 74, 11, 63, 190, 214, 127,
    },
    ['cipher'] = {
       233, 16, 249, 163, 241,
    },
  },
}

describe('library crypto_secretbox', function()
  it('should be a library', function()
    assert(type(lib) == 'table')
  end)

  it('should have constants', function()
    assert(type(lib.crypto_secretbox_MACBYTES) == 'number')
    assert(type(lib.crypto_secretbox_NONCEBYTES) == 'number')
    assert(type(lib.crypto_secretbox_KEYBYTES) == 'number')
    assert(type(lib.crypto_secretbox_ZEROBYTES) == 'number')
    assert(type(lib.crypto_secretbox_BOXZEROBYTES) == 'number')
    assert(type(lib.crypto_secretbox_xsalsa20poly1305_MACBYTES) == 'number')
    assert(type(lib.crypto_secretbox_xsalsa20poly1305_NONCEBYTES) == 'number')
    assert(type(lib.crypto_secretbox_xsalsa20poly1305_KEYBYTES) == 'number')
    assert(type(lib.crypto_secretbox_xsalsa20poly1305_ZEROBYTES) == 'number')
    assert(type(lib.crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES) == 'number')
  end)

  for _,f in ipairs({
    'crypto_secretbox',
    'crypto_secretbox_xsalsa20poly1305'
  }) do
    local crypto_secretbox = string.format('%s',f)
    local crypto_secretbox_open = string.format('%s_open',f)

    local MACBYTES = lib[string.format('%s_MACBYTES',f)]
    local NONCEBYTES = lib[string.format('%s_NONCEBYTES',f)]
    local KEYBYTES = lib[string.format('%s_KEYBYTES',f)]

    local nonce = string.rep('\0',NONCEBYTES)
    local key = tbl_to_str(expected_results[f].key)
    local mac = tbl_to_str(expected_results[f].mac)
    local cipher = tbl_to_str(expected_results[f].cipher)

    describe('function ' .. crypto_secretbox, function()
      it('should error on invalid calls', function()
        assert(pcall(lib[crypto_secretbox]) == false)
        assert(pcall(lib[crypto_secretbox],'','','') == false)
        assert(pcall(lib[crypto_secretbox],'',string.rep('\0',NONCEBYTES),'') == false)
      end)

      it('should produce results for a known key', function()
        local encrypted = lib[crypto_secretbox](message,nonce,key)
        assert(mac .. cipher == encrypted)
      end)
    end)

    describe('function ' .. crypto_secretbox_open, function()
      it('should error on invalid calls', function()
        assert(pcall(lib[crypto_secretbox_open]) == false)
        assert(pcall(lib[crypto_secretbox_open],'','','') == false)
        assert(pcall(lib[crypto_secretbox_open],string.rep('\0',MACBYTES),'','') == false)
        assert(pcall(lib[crypto_secretbox_open],string.rep('\0',MACBYTES),string.rep('\0',NONCEBYTES),'') == false)
      end)

      it('should decrypt a valid message', function()
        assert(lib[crypto_secretbox_open](mac .. cipher, nonce, key) == message)
      end)

      it('should return nil on an invalid message', function()
        local tag = string.rep('\0',MACBYTES)
        assert(lib[crypto_secretbox_open](tag .. cipher, nonce, key) == nil)
      end)

    end)
  end

  for _,f in ipairs({
    'crypto_secretbox',
  }) do
    local crypto_secretbox_easy = string.format('%s_easy',f)
    local crypto_secretbox_open_easy = string.format('%s_open_easy',f)
    local crypto_secretbox_detached = string.format('%s_detached',f)
    local crypto_secretbox_open_detached = string.format('%s_open_detached',f)

    local MACBYTES = lib[string.format('%s_MACBYTES',f)]
    local NONCEBYTES = lib[string.format('%s_NONCEBYTES',f)]
    local KEYBYTES = lib[string.format('%s_KEYBYTES',f)]

    local nonce = string.rep('\0',NONCEBYTES)
    local key = tbl_to_str(expected_results[f].key)
    local mac = tbl_to_str(expected_results[f].mac)
    local cipher = tbl_to_str(expected_results[f].cipher)

    describe('function ' .. crypto_secretbox_easy, function()
      it('should error on invalid calls', function()
        assert(pcall(lib[crypto_secretbox_easy]) == false)
        assert(pcall(lib[crypto_secretbox_easy],'','','') == false)
        assert(pcall(lib[crypto_secretbox_easy],'',string.rep('\0',NONCEBYTES),'') == false)
      end)

      it('should produce results for a known key', function()
        local encrypted = lib[crypto_secretbox_easy](message,nonce,key)
        assert(mac .. cipher == encrypted)
      end)
    end)

    describe('function ' .. crypto_secretbox_open_easy, function()
      it('should error on invalid calls', function()
        assert(pcall(lib[crypto_secretbox_open_easy]) == false)
        assert(pcall(lib[crypto_secretbox_open_easy],'','','') == false)
        assert(pcall(lib[crypto_secretbox_open_easy],string.rep('\0',MACBYTES),'','') == false)
        assert(pcall(lib[crypto_secretbox_open_easy],string.rep('\0',MACBYTES),string.rep('\0',NONCEBYTES),'') == false)
      end)

      it('should decrypt a valid message', function()
        assert(lib[crypto_secretbox_open_easy](mac .. cipher, nonce, key) == message)
      end)

      it('should return nil on an invalid message', function()
        local tag = string.rep('\0',MACBYTES)
        assert(lib[crypto_secretbox_open_easy](tag .. cipher, nonce, key) == nil)
      end)

    end)

    describe('function ' .. crypto_secretbox_detached, function()
      it('should error on invalid calls', function()
        assert(pcall(lib[crypto_secretbox_detached]) == false)
        assert(pcall(lib[crypto_secretbox_detached],'','','') == false)
        assert(pcall(lib[crypto_secretbox_detached],'',string.rep('\0',NONCEBYTES),'') == false)
      end)

      it('should produce results for a known key', function()
        local encrypted, tag = lib[crypto_secretbox_detached](message,nonce,key)
        assert(encrypted == cipher)
        assert(tag == mac)
      end)
    end)

    describe('function ' .. crypto_secretbox_open_detached, function()
      it('should error on invalid calls', function()
        assert(pcall(lib[crypto_secretbox_open_detached]) == false)
        assert(pcall(lib[crypto_secretbox_open_detached],'','','','') == false)
        assert(pcall(lib[crypto_secretbox_open_detached],'',string.rep('\0',MACBYTES),'','') == false)
        assert(pcall(lib[crypto_secretbox_open_detached],'',string.rep('\0',MACBYTES),string.rep('\0',NONCEBYTES),'') == false)
      end)

      it('should decrypt a valid message', function()
        assert(lib[crypto_secretbox_open_detached](cipher, mac, nonce, key) == message)
      end)

      it('should return nil on an invalid message', function()
        local tag = string.rep('\0',MACBYTES)
        assert(lib[crypto_secretbox_open_detached](cipher, tag, nonce, key) == nil)
      end)

    end)
  end

  for _,f in ipairs({
    'crypto_secretbox',
    'crypto_secretbox_xsalsa20poly1305',
  }) do
    local crypto_secretbox_keygen = string.format('%s_keygen',f)
    local KEYBYTES = lib[string.format('%s_KEYBYTES',f)]

    describe('function ' .. crypto_secretbox_keygen, function()
      it('should produce a random key', function()
        local key = lib[crypto_secretbox_keygen]()
        assert(string.len(key) == KEYBYTES)
      end)
    end)
  end
end)

