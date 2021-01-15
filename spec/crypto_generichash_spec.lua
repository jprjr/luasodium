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

describe('library crypto_generichash', function()
  it('is a library', function()
    assert(type(lib) == 'table')
  end)

  it('has constants', function()
    assert(type(lib.crypto_generichash_KEYBYTES) == 'number')
  end)

  for _,f in ipairs({
    'crypto_generichash'
  }) do
    local crypto_generichash_keygen = string.format('%s_keygen',f)

    local KEYBYTES = string.format('%s_KEYBYTES',f)

    describe('function ' .. crypto_generichash_keygen, function()
      it('should return a random key', function()
        assert(string.len(lib[crypto_generichash_keygen]()) ==
          lib[KEYBYTES])
      end)
    end)
  end
end)
