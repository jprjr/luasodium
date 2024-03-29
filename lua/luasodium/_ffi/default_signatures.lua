-- signatures, used by
-- both pure FFI and FFI-inside-C
local signatures = {
  ['sodium_init'] = [[
    int %s(void)
  ]],
  ['sodium_memzero'] = [[
    void %s(void * const pnt, const size_t len)
  ]],
}

local function add_signatures(tbl)
  for k,v in pairs(signatures) do
    tbl[k] = v
  end
  return tbl
end

return add_signatures
