local function describe_stub(_,cb)
  cb()
end

local function it_stub(_,cb)
  cb()
end

function try_busted()
  local ok, runner = pcall(require,'busted.runner')
  
  if ok then
    runner()
  else
    _G.describe = describe_stub
    _G.it = it_stub
  end
end

