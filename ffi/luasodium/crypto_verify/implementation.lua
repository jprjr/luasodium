return function(libs)
  local string_len = string.len
  local string_format = string.format
  local sodium_lib = libs.sodium

  local function ls_crypto_verify(f,l)
    return function(x,y)
      if not y then
        return error('requires 2 parameters')
      end

      if string_len(x) ~= l or
         string_len(y) ~= l then
         return error(string_format('incorrect string size, expected: %d',
           l))
      end

      return tonumber(sodium_lib[f](x,y)) == 0
    end
  end

  local M = {
    crypto_verify_16 = ls_crypto_verify(
      'crypto_verify_16',16),
    crypto_verify_32 = ls_crypto_verify(
      'crypto_verify_32',32),
  }

  return M
end

