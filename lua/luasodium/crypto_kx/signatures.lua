local crypto_kx_keypair_sig = [[
  int %s(unsigned char *pk,
         unsigned char *sk)
]]

local crypto_kx_seed_keypair_sig = [[
  int %s(unsigned char *pk,
         unsigned char *sk,
         const unsigned char *seed)
]]

local crypto_kx_client_session_keys_sig = [[
  int %s(unsigned char *rx,
         unsigned char *tx,
         const unsigned char *client_pk,
         const unsigned char *client_sk,
         const unsigned char *server_pk)
]]

local crypto_kx_server_session_keys_sig = [[
  int %s(unsigned char *rx,
         unsigned char *tx,
         const unsigned char *server_pk,
         const unsigned char *server_sk,
         const unsigned char *client_pk)
]]

local signatures = {
  ['crypto_kx_keypair'] = crypto_kx_keypair_sig,
  ['crypto_kx_seed_keypair'] = crypto_kx_seed_keypair_sig,
  ['crypto_kx_client_session_keys'] = crypto_kx_client_session_keys_sig,
  ['crypto_kx_server_session_keys'] = crypto_kx_server_session_keys_sig,
}

return signatures
