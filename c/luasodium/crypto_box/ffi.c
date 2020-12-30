#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

#define str(s) #s

static const char *const
keypair_sig = "int (*)(unsigned char *, unsigned char *)";

static const char *const
seed_keypair_sig = "int (*)(unsigned char *, unsigned char *, "
                   "const unsigned char *)";

static const char * const
crypto_box_sig = "int (*)(unsigned char *c, const unsigned char *m, "
                 "unsigned long long mlen, const unsigned char *n, "
                 "const unsigned char *pk, const unsigned char *sk)";

static const char * const
crypto_box_detached_sig = "int (*)(unsigned char *c, unsigned char *mac, "
                          "const unsigned char *m, "
                          "unsigned long long mlen, "
                          "const unsigned char *n, "
                          "const unsigned char *pk, "
                          "const unsigned char *sk)";

static const char * const
crypto_box_open_detached_sig = "int (*)(unsigned char *m, "
                               "const unsigned char *c, "
                               "const unsigned char *mac, "
                               "unsigned long long clen, "
                               "const unsigned char *n, "
                               "const unsigned char *pk, "
                               "const unsigned char *sk)";

static const char * const
crypto_box_beforenm_sig = "int (*)(unsigned char *k, const unsigned char *pk, "
                          "const unsigned char *sk)";

static const char * const
crypto_box_easy_afternm_sig = "int (*)(unsigned char *c, const unsigned char *m, "
                              "unsigned long long mlen, const unsigned char *n, "
                              "const unsigned char *k)";

static const char * const
crypto_box_detached_afternm_sig = "int (*)(unsigned char *c, unsigned char *mac, "
                                  "const unsigned char *m, unsigned long long mlen, "
                                  "const unsigned char *n, const unsigned char *k)";

static const char * const
crypto_box_open_detached_afternm_sig = "int (*)(unsigned char *m, const unsigned char *c, "
                                       "const unsigned char *mac, "
                                       "unsigned long long clen, const unsigned char *n, "
                                       "const unsigned char *k)";


static const ffi_pointer_t ffi_pointers[] = {
    crypto_box_keypair,
    crypto_box_seed_keypair,
    crypto_box_easy,
    crypto_box_open_easy,
    crypto_box_detached,
    crypto_box_open_detached,
    crypto_box_beforenm,
    crypto_box_easy_afternm,
    crypto_box_open_easy_afternm,
    crypto_box_detached_afternm,
    crypto_box_open_detached_afternm,
    NULL,
};

static const
luasodium_ffi_func ffi_funcs[] = {
    LS_FFI_FUNC(crypto_box_keypair,keypair_sig),

    LS_FFI_FUNC(crypto_box_seed_keypair,seed_keypair_sig),

    LS_FFI_FUNC(crypto_box_easy,crypto_box_sig),
    LS_FFI_FUNC(crypto_box_open_easy,crypto_box_sig),

    LS_FFI_FUNC(crypto_box_detached,crypto_box_detached_sig),

    LS_FFI_FUNC(crypto_box_open_detached,crypto_box_open_detached_sig),

    LS_FFI_FUNC(crypto_box_beforenm,crypto_box_beforenm_sig),

    LS_FFI_FUNC(crypto_box_easy_afternm,crypto_box_easy_afternm_sig),
    LS_FFI_FUNC(crypto_box_open_easy_afternm,crypto_box_easy_afternm_sig),

    LS_FFI_FUNC(crypto_box_detached_afternm,crypto_box_detached_afternm_sig),
    LS_FFI_FUNC(crypto_box_open_detached_afternm,crypto_box_open_detached_afternm_sig),

    LS_FFI_END
};

int luaopen_luasodium_crypto_box_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,crypto_box_lua,crypto_box_lua_length - 1,"crypto_box.lua") ) {
        return lua_error(L);
    }

    luasodium_push_inittable(L);

    lua_newtable(L);
    luasodium_set_constants(L,luasodium_box_constants);

    luasodium_push_ffi_funcs(L,ffi_funcs);

    if(lua_pcall(L,3,1,0)) {
        return lua_error(L);
    }
    return 1;
}
