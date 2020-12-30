#include "../luasodium-ffi.h"
#include "constants.h"
#include "core.luah"

#define str(s) #s

static const char *const easy_sig = "int (*)(unsigned char *c, "
                                    "const unsigned char *m, "
                                    "unsigned long long mlen, "
                                    "const unsigned char *n, "
                                    "const unsigned char *k)";

static const char * const detached_sig = "int (*)(unsigned char *c, "
                                              "unsigned char *mac, "
                                              "const unsigned char *m, "
                                              "unsigned long long mlen, "
                                              "const unsigned char *n, "
                                              "const unsigned char *k)";

static const char * const open_detached_sig = "int (*)(unsigned char *m, "
                                              "const unsigned char *c, "
                                              "const unsigned char *mac, "
                                              "unsigned long long mlen, "
                                              "const unsigned char *n, "
                                              "const unsigned char *k)";

static const char * const keygen_sig = "void (*)(unsigned char *)";

static const
luasodium_ffi_func ffi_funcs[] = {
    LS_FFI_FUNC(crypto_secretbox,easy_sig),
    LS_FFI_FUNC(crypto_secretbox_open,easy_sig),
    LS_FFI_FUNC(crypto_secretbox_xsalsa20poly1305,easy_sig),
    LS_FFI_FUNC(crypto_secretbox_xsalsa20poly1305_open,easy_sig),

    LS_FFI_FUNC(crypto_secretbox_easy,easy_sig),
    LS_FFI_FUNC(crypto_secretbox_open_easy,easy_sig),
    LS_FFI_FUNC(crypto_secretbox_xchacha20poly1305_easy,easy_sig),
    LS_FFI_FUNC(crypto_secretbox_xchacha20poly1305_open_easy,easy_sig),

    LS_FFI_FUNC(crypto_secretbox_detached,detached_sig),
    LS_FFI_FUNC(crypto_secretbox_xchacha20poly1305_detached,detached_sig),

    LS_FFI_FUNC(crypto_secretbox_open_detached,open_detached_sig),
    LS_FFI_FUNC(crypto_secretbox_xchacha20poly1305_open_detached,open_detached_sig),

    LS_FFI_FUNC(crypto_secretbox_keygen,keygen_sig),
    LS_FFI_FUNC(crypto_secretbox_xsalsa20poly1305_keygen,keygen_sig),

    LS_FFI_END
};

int
luaopen_luasodium_crypto_secretbox_ffi(lua_State *L) {
    if(luaL_loadbuffer(L,crypto_secretbox_lua,crypto_secretbox_lua_length - 1,"crypto_secretbox.lua")) {
        return lua_error(L);
    }

    luasodium_push_init(L);

    lua_newtable(L);
    luasodium_set_constants(L,luasodium_secretbox_constants);

    luasodium_push_ffi_funcs(L,ffi_funcs);

    if(lua_pcall(L,3,1,0)) {
        return lua_error(L);
    }
    return 1;
}
