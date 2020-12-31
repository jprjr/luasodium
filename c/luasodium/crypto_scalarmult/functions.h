static const char * const
ls_crypto_scalarmult_base_sig = "int (*)(unsigned char *q, const unsigned char *n)";

static const char * const
ls_crypto_scalarmult_sig = "int (*)(unsigned char *q, const unsigned char *n,"
                            "const unsigned char *p)";

typedef int (*ls_crypto_scalarmult_base_func_ptr)(unsigned char *q, const unsigned char *n);

typedef int (*ls_crypto_scalarmult_func_ptr)(unsigned char *q, const unsigned char *n,
                      const unsigned char *p);

struct ls_crypto_scalarmult_base_func_def_s {
    const char *name;
    ls_crypto_scalarmult_base_func_ptr func;
    const char *signature;
    size_t scalarbytes;
    size_t bytes;
};

struct ls_crypto_scalarmult_func_def_s {
    const char *name;
    ls_crypto_scalarmult_func_ptr func;
    const char *signature;
    size_t scalarbytes;
    size_t bytes;
};

typedef struct ls_crypto_scalarmult_base_func_def_s ls_crypto_scalarmult_base_func_def;
typedef struct ls_crypto_scalarmult_func_def_s ls_crypto_scalarmult_func_def;

static const ls_crypto_scalarmult_base_func_def ls_crypto_scalarmult_base_func = {
    LS_FUNC(crypto_scalarmult_base,ls_crypto_scalarmult_base_sig),
    crypto_scalarmult_SCALARBYTES,
    crypto_scalarmult_BYTES
};

static const ls_crypto_scalarmult_func_def ls_crypto_scalarmult_func = {
    LS_FUNC(crypto_scalarmult,ls_crypto_scalarmult_sig),
    crypto_scalarmult_SCALARBYTES,
    crypto_scalarmult_BYTES
};
