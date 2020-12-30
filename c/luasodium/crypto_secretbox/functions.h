/* shared with:
 * open
 * easy
 * open_easy */
static const char * const
ls_crypto_secretbox_sig = "int (*)("
                          "unsigned char *c,"
                          "const unsigned char *m,"
                          "unsigned long long mlen,"
                          "const unsigned char *n,"
                          "const unsigned char *k)";

static const char * const
ls_crypto_secretbox_detached_sig = "int (*)("
                                   "unsigned char *c,"
                                   "unsigned char *mac,"
                                   "const unsigned char *m,"
                                   "unsigned long long mlen,"
                                   "const unsigned char *n,"
                                   "const unsigned char *k)";

static const char * const
ls_crypto_secretbox_open_detached_sig = "int (*)("
                                   "unsigned char *m,"
                                   "const unsigned char *c,"
                                   "const unsigned char *mac,"
                                   "unsigned long long clen,"
                                   "const unsigned char *n,"
                                   "const unsigned char *k)";

static const char * const
ls_crypto_secretbox_keygen_sig = "void (*)(unsigned char *k)";

typedef int (*ls_crypto_secretbox_func_ptr)(unsigned char *c,
                              const unsigned char *m,
                              unsigned long long mlen,
                              const unsigned char *n,
                              const unsigned char *k);


typedef int (*ls_crypto_secretbox_detached_func_ptr)(unsigned char *c,
                                       unsigned char *mac,
                                       const unsigned char *m,
                                       unsigned long long mlen,
                                       const unsigned char *n,
                                       const unsigned char *k);

typedef int (*ls_crypto_secretbox_open_detached_func_ptr)(unsigned char *m,
                                            const unsigned char *c,
                                            const unsigned char *mac,
                                            unsigned long long clen,
                                            const unsigned char *n,
                                            const unsigned char *k);

typedef void (*ls_crypto_secretbox_keygen_func_ptr)(unsigned char *k);

struct ls_crypto_secretbox_func_def_s {
    const char *name;
    ls_crypto_secretbox_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t keysize;
    size_t zerosize;
    size_t boxzerosize;
};

struct ls_crypto_secretbox_open_func_def_s {
    const char *name;
    ls_crypto_secretbox_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t keysize;
    size_t zerosize;
    size_t boxzerosize;
};

struct ls_crypto_secretbox_easy_func_def_s {
    const char *name;
    ls_crypto_secretbox_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t keysize;
};

struct ls_crypto_secretbox_open_easy_func_def_s {
    const char *name;
    ls_crypto_secretbox_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t keysize;
};

struct ls_crypto_secretbox_detached_func_def_s {
    const char *name;
    ls_crypto_secretbox_detached_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t keysize;
};

struct ls_crypto_secretbox_open_detached_func_def_s {
    const char *name;
    ls_crypto_secretbox_open_detached_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t keysize;
};

struct ls_crypto_secretbox_keygen_func_def_s {
    const char *name;
    ls_crypto_secretbox_keygen_func_ptr func;
    const char *signature;
    size_t keysize;
};

typedef struct ls_crypto_secretbox_func_def_s ls_crypto_secretbox_func_def;
typedef struct ls_crypto_secretbox_open_func_def_s ls_crypto_secretbox_open_func_def;
typedef struct ls_crypto_secretbox_easy_func_def_s ls_crypto_secretbox_easy_func_def;
typedef struct ls_crypto_secretbox_open_easy_func_def_s ls_crypto_secretbox_open_easy_func_def;
typedef struct ls_crypto_secretbox_detached_func_def_s ls_crypto_secretbox_detached_func_def;
typedef struct ls_crypto_secretbox_open_detached_func_def_s ls_crypto_secretbox_open_detached_func_def;
typedef struct ls_crypto_secretbox_keygen_func_def_s ls_crypto_secretbox_keygen_func_def;

/* crypto_secretbox functions */
static const ls_crypto_secretbox_func_def ls_crypto_secretbox_func = {
    LS_FUNC(crypto_secretbox,ls_crypto_secretbox_sig),
    crypto_secretbox_NONCEBYTES,
    crypto_secretbox_MACBYTES,
    crypto_secretbox_KEYBYTES,
    crypto_secretbox_ZEROBYTES,
    crypto_secretbox_BOXZEROBYTES,
};

static const ls_crypto_secretbox_open_func_def ls_crypto_secretbox_open_func = {
    LS_FUNC(crypto_secretbox_open,ls_crypto_secretbox_sig),
    crypto_secretbox_NONCEBYTES,
    crypto_secretbox_MACBYTES,
    crypto_secretbox_KEYBYTES,
    crypto_secretbox_ZEROBYTES,
    crypto_secretbox_BOXZEROBYTES,
};

static const ls_crypto_secretbox_easy_func_def ls_crypto_secretbox_easy_func = {
    LS_FUNC(crypto_secretbox_easy,ls_crypto_secretbox_sig),
    crypto_secretbox_NONCEBYTES,
    crypto_secretbox_MACBYTES,
    crypto_secretbox_KEYBYTES,
};


static const ls_crypto_secretbox_open_easy_func_def ls_crypto_secretbox_open_easy_func = {
    LS_FUNC(crypto_secretbox_open_easy,ls_crypto_secretbox_sig),
    crypto_secretbox_NONCEBYTES,
    crypto_secretbox_MACBYTES,
    crypto_secretbox_KEYBYTES,
};

static const ls_crypto_secretbox_detached_func_def ls_crypto_secretbox_detached_func = {
    LS_FUNC(crypto_secretbox_detached,ls_crypto_secretbox_detached_sig),
    crypto_secretbox_NONCEBYTES,
    crypto_secretbox_MACBYTES,
    crypto_secretbox_KEYBYTES,
};


static const ls_crypto_secretbox_open_detached_func_def ls_crypto_secretbox_open_detached_func = {
    LS_FUNC(crypto_secretbox_open_detached,ls_crypto_secretbox_open_detached_sig),
    crypto_secretbox_NONCEBYTES,
    crypto_secretbox_MACBYTES,
    crypto_secretbox_KEYBYTES,
};

static const ls_crypto_secretbox_keygen_func_def ls_crypto_secretbox_keygen_func = {
    LS_FUNC(crypto_secretbox_keygen,ls_crypto_secretbox_keygen_sig),
    crypto_secretbox_KEYBYTES,
};

/* xsalsa20poly1305 functions */
static const ls_crypto_secretbox_func_def ls_crypto_secretbox_xsalsa20poly1305_func = {
    LS_FUNC(crypto_secretbox_xsalsa20poly1305,ls_crypto_secretbox_sig),
    crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
    crypto_secretbox_xsalsa20poly1305_MACBYTES,
    crypto_secretbox_xsalsa20poly1305_KEYBYTES,
    crypto_secretbox_xsalsa20poly1305_ZEROBYTES,
    crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES,
};

static const ls_crypto_secretbox_open_func_def ls_crypto_secretbox_xsalsa20poly1305_open_func = {
    LS_FUNC(crypto_secretbox_xsalsa20poly1305_open,ls_crypto_secretbox_sig),
    crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
    crypto_secretbox_xsalsa20poly1305_MACBYTES,
    crypto_secretbox_xsalsa20poly1305_KEYBYTES,
    crypto_secretbox_xsalsa20poly1305_ZEROBYTES,
    crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES,
};

static const ls_crypto_secretbox_keygen_func_def ls_crypto_secretbox_xsalsa20poly1305_keygen_func = {
    LS_FUNC(crypto_secretbox_xsalsa20poly1305_keygen,ls_crypto_secretbox_keygen_sig),
    crypto_secretbox_xsalsa20poly1305_KEYBYTES,
};

/* xchacha20poly1305 functions */
static const ls_crypto_secretbox_easy_func_def ls_crypto_secretbox_xchacha20poly1305_easy_func = {
    LS_FUNC(crypto_secretbox_xchacha20poly1305_easy,ls_crypto_secretbox_sig),
    crypto_secretbox_xchacha20poly1305_NONCEBYTES,
    crypto_secretbox_xchacha20poly1305_MACBYTES,
    crypto_secretbox_xchacha20poly1305_KEYBYTES,
};


static const ls_crypto_secretbox_open_easy_func_def ls_crypto_secretbox_xchacha20poly1305_open_easy_func = {
    LS_FUNC(crypto_secretbox_xchacha20poly1305_open_easy,ls_crypto_secretbox_sig),
    crypto_secretbox_xchacha20poly1305_NONCEBYTES,
    crypto_secretbox_xchacha20poly1305_MACBYTES,
    crypto_secretbox_xchacha20poly1305_KEYBYTES,
};

static const ls_crypto_secretbox_detached_func_def ls_crypto_secretbox_xchacha20poly1305_detached_func = {
    LS_FUNC(crypto_secretbox_xchacha20poly1305_detached,ls_crypto_secretbox_sig),
    crypto_secretbox_xchacha20poly1305_NONCEBYTES,
    crypto_secretbox_xchacha20poly1305_MACBYTES,
    crypto_secretbox_xchacha20poly1305_KEYBYTES,
};


static const ls_crypto_secretbox_open_detached_func_def ls_crypto_secretbox_xchacha20poly1305_open_detached_func = {
    LS_FUNC(crypto_secretbox_xchacha20poly1305_open_detached,ls_crypto_secretbox_sig),
    crypto_secretbox_xchacha20poly1305_NONCEBYTES,
    crypto_secretbox_xchacha20poly1305_MACBYTES,
    crypto_secretbox_xchacha20poly1305_KEYBYTES,
};

