static const char *const
ls_crypto_box_keypair_sig = "int (*)(unsigned char *, unsigned char *)";

static const char *const
ls_crypto_box_seed_keypair_sig = "int (*)(unsigned char *, unsigned char *, "
                   "const unsigned char *)";

static const char * const
ls_crypto_box_sig = "int (*)(unsigned char *c, const unsigned char *m, "
                 "unsigned long long mlen, const unsigned char *n, "
                 "const unsigned char *pk, const unsigned char *sk)";

static const char * const
ls_crypto_box_detached_sig = "int (*)(unsigned char *c, unsigned char *mac, "
                          "const unsigned char *m, "
                          "unsigned long long mlen, "
                          "const unsigned char *n, "
                          "const unsigned char *pk, "
                          "const unsigned char *sk)";

static const char * const
ls_crypto_box_open_detached_sig = "int (*)(unsigned char *m, "
                               "const unsigned char *c, "
                               "const unsigned char *mac, "
                               "unsigned long long clen, "
                               "const unsigned char *n, "
                               "const unsigned char *pk, "
                               "const unsigned char *sk)";

static const char * const
ls_crypto_box_beforenm_sig = "int (*)(unsigned char *k, const unsigned char *pk, "
                          "const unsigned char *sk)";

static const char * const
ls_crypto_box_easy_afternm_sig = "int (*)(unsigned char *c, const unsigned char *m, "
                              "unsigned long long mlen, const unsigned char *n, "
                              "const unsigned char *k)";

static const char * const
ls_crypto_box_detached_afternm_sig = "int (*)(unsigned char *c, unsigned char *mac, "
                                  "const unsigned char *m, unsigned long long mlen, "
                                  "const unsigned char *n, const unsigned char *k)";

static const char * const
ls_crypto_box_open_detached_afternm_sig = "int (*)(unsigned char *m, const unsigned char *c, "
                                       "const unsigned char *mac, "
                                       "unsigned long long clen, const unsigned char *n, "
                                       "const unsigned char *k)";

typedef int (*ls_crypto_box_keypair_func_ptr)(unsigned char *, unsigned char *);

typedef int (*ls_crypto_box_seed_keypair_func_ptr)(unsigned char *, unsigned char *,
                   const unsigned char *);

/* ls_crypto_box_func_ptr also used by:
 * crypto_box_open
 * crypto_box_easy
 * crypto_box_easy_open
 */
typedef int (*ls_crypto_box_func_ptr)(unsigned char *c, const unsigned char *m,
                 unsigned long long mlen, const unsigned char *n,
                 const unsigned char *pk, const unsigned char *sk);

typedef int (*ls_crypto_box_detached_func_ptr)(unsigned char *c, unsigned char *mac,
                          const unsigned char *m,
                          unsigned long long mlen,
                          const unsigned char *n,
                          const unsigned char *pk,
                          const unsigned char *sk);

typedef int (*ls_crypto_box_open_detached_func_ptr)(unsigned char *m,
                               const unsigned char *c,
                               const unsigned char *mac,
                               unsigned long long clen,
                               const unsigned char *n,
                               const unsigned char *pk,
                               const unsigned char *sk);

typedef int (*ls_crypto_box_beforenm_func_ptr)(unsigned char *k, const unsigned char *pk,
                          const unsigned char *sk);

/* ls_crypto_box_easy_afternm_func_ptr also used by
 * crypto_box_easy_open_afternm
 */
typedef int (*ls_crypto_box_easy_afternm_func_ptr)(unsigned char *c, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *n,
                              const unsigned char *k);

typedef int (*ls_crypto_box_detached_afternm_func_ptr)(unsigned char *c, unsigned char *mac,
                                  const unsigned char *m, unsigned long long mlen,
                                  const unsigned char *n, const unsigned char *k);

typedef int (*ls_crypto_box_open_detached_afternm_func_ptr)(unsigned char *m, const unsigned char *c,
                                       const unsigned char *mac,
                                       unsigned long long clen, const unsigned char *n,
                                       const unsigned char *k);

struct ls_crypto_box_keypair_func_def_s {
    const char *name;
    ls_crypto_box_keypair_func_ptr func;
    const char *signature;
    size_t pksize;
    size_t sksize;
};

struct ls_crypto_box_seed_keypair_func_def_s {
    const char *name;
    ls_crypto_box_seed_keypair_func_ptr func;
    const char *signature;
    size_t pksize;
    size_t sksize;
    size_t seedsize;
};

struct ls_crypto_box_func_def_s {
    const char *name;
    ls_crypto_box_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
    size_t inputzerobytes;
    size_t outputzerobytes;
};

struct ls_crypto_box_open_func_def_s {
    const char *name;
    ls_crypto_box_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
    size_t inputzerobytes;
    size_t outputzerobytes;
};

struct ls_crypto_box_easy_func_def_s {
    const char *name;
    ls_crypto_box_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
};

struct ls_crypto_box_open_easy_func_def_s {
    const char *name;
    ls_crypto_box_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
};

struct ls_crypto_box_detached_func_def_s {
    const char *name;
    ls_crypto_box_detached_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
};

struct ls_crypto_box_open_detached_func_def_s {
    const char *name;
    ls_crypto_box_open_detached_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t pksize;
    size_t sksize;
};

struct ls_crypto_box_beforenm_func_def_s {
    const char *name;
    ls_crypto_box_beforenm_func_ptr func;
    const char *signature;
    size_t ksize;
    size_t pksize;
    size_t sksize;
};

struct ls_crypto_box_easy_afternm_func_def_s {
    const char *name;
    ls_crypto_box_easy_afternm_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t ksize;
};

struct ls_crypto_box_open_easy_afternm_func_def_s {
    const char *name;
    ls_crypto_box_easy_afternm_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t ksize;
};

struct ls_crypto_box_detached_afternm_func_def_s {
    const char *name;
    ls_crypto_box_detached_afternm_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t ksize;
};

struct ls_crypto_box_open_detached_afternm_func_def_s {
    const char *name;
    ls_crypto_box_open_detached_afternm_func_ptr func;
    const char *signature;
    size_t noncesize;
    size_t macsize;
    size_t ksize;
};

typedef struct ls_crypto_box_keypair_func_def_s ls_crypto_box_keypair_func_def;
typedef struct ls_crypto_box_seed_keypair_func_def_s ls_crypto_box_seed_keypair_func_def;
typedef struct ls_crypto_box_func_def_s ls_crypto_box_func_def;
typedef struct ls_crypto_box_open_func_def_s ls_crypto_box_open_func_def;
typedef struct ls_crypto_box_easy_func_def_s ls_crypto_box_easy_func_def;
typedef struct ls_crypto_box_open_easy_func_def_s ls_crypto_box_open_easy_func_def;
typedef struct ls_crypto_box_detached_func_def_s ls_crypto_box_detached_func_def;
typedef struct ls_crypto_box_open_detached_func_def_s ls_crypto_box_open_detached_func_def;

typedef struct ls_crypto_box_beforenm_func_def_s ls_crypto_box_beforenm_func_def;

typedef struct ls_crypto_box_easy_afternm_func_def_s ls_crypto_box_easy_afternm_func_def;
typedef struct ls_crypto_box_open_easy_afternm_func_def_s ls_crypto_box_open_easy_afternm_func_def;
typedef struct ls_crypto_box_detached_afternm_func_def_s ls_crypto_box_detached_afternm_func_def;
typedef struct ls_crypto_box_open_detached_afternm_func_def_s ls_crypto_box_open_detached_afternm_func_def;

static const ls_crypto_box_keypair_func_def ls_crypto_box_keypair_func = {
    LS_FUNC(crypto_box_keypair,ls_crypto_box_keypair_sig),
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
};

static const ls_crypto_box_seed_keypair_func_def ls_crypto_box_seed_keypair_func = {
    LS_FUNC(crypto_box_seed_keypair,ls_crypto_box_seed_keypair_sig),
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
    crypto_box_SEEDBYTES,
};

static const ls_crypto_box_func_def ls_crypto_box_func = {
    LS_FUNC(crypto_box,ls_crypto_box_sig),
    crypto_box_NONCEBYTES,
    crypto_box_MACBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
    crypto_box_BOXZEROBYTES,
    crypto_box_ZEROBYTES,
};

static const ls_crypto_box_open_func_def ls_crypto_box_open_func = {
    LS_FUNC(crypto_box_open,ls_crypto_box_sig),
    crypto_box_NONCEBYTES,
    crypto_box_MACBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
    crypto_box_ZEROBYTES,
    crypto_box_BOXZEROBYTES,
};

static const ls_crypto_box_easy_func_def ls_crypto_box_easy_func = {
    LS_FUNC(crypto_box_easy,ls_crypto_box_sig),
    crypto_box_NONCEBYTES,
    crypto_box_MACBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
};

static const ls_crypto_box_open_easy_func_def ls_crypto_box_open_easy_func = {
    LS_FUNC(crypto_box_open_easy,ls_crypto_box_sig),
    crypto_box_NONCEBYTES,
    crypto_box_MACBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
};

static const ls_crypto_box_detached_func_def ls_crypto_box_detached_func = {
    LS_FUNC(crypto_box_detached,ls_crypto_box_detached_sig),
    crypto_box_NONCEBYTES,
    crypto_box_MACBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
};

static const ls_crypto_box_open_detached_func_def ls_crypto_box_open_detached_func = {
    LS_FUNC(crypto_box_open_detached, ls_crypto_box_open_detached_sig),
    crypto_box_NONCEBYTES,
    crypto_box_MACBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
};

static const ls_crypto_box_beforenm_func_def ls_crypto_box_beforenm_func = {
    LS_FUNC(crypto_box_beforenm, ls_crypto_box_beforenm_sig),
    crypto_box_BEFORENMBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
};

static const ls_crypto_box_easy_afternm_func_def ls_crypto_box_easy_afternm_func = {
    LS_FUNC(crypto_box_easy_afternm, ls_crypto_box_easy_afternm_sig),
    crypto_box_NONCEBYTES,
    crypto_box_MACBYTES,
    crypto_box_BEFORENMBYTES,
};

static const ls_crypto_box_open_easy_afternm_func_def ls_crypto_box_open_easy_afternm_func = {
    LS_FUNC(crypto_box_open_easy_afternm, ls_crypto_box_easy_afternm_sig),
    crypto_box_NONCEBYTES,
    crypto_box_MACBYTES,
    crypto_box_BEFORENMBYTES,
};

static const ls_crypto_box_detached_afternm_func_def ls_crypto_box_detached_afternm_func = {
    LS_FUNC(crypto_box_detached_afternm, ls_crypto_box_detached_afternm_sig),
    crypto_box_NONCEBYTES,
    crypto_box_MACBYTES,
    crypto_box_BEFORENMBYTES,
};

static const ls_crypto_box_open_detached_afternm_func_def ls_crypto_box_open_detached_afternm_func = {
    LS_FUNC(crypto_box_open_detached_afternm, ls_crypto_box_open_detached_afternm_sig),
    crypto_box_NONCEBYTES,
    crypto_box_MACBYTES,
    crypto_box_BEFORENMBYTES,
};

