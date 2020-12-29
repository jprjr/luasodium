/* types shared by c and ffi */
#define str(s) #s

typedef int (*secretbox_func)(unsigned char *c,
                              const unsigned char *m,
                              unsigned long long mlen,
                              const unsigned char *n,
                              const unsigned char *k);

typedef int (*secretbox_easy_func)(unsigned char *c,
                              const unsigned char *m,
                              unsigned long long mlen,
                              const unsigned char *n,
                              const unsigned char *k);

typedef int (*secretbox_detached_func)(unsigned char *c,
                                       unsigned char *mac,
                                       const unsigned char *m,
                                       unsigned long long mlen,
                                       const unsigned char *n,
                                       const unsigned char *k);

typedef int (*secretbox_open_detached_func)(unsigned char *m,
                                            const unsigned char *c,
                                            const unsigned char *mac,
                                            unsigned long long clen,
                                            const unsigned char *n,
                                            const unsigned char *k);


typedef void (*secretbox_keygen_func)(unsigned char *k);

struct secretbox_func_def_s {
    secretbox_func secretbox;
    const char *secretbox_name;
    secretbox_func open;
    const char *open_name;
    size_t noncebytes;
    size_t keybytes;
    size_t zerobytes;
    size_t boxzerobytes;
    size_t macbytes;
};

struct secretbox_easy_func_def_s {
    secretbox_easy_func secretbox;
    const char *secretbox_name;
    secretbox_easy_func open;
    const char *open_name;
    size_t noncebytes;
    size_t keybytes;
    size_t macbytes;
};

struct secretbox_detached_func_def_s {
    secretbox_detached_func secretbox;
    const char *secretbox_name;
    secretbox_open_detached_func open;
    const char *open_name;
    size_t noncebytes;
    size_t keybytes;
    size_t macbytes;
};

struct secretbox_keygen_func_def_s {
    secretbox_keygen_func keygen;
    const char *name;
    size_t size;
};

typedef struct secretbox_func_def_s secretbox_func_def;
typedef struct secretbox_easy_func_def_s secretbox_easy_func_def;
typedef struct secretbox_detached_func_def_s secretbox_detached_func_def;
typedef struct secretbox_keygen_func_def_s secretbox_keygen_func_def;

static const secretbox_func_def secretbox_funcs[] = {
    {
      crypto_secretbox,
      str(crypto_secretbox),
      crypto_secretbox_open,
      str(crypto_secretbox_open),
      crypto_secretbox_NONCEBYTES,
      crypto_secretbox_KEYBYTES,
      crypto_secretbox_ZEROBYTES,
      crypto_secretbox_BOXZEROBYTES,
      crypto_secretbox_MACBYTES,
    },
    { crypto_secretbox_xsalsa20poly1305,
      str(crypto_secretbox_xsalsa20poly1305),
      crypto_secretbox_xsalsa20poly1305_open,
      str(crypto_secretbox_xsalsa20poly1305_open),
      crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
      crypto_secretbox_xsalsa20poly1305_KEYBYTES,
      crypto_secretbox_xsalsa20poly1305_ZEROBYTES,
      crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES,
      crypto_secretbox_xsalsa20poly1305_MACBYTES,
    },
    { NULL }
};


static const secretbox_easy_func_def secretbox_easy_funcs[] = {
    {
      crypto_secretbox_easy,
      str(crypto_secretbox_easy),
      crypto_secretbox_open_easy,
      str(crypto_secretbox_open_easy),
      crypto_secretbox_NONCEBYTES,
      crypto_secretbox_KEYBYTES,
      crypto_secretbox_MACBYTES,
    },
    {
      crypto_secretbox_xchacha20poly1305_easy,
      str(crypto_secretbox_xchacha20poly1305_easy),
      crypto_secretbox_xchacha20poly1305_open_easy,
      str(crypto_secretbox_xchacha20poly1305_open_easy),
      crypto_secretbox_xchacha20poly1305_NONCEBYTES,
      crypto_secretbox_xchacha20poly1305_KEYBYTES,
      crypto_secretbox_xchacha20poly1305_MACBYTES,
    },
    { NULL }
};

static const secretbox_detached_func_def secretbox_detached_funcs[] = {
    {
      crypto_secretbox_detached,
      str(crypto_secretbox_detached),
      crypto_secretbox_open_detached,
      str(crypto_secretbox_open_detached),
      crypto_secretbox_NONCEBYTES,
      crypto_secretbox_KEYBYTES,
      crypto_secretbox_MACBYTES,
    },
    {
      crypto_secretbox_xchacha20poly1305_detached,
      str(crypto_secretbox_xchacha20poly1305_detached),
      crypto_secretbox_xchacha20poly1305_open_detached,
      str(crypto_secretbox_xchacha20poly1305_open_detached),
      crypto_secretbox_xchacha20poly1305_NONCEBYTES,
      crypto_secretbox_xchacha20poly1305_KEYBYTES,
      crypto_secretbox_xchacha20poly1305_MACBYTES,
    },
    { NULL }
};

static const secretbox_keygen_func_def secretbox_keygen_funcs[] = {
    {
        crypto_secretbox_keygen,
        str(crypto_secretbox_keygen),
        crypto_secretbox_KEYBYTES
    },
    {
        crypto_secretbox_xsalsa20poly1305_keygen,
        str(crypto_secretbox_xsalsa20poly1305_keygen),
        crypto_secretbox_xsalsa20poly1305_KEYBYTES
    },
    { NULL }
};

