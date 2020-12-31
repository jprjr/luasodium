const char * const ls_randombytes_random_sig =
  "uint32_t (*)(void)";

const char * const ls_randombytes_uniform_sig =
  "uint32_t (*)(const uint32_t upper_bound)";

const char * const ls_randombytes_buf_sig =
  "void (*)(void * const buf, const size_t size)";

const char * const ls_randombytes_buf_deterministic_sig =
  "void (*)(void * const buf, const size_t size,"
  "const unsigned char *seed)";

const char * const ls_randombytes_close_sig =
  "int (*)(void)";

const char * const ls_randombytes_stir_sig =
  "void (*)(void)";

typedef uint32_t (*ls_randombytes_random_func_ptr)(void);
typedef uint32_t (*ls_randombytes_uniform_func_ptr)(const uint32_t upper_bound);
typedef void (*ls_randombytes_buf_func_ptr)(void * const buf, const size_t size);
typedef void (*ls_randombytes_buf_deterministic_func_ptr)(void * const buf,
  const size_t size, const unsigned char *seed);
typedef int (*ls_randombytes_close_func_ptr)(void);
typedef void (*ls_randombytes_stir_func_ptr)(void);

struct ls_randombytes_random_func_def_s {
    const char *name;
    ls_randombytes_random_func_ptr func;
    const char *signature;
};

struct ls_randombytes_uniform_func_def_s {
    const char *name;
    ls_randombytes_uniform_func_ptr func;
    const char *signature;
};

struct ls_randombytes_buf_func_def_s {
    const char *name;
    ls_randombytes_buf_func_ptr func;
    const char *signature;
};

struct ls_randombytes_buf_deterministic_func_def_s {
    const char *name;
    ls_randombytes_buf_deterministic_func_ptr func;
    const char *signature;
    size_t seedbytes;
};

struct ls_randombytes_close_func_def_s {
    const char *name;
    ls_randombytes_close_func_ptr func;
    const char *signature;
};

struct ls_randombytes_stir_func_def_s {
    const char *name;
    ls_randombytes_stir_func_ptr func;
    const char *signature;
};

typedef struct ls_randombytes_random_func_def_s  ls_randombytes_random_func_def;
typedef struct ls_randombytes_uniform_func_def_s ls_randombytes_uniform_func_def;
typedef struct ls_randombytes_buf_func_def_s ls_randombytes_buf_func_def;
typedef struct ls_randombytes_buf_deterministic_func_def_s ls_randombytes_buf_deterministic_func_def;
typedef struct ls_randombytes_close_func_def_s ls_randombytes_close_func_def;
typedef struct ls_randombytes_stir_func_def_s ls_randombytes_stir_func_def;

static const ls_randombytes_random_func_def ls_randombytes_random_func = {
    LS_FUNC(randombytes_random,ls_randombytes_random_sig)
};

static const ls_randombytes_uniform_func_def ls_randombytes_uniform_func = {
    LS_FUNC(randombytes_uniform,ls_randombytes_uniform_sig)
};

static const ls_randombytes_buf_func_def ls_randombytes_buf_func = {
    LS_FUNC(randombytes_buf,ls_randombytes_buf_sig)
};

static const ls_randombytes_buf_deterministic_func_def ls_randombytes_buf_deterministic_func = {
    LS_FUNC(randombytes_buf_deterministic,ls_randombytes_buf_deterministic_sig),
    randombytes_SEEDBYTES
};

static const ls_randombytes_close_func_def ls_randombytes_close_func = {
    LS_FUNC(randombytes_close,ls_randombytes_close_sig)
};

static const ls_randombytes_stir_func_def ls_randombytes_stir_func = {
    LS_FUNC(randombytes_stir,ls_randombytes_stir_sig)
};
