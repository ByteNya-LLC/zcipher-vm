/*
 * hydra_stream_ext.c
 * ==================
 * PHP extension that wraps the HydraStream stream cipher (hydra_stream.h).
 *
 * Exposes:
 *   Procedural (one-shot, stateless per call):
 *     string hydra_crypt(string $key, string $nonce, string $data)
 *     string hydra_keystream(string $key, string $nonce, int $len)
 *
 *   Object oriented (persistent stream state):
 *     final class HydraStream {
 *         public function __construct(string $key, string $nonce)
 *         public function crypt(string $data): string
 *         public function keystream(int $len): string
 *         public function reset(string $key, string $nonce): void
 *     }
 *
 * Compatible with PHP 8.0 through 8.4.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "Zend/zend_exceptions.h"
#include "php_hydra_stream.h"

/* The cipher implementation lives one directory up (repo root). Quote-include
 * resolves relative to this source file, so it works in any build directory. */
#include "../hydra_stream.h"

/* ── Object model ──────────────────────────────────────────────── */

typedef struct _hydra_object {
    hydra_state_t state;
    zend_bool     initialized;
    zend_object   std;          /* MUST be last */
} hydra_object;

static zend_class_entry   *hydra_stream_ce;
static zend_object_handlers hydra_object_handlers;

static inline hydra_object *hydra_from_obj(zend_object *obj)
{
    return (hydra_object *)((char *)obj - XtOffsetOf(hydra_object, std));
}
#define Z_HYDRA_P(zv) hydra_from_obj(Z_OBJ_P(zv))

static zend_object *hydra_create_object(zend_class_entry *ce)
{
    hydra_object *intern = zend_object_alloc(sizeof(hydra_object), ce);

    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);
    intern->std.handlers = &hydra_object_handlers;
    intern->initialized  = 0;

    return &intern->std;
}

static void hydra_free_object(zend_object *object)
{
    hydra_object *intern = hydra_from_obj(object);

    /* wipe key material / state before releasing */
    memset(&intern->state, 0, sizeof intern->state);
    zend_object_std_dtor(&intern->std);
}

/* ── arginfo ───────────────────────────────────────────────────── */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_hydra_crypt, 0, 3, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, nonce, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_hydra_keystream, 0, 3, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, nonce, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, len, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_HydraStream___construct, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, nonce, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_HydraStream_crypt, 0, 1, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_HydraStream_keystream, 0, 1, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, len, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_HydraStream_reset, 0, 2, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, nonce, IS_STRING, 0)
ZEND_END_ARG_INFO()

/* ── helpers ───────────────────────────────────────────────────── */

/* Returns FAILURE (and throws) if lengths are wrong. */
static int hydra_validate_key_nonce(size_t key_len, int key_arg,
                                    size_t nonce_len, int nonce_arg)
{
    if (key_len != HYDRA_KEY_SIZE) {
        zend_argument_value_error(key_arg, "must be exactly %d bytes", HYDRA_KEY_SIZE);
        return FAILURE;
    }
    if (nonce_len != HYDRA_NONCE_SIZE) {
        zend_argument_value_error(nonce_arg, "must be exactly %d bytes", HYDRA_NONCE_SIZE);
        return FAILURE;
    }
    return SUCCESS;
}

/* ── procedural functions ──────────────────────────────────────── */

PHP_FUNCTION(hydra_crypt)
{
    char *key, *nonce, *data;
    size_t key_len, nonce_len, data_len;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(key, key_len)
        Z_PARAM_STRING(nonce, nonce_len)
        Z_PARAM_STRING(data, data_len)
    ZEND_PARSE_PARAMETERS_END();

    if (hydra_validate_key_nonce(key_len, 1, nonce_len, 2) == FAILURE) {
        RETURN_THROWS();
    }

    zend_string *out = zend_string_alloc(data_len, 0);

    hydra_state_t st;
    hydra_init(&st, (const uint8_t *) key, (const uint8_t *) nonce);
    hydra_crypt(&st, (const uint8_t *) data, (uint8_t *) ZSTR_VAL(out), data_len);
    memset(&st, 0, sizeof st);

    ZSTR_VAL(out)[data_len] = '\0';
    RETURN_STR(out);
}

PHP_FUNCTION(hydra_keystream)
{
    char *key, *nonce;
    size_t key_len, nonce_len;
    zend_long len;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(key, key_len)
        Z_PARAM_STRING(nonce, nonce_len)
        Z_PARAM_LONG(len)
    ZEND_PARSE_PARAMETERS_END();

    if (hydra_validate_key_nonce(key_len, 1, nonce_len, 2) == FAILURE) {
        RETURN_THROWS();
    }
    if (len < 0) {
        zend_argument_value_error(3, "must be greater than or equal to 0");
        RETURN_THROWS();
    }

    zend_string *out = zend_string_alloc((size_t) len, 0);

    hydra_state_t st;
    hydra_init(&st, (const uint8_t *) key, (const uint8_t *) nonce);
    hydra_keystream(&st, (uint8_t *) ZSTR_VAL(out), (size_t) len);
    memset(&st, 0, sizeof st);

    ZSTR_VAL(out)[len] = '\0';
    RETURN_STR(out);
}

/* ── class methods ─────────────────────────────────────────────── */

PHP_METHOD(HydraStream, __construct)
{
    char *key, *nonce;
    size_t key_len, nonce_len;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(key, key_len)
        Z_PARAM_STRING(nonce, nonce_len)
    ZEND_PARSE_PARAMETERS_END();

    if (hydra_validate_key_nonce(key_len, 1, nonce_len, 2) == FAILURE) {
        RETURN_THROWS();
    }

    hydra_object *intern = Z_HYDRA_P(ZEND_THIS);
    hydra_init(&intern->state, (const uint8_t *) key, (const uint8_t *) nonce);
    intern->initialized = 1;
}

PHP_METHOD(HydraStream, reset)
{
    char *key, *nonce;
    size_t key_len, nonce_len;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(key, key_len)
        Z_PARAM_STRING(nonce, nonce_len)
    ZEND_PARSE_PARAMETERS_END();

    if (hydra_validate_key_nonce(key_len, 1, nonce_len, 2) == FAILURE) {
        RETURN_THROWS();
    }

    hydra_object *intern = Z_HYDRA_P(ZEND_THIS);
    hydra_init(&intern->state, (const uint8_t *) key, (const uint8_t *) nonce);
    intern->initialized = 1;
}

PHP_METHOD(HydraStream, crypt)
{
    char *data;
    size_t data_len;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(data, data_len)
    ZEND_PARSE_PARAMETERS_END();

    hydra_object *intern = Z_HYDRA_P(ZEND_THIS);
    if (!intern->initialized) {
        zend_throw_error(NULL, "HydraStream instance is not initialized");
        RETURN_THROWS();
    }

    zend_string *out = zend_string_alloc(data_len, 0);
    hydra_crypt(&intern->state, (const uint8_t *) data, (uint8_t *) ZSTR_VAL(out), data_len);
    ZSTR_VAL(out)[data_len] = '\0';
    RETURN_STR(out);
}

PHP_METHOD(HydraStream, keystream)
{
    zend_long len;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(len)
    ZEND_PARSE_PARAMETERS_END();

    if (len < 0) {
        zend_argument_value_error(1, "must be greater than or equal to 0");
        RETURN_THROWS();
    }

    hydra_object *intern = Z_HYDRA_P(ZEND_THIS);
    if (!intern->initialized) {
        zend_throw_error(NULL, "HydraStream instance is not initialized");
        RETURN_THROWS();
    }

    zend_string *out = zend_string_alloc((size_t) len, 0);
    hydra_keystream(&intern->state, (uint8_t *) ZSTR_VAL(out), (size_t) len);
    ZSTR_VAL(out)[len] = '\0';
    RETURN_STR(out);
}

/* ── function / method tables ──────────────────────────────────── */

static const zend_function_entry hydra_stream_functions[] = {
    PHP_FE(hydra_crypt,     arginfo_hydra_crypt)
    PHP_FE(hydra_keystream, arginfo_hydra_keystream)
    PHP_FE_END
};

static const zend_function_entry class_HydraStream_methods[] = {
    PHP_ME(HydraStream, __construct, arginfo_class_HydraStream___construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(HydraStream, crypt,       arginfo_class_HydraStream_crypt,       ZEND_ACC_PUBLIC)
    PHP_ME(HydraStream, keystream,   arginfo_class_HydraStream_keystream,   ZEND_ACC_PUBLIC)
    PHP_ME(HydraStream, reset,       arginfo_class_HydraStream_reset,       ZEND_ACC_PUBLIC)
    PHP_FE_END
};

/* ── module lifecycle ──────────────────────────────────────────── */

PHP_MINIT_FUNCTION(hydra_stream)
{
    zend_class_entry ce;
    INIT_CLASS_ENTRY(ce, "HydraStream", class_HydraStream_methods);

    hydra_stream_ce = zend_register_internal_class(&ce);
    hydra_stream_ce->create_object = hydra_create_object;
    hydra_stream_ce->ce_flags |= ZEND_ACC_FINAL;

    memcpy(&hydra_object_handlers, zend_get_std_object_handlers(),
           sizeof(zend_object_handlers));
    hydra_object_handlers.offset    = XtOffsetOf(hydra_object, std);
    hydra_object_handlers.free_obj  = hydra_free_object;
    hydra_object_handlers.clone_obj = NULL; /* state is not safe to clone */

    /* expose useful constants to PHP land */
    REGISTER_LONG_CONSTANT("HYDRA_KEY_SIZE",   HYDRA_KEY_SIZE,   CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("HYDRA_NONCE_SIZE", HYDRA_NONCE_SIZE, CONST_CS | CONST_PERSISTENT);

    return SUCCESS;
}

PHP_MINFO_FUNCTION(hydra_stream)
{
    php_info_print_table_start();
    php_info_print_table_row(2, "HydraStream support", "enabled");
    php_info_print_table_row(2, "Extension version", PHP_HYDRA_STREAM_VERSION);
    php_info_print_table_end();
}

zend_module_entry hydra_stream_module_entry = {
    STANDARD_MODULE_HEADER,
    "hydra_stream",
    hydra_stream_functions,
    PHP_MINIT(hydra_stream),
    NULL,   /* MSHUTDOWN */
    NULL,   /* RINIT */
    NULL,   /* RSHUTDOWN */
    PHP_MINFO(hydra_stream),
    PHP_HYDRA_STREAM_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_HYDRA_STREAM
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(hydra_stream)
#endif
