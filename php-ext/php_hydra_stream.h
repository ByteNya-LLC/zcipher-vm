/*
 * php_hydra_stream.h - PHP extension wrapper for HydraStream cipher.
 */
#ifndef PHP_HYDRA_STREAM_H
#define PHP_HYDRA_STREAM_H

extern zend_module_entry hydra_stream_module_entry;
#define phpext_hydra_stream_ptr &hydra_stream_module_entry

#define PHP_HYDRA_STREAM_VERSION "1.0.0"

#if defined(ZTS) && defined(COMPILE_DL_HYDRA_STREAM)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#endif /* PHP_HYDRA_STREAM_H */
