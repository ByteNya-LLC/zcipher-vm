dnl config.m4 for the hydra_stream extension

PHP_ARG_ENABLE([hydra-stream],
  [whether to enable HydraStream cipher support],
  [AS_HELP_STRING([--enable-hydra-stream],
    [Enable HydraStream stream cipher support])],
  [no])

if test "$PHP_HYDRA_STREAM" != "no"; then
  AC_DEFINE(HAVE_HYDRA_STREAM, 1, [ Have HydraStream support ])
  dnl hydra_stream_ext.c includes "../hydra_stream.h" (resolved relative to the
  dnl source file), so no extra include path is required.
  PHP_NEW_EXTENSION(hydra_stream, hydra_stream_ext.c, $ext_shared)
fi
