PHP_ARG_ENABLE(upload-logger, whether to enable file upload logging, [ --enable-upload-logging  Enable file upload logging])

if test "$PHP_UPLOAD_LOGGER" = "yes"; then
	AC_DEFINE([HAVE_UPLOAD_LOGGER], [1], [Whether file upload logging is enabled])
	PHP_NEW_EXTENSION([uploadlogger], [ul.c], $ext_shared,, [-Wall])
fi
