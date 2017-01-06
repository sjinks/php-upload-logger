#ifndef PHP_UL_H
#define PHP_UL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <main/php.h>
#include <main/php_ini.h>
#include <Zend/zend_modules.h>

#define PHP_UL_EXTNAME  "Upload Logger"
#define PHP_UL_EXTVER   "0.1"

#if defined(__GNUC__) && __GNUC__ >= 4
#	define UL_VISIBILITY_HIDDEN __attribute__((visibility("hidden")))
#else
#	define UL_VISIBILITY_HIDDEN
#endif


#ifdef COMPILE_DL_UPLOADLOGGER
UL_VISIBILITY_HIDDEN
#endif
extern zend_module_entry uploadlogger_module_entry;

#define phpext_uploadlogger_ptr &uploadlogger_module_entry

ZEND_BEGIN_MODULE_GLOBALS(uploadlogger)
    char* dir;
    char* script;
    size_t ctr;
    int fd;
    zend_bool enabled;
ZEND_END_MODULE_GLOBALS(uploadlogger)

UL_VISIBILITY_HIDDEN extern ZEND_DECLARE_MODULE_GLOBALS(uploadlogger)

#ifdef ZTS
#   define UL_G(v) TSRMG(uploadlogger_globals_id, zend_uploadlogger_globals*, v)
#else
#   define UL_G(v) (uploadlogger_globals.v)
#endif

#endif /* PHP_UL_H */
