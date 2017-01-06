#include "php_ul.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <Zend/zend.h>
#include <ext/standard/php_smart_string.h>
#include <ext/standard/info.h>
#include <main/rfc1867.h>
#include <main/SAPI.h>
#include <main/spprintf.h>

static int  (*old_rfc1867_callback)(unsigned int, void*, void**)    = NULL;
static void (*old_move_uploaded_file)(INTERNAL_FUNCTION_PARAMETERS) = NULL;

ZEND_DECLARE_MODULE_GLOBALS(uploadlogger);

PHP_INI_BEGIN()
    STD_PHP_INI_BOOLEAN("ul.enabled", "0",    PHP_INI_PERDIR, OnUpdateBool,   enabled, zend_uploadlogger_globals, uploadlogger_globals)
    STD_PHP_INI_ENTRY("ul.dir",       "/tmp", PHP_INI_PERDIR, OnUpdateString, dir,     zend_uploadlogger_globals, uploadlogger_globals)
PHP_INI_END()

static char* get_filename()
{
    char* buf;
    spprintf(&buf, 1024, "%s/%lu.log", UL_G(dir), (unsigned long)getuid());
    return buf;
}

static void get_fileid(smart_string* s)
{
    unsigned long int pid = (unsigned long int)getpid();
    unsigned long int ctr = (unsigned long int)UL_G(file_id);
#ifdef ZTS
    unsigned long int tid = (unsigned long int)tsrm_thread_id();
#endif

    smart_string_append_long(s, pid);
    smart_string_appendc(s, '_');
#ifdef ZTS
    smart_string_append_long(s, tid);
    smart_string_appendc(s, '_');
#endif
    smart_string_append_long(s, ctr);
}

static void get_remote_addr(smart_string* s)
{
    char* remote_addr          = NULL;
    char* http_x_forwarded_for = NULL;
    char* cf_connecting_ip     = NULL;
    /// TODO: do I really need to estrdup() values?
    if (sapi_module.getenv) {
        char* tmp;
        tmp = sapi_module.getenv(ZEND_STRL("REMOTE_ADDR"));
        if (tmp) remote_addr = estrdup(tmp);
        tmp = sapi_module.getenv(ZEND_STRL("HTTP_X_FORWARDED_FOR"));
        if (tmp) http_x_forwarded_for = estrdup(tmp);
        tmp = sapi_module.getenv(ZEND_STRL("HTTP_CF_CONNECTING_IP"));
        if (tmp) cf_connecting_ip = estrdup(tmp);
    }

    if (!remote_addr && !PG(during_request_startup)) {
        zval* server;
        zval* v;

        zend_is_auto_global_str(ZEND_STRL("_SERVER"));
        server = &PG(http_globals)[TRACK_VARS_SERVER];

        v = zend_hash_str_find(Z_ARRVAL_P(server), ZEND_STRL("REMOTE_ADDR"));
        if (v && Z_TYPE_P(v) == IS_STRING) {
            remote_addr = estrndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
        }

        v = zend_hash_str_find(Z_ARRVAL_P(server), ZEND_STRL("HTTP_X_FORWARDED_FOR"));
        if (v && Z_TYPE_P(v) == IS_STRING) {
            http_x_forwarded_for = estrndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
        }

        v = zend_hash_str_find(Z_ARRVAL_P(server), ZEND_STRL("HTTP_CF_CONNECTING_IP"));
        if (v && Z_TYPE_P(v) == IS_STRING) {
            cf_connecting_ip = estrndup(Z_STRVAL_P(v), Z_STRLEN_P(v));
        }
    }

    if (!remote_addr) {
        char* tmp;
        tmp = getenv("REMOTE_ADDR");
        if (tmp) remote_addr = estrdup(tmp);
        tmp = getenv("HTTP_X_FORWARDED_FOR");
        if (tmp) http_x_forwarded_for = estrdup(tmp);
        tmp = getenv("HTTP_CF_CONNECTING_IP");
        if (tmp) cf_connecting_ip = estrdup(tmp);
    }

    smart_string_appends(s, "REMOTE_ADDR: ");
    smart_string_appends(s, remote_addr ? remote_addr : "N/A");
    smart_string_appendc(s, '\n');

    if (http_x_forwarded_for) {
        smart_string_appends(s, "HTTP_X_FORWARDED_FOR: ");
        smart_string_appends(s, http_x_forwarded_for ? http_x_forwarded_for : "N/A");
        smart_string_appendc(s, '\n');
    }

    if (cf_connecting_ip) {
        smart_string_appends(s, "HTTP_CF_CONNECTING_IP: ");
        smart_string_appends(s, cf_connecting_ip ? cf_connecting_ip : "N/A");
        smart_string_appendc(s, '\n');
    }

    efree(remote_addr);
    efree(http_x_forwarded_for);
    efree(cf_connecting_ip);
}

static void get_current_time(smart_string* s)
{
    char buf[32];
    time_t t      = time(NULL);
    struct tm* tm = localtime(&t);
    size_t len    = strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S]", tm);

    smart_string_appendl(s, buf, len);
}

static ssize_t safe_write(int fd, const char* buf, size_t len)
{
    ssize_t res;
    do {
        res = write(fd, buf, len);
    } while (-1 == res && (EAGAIN == errno || EINTR == errno));

    return res;
}

static int my_rfc1867_callback(unsigned int event, void* event_data, void** extra)
{
    if (UL_G(enabled) && UL_G(dir)) {
        if (MULTIPART_EVENT_FILE_START == event) {
            multipart_event_file_start* data = (multipart_event_file_start*)event_data;
            int fd = UL_G(fd);
            char* filename;

            if (fd != -1) {
                close(fd);
            }

            filename = get_filename();
            if (!filename) {
                zend_error(E_WARNING, "Out of memory");
                return FAILURE;
            }

            fd = open(filename, O_CREAT | O_APPEND | O_WRONLY, 0600);
            if (fd == -1) {
                zend_error(E_WARNING, "Failed to open file %s (%s)", filename, strerror(errno));
                efree(filename);
                return FAILURE;
            }

            efree(filename);
            UL_G(fd) = fd;
            ++UL_G(file_id);

            {
                smart_string s        = { NULL, 0, 0 };
                char* filename        = *(data->filename);
                char* path_translated = SG(request_info).path_translated;
                char* query_string    = SG(request_info).query_string;
                char* request_uri     = SG(request_info).request_uri;

                get_current_time(&s);
                smart_string_appends(&s, " File ID: ");
                get_fileid(&s);
                smart_string_appends(&s, "\nFilename: ");
                smart_string_appends(&s, filename ? filename : "N/A");
                smart_string_appends(&s, "\nREQUEST_URI: ");
                smart_string_appends(&s, request_uri ? request_uri : "N/A");
                smart_string_appends(&s, "\nPATH_TRANSLATED: ");
                smart_string_appends(&s, path_translated ? path_translated : "N/A");
                smart_string_appends(&s, "\nQUERY_STRING: ");
                smart_string_appends(&s, query_string ? query_string : "N/A");
                smart_string_appendc(&s, '\n');
                get_remote_addr(&s);
                smart_string_appends(&s, "\n\n");
                smart_string_0(&s);

                safe_write(fd, s.c, s.len);
                smart_string_free(&s);
            }
        }
        else if (MULTIPART_EVENT_FILE_END == event) {
            int fd = UL_G(fd);
            if (fd != -1) {
                multipart_event_file_end* data = (multipart_event_file_end*)event_data;
                smart_string s                 = { NULL, 0, 0 };
                char* filename                 = data->temp_filename;

                get_current_time(&s);
                smart_string_appends(&s, " File ID: ");
                get_fileid(&s);
                smart_string_appends(&s, "\nTemporary filename: ");
                smart_string_appends(&s, filename ? filename : "N/A");
                smart_string_appends(&s, "\nUpload status: ");
                smart_string_append_long(&s, data->cancel_upload);
                smart_string_appends(&s, "\n\n\n");
                smart_string_0(&s);

                safe_write(fd, s.c, s.len);
                smart_string_free(&s);
                fsync(fd);
                close(fd);
                UL_G(fd) = -1;
            }
        }
    }

    return old_rfc1867_callback ? old_rfc1867_callback(event, event_data, extra) : SUCCESS;
}

static PHP_FUNCTION(move_uploaded_file)
{
    assert(old_move_uploaded_file != NULL);
    old_move_uploaded_file(INTERNAL_FUNCTION_PARAM_PASSTHRU);

    if (UL_G(enabled) && UL_G(dir)) {
        int fd;
        char* path;
        char* new_path;
        char* filename;
        size_t path_len, new_path_len;

        if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &path, &path_len, &new_path, &new_path_len) == FAILURE) {
            return;
        }

        filename = get_filename();
        if (!filename) {
            return;
        }

        fd = open(filename, O_CREAT | O_APPEND | O_WRONLY, 0600);
        if (fd == -1) {
            zend_error(E_WARNING, "Failed to open file %s (%s)", filename, strerror(errno));
            efree(filename);
            return;
        }

        efree(filename);

        {
            smart_string s = { NULL, 0, 0 };
            get_current_time(&s);
            smart_string_appendc(&s, '\n');
            get_remote_addr(&s);
            smart_string_appends(&s, "move_uploaded_file: old=");
            smart_string_appendl(&s, path, path_len);
            smart_string_appends(&s, ", new=");
            smart_string_appendl(&s, new_path, new_path_len);
            smart_string_appends(&s, ", status=");
            smart_string_appends(&s, zend_is_true(return_value) ? "SUCCESS" : "FAILURE");
            smart_string_appends(&s, "\n\n\n");
            smart_string_0(&s);

            safe_write(fd, s.c, s.len);
            smart_string_free(&s);
            fsync(fd);
            close(fd);
        }
    }
}

static PHP_GINIT_FUNCTION(uploadlogger)
{
    uploadlogger_globals->enabled  = 0;
    uploadlogger_globals->dir      = NULL;
    uploadlogger_globals->fd       = -1;
    uploadlogger_globals->file_id  = 0;
}

static PHP_MINIT_FUNCTION(uploadlogger)
{
    zend_internal_function* func = zend_hash_str_find_ptr(CG(function_table), ZEND_STRL("move_uploaded_file"));
    if (func) {
        old_move_uploaded_file = func->handler;
        func->handler          = PHP_FN(move_uploaded_file);
    }

    old_rfc1867_callback = php_rfc1867_callback;
    php_rfc1867_callback = my_rfc1867_callback;

    REGISTER_INI_ENTRIES();
    return SUCCESS;
}

static PHP_MSHUTDOWN_FUNCTION(uploadlogger)
{
    UNREGISTER_INI_ENTRIES();
    php_rfc1867_callback = old_rfc1867_callback;

    if (old_move_uploaded_file) {
        zend_internal_function* func = zend_hash_str_find_ptr(CG(function_table), ZEND_STRL("move_uploaded_file"));
        if (func) {
            func->handler = old_move_uploaded_file;
        }
    }

    if (UL_G(fd) != -1) {
        close(UL_G(fd));
    }

    return SUCCESS;
}

static PHP_MINFO_FUNCTION(uploadlogger)
{
    php_info_print_table_start();
    php_info_print_table_row(2, "Track File Uploads", "enabled");
    php_info_print_table_row(2, "version", PHP_UL_EXTVER);
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}

zend_module_entry uploadlogger_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_UL_EXTNAME,
    NULL,
    PHP_MINIT(uploadlogger),
    PHP_MSHUTDOWN(uploadlogger),
    NULL,
    NULL,
    PHP_MINFO(uploadlogger),
    PHP_UL_EXTVER,
    PHP_MODULE_GLOBALS(uploadlogger),
    PHP_GINIT(uploadlogger),
    NULL,
    NULL,
    STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_UPLOADLOGGER
ZEND_GET_MODULE(uploadlogger)
#endif
