# php-upload-logger

[![Build Status](https://travis-ci.org/sjinks/php-upload-logger.png?branch=master)](https://travis-ci.org/sjinks/php-upload-logger)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/11356/badge.svg)](https://scan.coverity.com/projects/sjinks-php-upload-logger)

PHP extension to track and log all file uploads.

## About

This is a tool that I use myself to track malicious file uploads.
If someone else finds it useful, well, I will be glad.

Sometimes, looking into `/tmp`, I see something like this:

```
'/tmp/php2X0Uup'
# Known exploit = [Fingerprint Match] [PHP POST Exploit [P0806]]

'/tmp/php5E9xaH'
# Known exploit = [Fingerprint Match] [PHP POST Exploit [P0892]]

'/tmp/php65shDi'
# Known exploit = [Fingerprint Match] [PHP POST Exploit [P0892]]

'/tmp/php9v1E5t'
# Known exploit = [Fingerprint Match] [PHP POST Exploit [P0892]]

'/tmp/phpA2JC27'
# Known exploit = [Fingerprint Match] [PHP POST Exploit [P0892]]
…
```

These files are leftovers from vulnerability scans: a scan tool
tried to exploit a suspected vulnerability somewhere, and tried
to upload a malicious file. But because the component the attacker
tried to exploit was not vulnerable and rejected the upload,
the file the attacker had tried to upload was left in `/tmp`
(I still wonder why PHP does not delete such files after the end
of the request).

It was always interesting for me to know who upload such files,
and what component they are trying to exploit. This is how this
extension was born :-)

## Installation

```bash
phpize && ./configure && make && sudo make install
```

Tested to work under PHP 7.0 and 7.1. It will not compile for PHP 5,
but it should be trivial to fix.

## Configuration

Right now there are three configuration directives (to be added to
`php.ini`) controlling the behavior of the extsnsion (both are
`PHP_INI_PREDIR`):

  * `ul.enabled` (boolean, default is `false`): whether Upload
  Logger is enabled.
  * `ul.dir` (string, default is `/tmp`): directory where Upload
  Logger writes its log files.
  * `ul.verification_script` (string, default is empty): path to
  the verification script to be run for every uploaded file.

Log files are named `UID`.log, where `UID` is the ID of the user
PHP runs as. Log files are created with 0600 permissions.

The reason why there is a separate file for every user is that there
could be multiple PHP processes running as different users (think of
php-fpm or [chuid](https://github.com/sjinks/php-chuid)): in this case
the log file either needs to be world writable (I hate this), or it might
be necessary to add all users to the single group (and use 0660
permissions), but this complicates the configuration.

## Principle of Operation

Upload Logger sets its own callback for `php_rfc1867_callback` (it is called
when PHP parses multipart/form-data and handles file upload). It listens for
two events:

  * `MULTIPART_EVENT_FILE_START`: this one is triggered when PHP starts to
  process the upload. At this moment we know the original filename of the
  uploaded file.
  * `MULTIPART_EVENT_FILE_END`: this one is triggered when PHP finishes to
  process the uploaded file. At this moment we know the size of the file, and
  the name of the temporary file to which the uploaded file was written
  (it corresponds to `$_FILES['userfile']['tmp_name']`).

The most common way to save the uploaded file is [`move_uploaded_file`](http://php.net/manual/en/function.move-uploaded-file.php).
Therefore Upload Logger intercepts this function, and logs the temporary
and the new filenames.

## Log File

This is how the log file looks like:

```
[2017-01-05 13:43:05] File ID: 27008_139636915363904_1
Filename: 3 - 1.JPG
REQUEST_URI: /wp-admin/async-upload.php
PATH_TRANSLATED: /home/***/wp-admin/async-upload.php
QUERY_STRING:
REMOTE_ADDR: 1.2.3.4
HTTP_X_FORWARDED_FOR: 5.6.7.8


[2017-01-05 13:43:05] File ID: 27008_139636915363904_1
Temporary filename: /tmp/phpJvX3jY
Upload status: 0


[2017-01-05 13:43:05]
REMOTE_ADDR: 1.2.3.4
HTTP_X_FORWARDED_FOR: 5.6.7.8
move_uploaded_file: old=/tmp/phpJvX3jY, new=/home/*/wp-content/uploads/2017/01/3-1.jpg, status=SUCCESS
```

*The first block* is written during the `MULTIPART_EVENT_FILE_START` phase.

`File ID` is used to distinguish between different threads and processes
and consists of two (NTS) or three (ZTS) fields separarted with `_`:
`PID_TID_CTR`

  * `PID` is the process ID (useful for, say, php-fpm or php-cgi);
  * `TID` is thread ID (only if PHP was compiled with ZTS support);
  * `CTR` incrementing counter for the given `PID` and `TID`.

`Filename` is the original filename.

`REQUEST_URI`, `PATH_TRANSLATED`, `QUERY_STRING` are the request URI,
the name of the file that is meant to handle the upload, and the
query string respectively. Note that these variables are read directly
from the SAPI module, and therefore they cannot be "overridden" by
replacing a corresponding `$_SERVER` variable (moreover, when PHP handles
uploads, `$_SERVER` variables are not yet available anyway).

`REMOTE_ADDR` and `HTTP_X_FORWARDED_FOR` (and `HTTP_CF_CONNECTING_IP`)
contain the remote address of the uploader. These data are gotten from
the SAPI, and therefore may not always be available (ie, when the PHP
CLI binary runs in server mode, `REMOTE_ADDR` et al are not available).

*The second block* is written during the `MULTIPART_EVENT_FILE_END` phase.

`Temporary filename` is the name of the temporary file to which PHP has
written the uploaded data.

`Upload status` is the indication whether the file has been successully
uploaded (0). The codes are available [here](http://php.net/manual/en/features.file-upload.errors.php).

*The third block* is written during execution of `move_uploaded_file()`.
It also contains the remote address because sometimes it may not be possible
to get it during the `MULTIPART_EVENT_FILE_START` phase.

The `move_uploaded_file` line:

```
move_uploaded_file: old=TEMPORARY_FILENAME, new=NEW_FILENAME, status=SUCCESS_or_FAILURE
```

`old` and `new` are the original arguments passed to `move_uploaded_file` (ie,
`move_uploaded_file($old, $new)`) and status (`SUCCESS` or `FAILURE`) is the result
returned by `move_uploaded_file` (`SUCCESS` obviously corresponds to `true`).

## Upload Verification Script

Upload Logger can run custom verification script for every uploaded file.
The name of the script is specified in the `ul.verification_script`
configuration directive.

The script must be an executable (script or binary) file.

**WARNING:** failure to locate or execute the script leads to rejection of
the uploaded file.

The verification script is invoked as follows:

```bash
/path/to/script /path/to/uploaded/file 2>&1
```

That is, the name of the file to check is given as the first argument.

If the script has no objections as to the uploaded file, it should print
the plus (`+`) sign. Everything else is treated as the objection.

### Sample Verification Script

The script below assumes that you have the ClamAV daemon installed and
running, and `clamdscan` binary is available.

```bash
#!/bin/sh

# This normally should not happen unless the script is invoked manually
if [ "x$1" = "x" ]; then
    echo '-'
    exit 10
fi

# Scan the file with ClamAV
# Return code of 0 means the file is possibly clean
OUT=$(clamdscan --fdpass --infected --no-summary "$1")
RC=$?

if [ $RC -eq 0 ]; then
    # Allow the file
    echo '+'
else
    # Reject the file and print the scan log
    echo '-'
    echo "$OUT"
fi

exit $RC

```

Possible output when the [EICAR Test File](https://en.wikipedia.org/wiki/EICAR_test_file)
is uploaded:

```
[2017-01-06 11:20:31] File ID: 27008_139636915363904_1
Filename: eicar.com
REQUEST_URI: /index.php
PATH_TRANSLATED: /var/www/php-upload-logger-test/index.php
QUERY_STRING: N/A
REMOTE_ADDR: N/A


[2017-01-06 11:20:31] File ID: 27008_139636915363904_1
Temporary filename: /tmp/phpqIjGWR
Upload status: 0
The file is disallowed by the verification script:
-
/tmp/phpqIjGWR: Eicar-Test-Signature FOUND


```
