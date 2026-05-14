# simple-cgi-upload
This is a simple upload site I wrote years ago. This was pretty convenient for quick file transfers and sharing files (especially as an alternative to very large email attachments). It provides a simple interface to upload a single file and then gives you a shareable link.

This was written in perl and uses Apache for the web server, and I always ran it on Debian / Ubuntu (though it would need only minor if any modifications to run on other distributions / web servers).

## Installation
The two html files need to be served by the web server. There are some edits to make if you want to customize / add some information. The `index.html` should be the main entry point.

The `upload.html` file kicks out to the `up.cgi` file, which needs to be placed in the appropriate `cgi-bin` directory. For Apache on Ubuntu, typically that is `/usr/lib/cgi-bin`.

The `up.cgi` file has a few variables that should be set for your system, namely `$base_dir` and `$base_url`, which should point to the same directory (I set this up as the directory where the html files were served from).

This version also supports optional configuration via environment variables or an `upload.conf` file placed alongside `cgi-bin/up.cgi`. The relevant settings include:
* `UPLOAD_BASE_DIR` / `UPLOAD_BASE_URL`
* `UPLOAD_MAX_SIZE` to control the maximum upload payload
* `UPLOAD_MAX_PARAMS` and `UPLOAD_MAX_MULTIPART_RECORDS` to control CGI parser limits
* `UPLOAD_ALLOWED_DIRS` to whitelist subdirectories like `incoming`
* `UPLOAD_FORBIDDEN_EXTENSIONS` to control the extension blacklist
* `UPLOAD_SECURITY_HEADERS` to override or extend HTTP security headers

A sample config file can be created by copying `cgi-bin/upload.conf.example` and adjusting values for your environment.

Finally, you need to make a separate directory that will store the files. This needs to have read and write access for the web server. I set this up as:
* `$base_dir = /var/www/html/files`
* Then make a `/var/www/html/files/incoming` directory and make it world read- and write-able (`chmod 777 /var/www/html/files/incoming`)

If you want to automatically clean up the files (after 30 days in my case), I set up a cron job that ran every day:
`find /var/www/html/files/incoming/ -type f -mtime +30 -print0 | xargs -0 rm -f`

# Disclaimers
There are lots of reasons why you should do something more complicated than this. This is easily susceptible to bad actors (say filling up your hard drive). This is inconvenient if you want to really transfer a lot of files. This has some limitations based on the perl CGI implementation (such as for file size). etc. etc.

But if you want something simple, maybe you are ok with not dealing with these issues (as well as things I am not thinking of). This code is provided as-is, and I make no claims, warrants, or guarantees at all.
