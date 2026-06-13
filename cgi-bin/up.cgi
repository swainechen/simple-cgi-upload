#!/usr/bin/perl
use strict;
use warnings;

my $debug = 0;
use File::Basename qw(basename fileparse_set_fstype);
use File::Spec;
use Fcntl qw(:DEFAULT O_RDONLY O_NOFOLLOW);
use FindBin qw($Bin);
use Digest::SHA;
use CGI;

# SECURITY: Pre-load variables to avoid "used only once" warnings
$CGI::POST_MAX = $CGI::POST_MAX;
$CGI::MAX_PARAMS = $CGI::MAX_PARAMS;
$CGI::MAX_MULTIPART_RECORDS = $CGI::MAX_MULTIPART_RECORDS;
$CGI::LIST_CONTEXT_WARN = $CGI::LIST_CONTEXT_WARN;

# SECURITY: Sanitize remote IP for logging as early as possible.
my $remote_ip = $ENV{REMOTE_ADDR} || 'unknown';
$remote_ip =~ s/[^\w\.\-:]//g;

sub trim {
    my ($value) = @_;
    return '' unless defined $value;
    $value =~ s/^\s+|\s+$//g;
    return $value;
}

# SECURITY: Helper to sanitize data for logging to prevent log injection
sub sanitize_for_log {
    my ($data) = @_;
    $data = '' unless defined $data;
    $data =~ s/[^\w\ \-\.]//g;
    return $data;
}

# GLOBAL OBJECTS (pre-initialized for use in early error handling)
my $cgi;
my %sec_headers;

# SECURITY: Centralized error handling
sub send_error {
    my ($status, $message) = @_;
    # SECURITY: Ensure we have a CGI object for headers if not yet initialized
    $cgi ||= new CGI;
    # SECURITY: Sanitize for logging to prevent log injection
    my $san_status = sanitize_for_log($status);
    my $san_message = sanitize_for_log($message);
    my $raw_ua = $cgi->user_agent() || '';
    my $san_ua = sanitize_for_log(substr($raw_ua, 0, 255));
    my $method = sanitize_for_log($cgi->request_method() || 'unknown');
    warn "$remote_ip [ERROR] method=$method, status=$san_status, message=$san_message, ua=$san_ua\n";
    # SECURITY: Sanitize status to prevent header injection
    $status =~ s/[\r\n]//g;
    print $cgi->header(%sec_headers, -status => $status);
    my $esc_message = $cgi->escapeHTML($message);
    my $esc_status = $cgi->escapeHTML($status);
    my $meta_csp = $cgi->escapeHTML(get_meta_csp());
    print <<EOF;
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="robots" content="noindex, nofollow">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="Content-Security-Policy" content="$meta_csp">
    <title>Error: $esc_status</title>
</head>
<body>
    <h1>Error: $esc_status</h1>
    <p>$esc_message</p>
</body>
</html>
EOF
    exit;
}

sub parse_config_file {
    my ($path) = @_;
    my %config;
    return %config unless defined $path;
    $path = File::Spec->rel2abs($path);
    # SECURITY: Ensure it's a regular file and not excessively large (max 64KB) to prevent DoS.
    return %config unless -f $path && -s $path < 65536;
    sysopen(my $fh, $path, O_RDONLY | (defined &O_NOFOLLOW ? O_NOFOLLOW : 0)) or do {
        my $san_path = sanitize_for_log($path);
        my $san_error = sanitize_for_log($!);
        warn "$remote_ip [ERROR] Could not read config file $san_path: $san_error\n";
        return %config;
    };
    while (<$fh>) {
        next if /\0/; # SECURITY: Reject lines containing null bytes
        s/#.*//;
        s/^\s+|\s+$//g;
        next unless length;
        my ($key, $value) = split /=/, $_, 2;
        next unless defined $value;
        $config{trim($key)} = trim($value);
    }
    close $fh;
    return %config;
}

sub load_security_headers {
    my ($config_value) = @_;
    # Default headers use lowercase keys to match normalization
    my %headers = (
        -type                        => 'text/html',
        -charset                     => 'utf-8',
        -x_frame_options             => 'DENY',
        -x_content_type_options      => 'nosniff',
        -x_xss_protection            => '0',
        -content_security_policy     => "upgrade-insecure-requests; default-src 'self'; script-src 'none'; connect-src 'none'; form-action 'self'; style-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; media-src 'none'; worker-src 'none';",
        -strict_transport_security   => 'max-age=31536000; includeSubDomains; preload',
        -referrer_policy             => 'no-referrer',
        -x_permitted_cross_domain_policies => 'none',
        -permissions_policy          => 'accelerometer=(), ambient-light-sensor=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), usb=(), web-share=(), interest-cohort=(), attribution-reporting=(), browsing-topics=(), join-ad-interest=(), run-ad-auction=()',
        -x_download_options          => 'noopen',
        -cross_origin_resource_policy => 'same-origin',
        -cross_origin_opener_policy  => 'same-origin',
        -cross_origin_embedder_policy => 'require-corp',
        -cache_control               => 'no-store, no-cache, must-revalidate, max-age=0',
        -x_robots_tag                => 'noindex, nofollow',
    );
    return %headers unless defined $config_value && length $config_value;

    # SECURITY: Whitelist of recognized security headers to distinguish between
    # a new HTTP header and a continuation of a multi-part value (like CSP).
    my %recognized_headers = map { $_ => 1 } (
        'x_frame_options', 'x_content_type_options', 'x_xss_protection',
        'content_security_policy', 'strict_transport_security', 'referrer_policy',
        'x_permitted_cross_domain_policies', 'permissions_policy', 'x_download_options',
        'cross_origin_resource_policy', 'cross_origin_opener_policy',
        'cross_origin_embedder_policy', 'cache_control', 'content_type', 'charset', 'type',
        'x_robots_tag'
    );

    # Headers that are known to contain multiple parts or colons in their directives.
    # For these headers, we are more lenient and allow subsequent entries to be appended.
    my %multi_part_headers = (
        '-content_security_policy'   => 1,
        '-permissions_policy'        => 1,
        '-x_robots_tag'              => 1,
        '-strict_transport_security' => 1,
        '-x_xss_protection'          => 1,
        '-cache_control'             => 1,
        '-type'                      => 1,
    );

    my $last_key;
    for my $entry (split /\s*;\s*/, $config_value) {
        next unless length $entry;
        $entry =~ s/[\r\n]//g; # SECURITY: Prevent header injection

        # Check if entry starts with a header name (key: value)
        if ($entry =~ /^\s*([\w\-]+)\s*:(.*)$/) {
            my ($name, $value) = ($1, $2);
            $name = trim($name);
            $value = trim($value);

            # Normalize for lookup
            my $norm_name = lc($name);
            $norm_name =~ s/-/_/g;

            if ($recognized_headers{$norm_name}) {
                # SECURITY: Normalize header names for CGI.pm
                my $cgi_key = "-$norm_name";
                $cgi_key = "-type" if $norm_name eq 'content_type';
                $cgi_key = "-charset" if $norm_name eq 'charset';
                $last_key = $cgi_key;
                $headers{$last_key} = $value;
                next;
            }
            # SECURITY: If it looks like a header but is not recognized, only append to last_key
            # if the current header is known to contain colons in its directives.
            if (defined $last_key && $multi_part_headers{$last_key}) {
                $headers{$last_key} .= "; $entry";
                next;
            }
            # Otherwise, stop appending to the previous header to prevent potential bypasses.
            undef $last_key;
            next;
        }
        # Otherwise append to the last header (e.g. CSP parts containing semicolons but no colons)
        # only if the last header is recognized as multi-part.
        if (defined $last_key && $multi_part_headers{$last_key}) {
            $headers{$last_key} .= "; $entry";
        } else {
            undef $last_key;
        }
    }
    return %headers;
}

# SECURITY: Helper to generate CSP for meta tags (strips frame-ancestors)
sub get_meta_csp {
    my $csp = $sec_headers{'-content_security_policy'} || '';
    my @parts = split /\s*;\s*/, $csp;
    my @meta_parts = grep { !/^frame-ancestors\b/i } @parts;
    return join('; ', @meta_parts);
}

sub compile_extension_regex {
    my @patterns = @_;
    my @parts;
    for my $pattern (@patterns) {
        next unless defined $pattern;
        $pattern = trim($pattern);
        next unless length $pattern;
        if ($pattern =~ /[\\\^\$\.\|\?\*\+\(\)\[\]\{\}]/) {
            push @parts, $pattern;
        } else {
            push @parts, quotemeta($pattern);
        }
    }
    return qr/\.(?:@{[ join '|', @parts ] })(?:\.|\z)/i;
}

# SECURITY: Initialize security headers with defaults
%sec_headers = load_security_headers();

my %config = parse_config_file($ENV{UPLOAD_CONFIG_FILE} || File::Spec->catfile($Bin, 'upload.conf'));

# Update security headers if overrides exist in config or environment
%sec_headers = load_security_headers($ENV{UPLOAD_SECURITY_HEADERS} || $config{UPLOAD_SECURITY_HEADERS});

# SECURITY: Limit upload size to prevent DoS; configurable via environment or config file
# Must be set BEFORE creating the CGI object.
$CGI::POST_MAX = $ENV{CGI_POST_MAX_TEST} || $ENV{UPLOAD_MAX_SIZE} || $config{UPLOAD_MAX_SIZE} || (1024 * 1024 * 100);
# SECURITY: Limit parameters and multipart records to prevent DoS; configurable via environment or config file
$CGI::MAX_PARAMS = $ENV{UPLOAD_MAX_PARAMS} || $config{UPLOAD_MAX_PARAMS} || 10;
$CGI::MAX_MULTIPART_RECORDS = $ENV{UPLOAD_MAX_MULTIPART_RECORDS} || $config{UPLOAD_MAX_MULTIPART_RECORDS} || 100;
# SECURITY: Enable warnings for list context in param() to prevent vulnerabilities
$CGI::LIST_CONTEXT_WARN = 1;

$cgi = new CGI;

# SECURITY: Enforce POST method to prevent accidental script triggering and information disclosure.
if (($cgi->request_method() || '') ne 'POST') {
    send_error("405 Method Not Allowed", "This script only accepts POST requests.");
}

# SECURITY: Enforce multipart/form-data content type for file uploads.
if (($cgi->content_type() || '') !~ m|^multipart/form-data|i) {
    send_error("400 Bad Request", "Invalid Content-Type. Expected multipart/form-data.");
}

# $base_dir is an actual path on your local file system that's accessible to the html server
my $base_dir = $ENV{UPLOAD_BASE_DIR} || $config{UPLOAD_BASE_DIR} || "/var/www/html/files";
# $base_url is the URL that you would use to access $base_dir from a web browser
my $base_url = $ENV{UPLOAD_BASE_URL} || $config{UPLOAD_BASE_URL} || "http://server/files";

# SECURITY: Basic validation for base_url and base_dir. Fail early if misconfigured.
if (!$base_dir || $base_dir !~ m|^/|) {
    send_error("500 Internal Server Error", "Invalid UPLOAD_BASE_DIR configuration");
}
if (!$base_url || $base_url !~ m!^(?:https?://|/)!) {
    send_error("500 Internal Server Error", "Invalid UPLOAD_BASE_URL configuration");
}

my %allowed_dirs = map { $_ => 1 } grep { length } map { trim($_) } split /,/, ($ENV{UPLOAD_ALLOWED_DIRS} || $config{UPLOAD_ALLOWED_DIRS} || 'incoming');

my @default_forbidden_extensions = (
    'pl','cgi','php\d*','phps','pht','phar','py','pyw','pyc','pyo','sh','bash','zsh',
    'rb','rbw','lua','tcl','exe','bat','cmd','cpl','iso','ins','isp','job','inf','scf',
    'html?','js','mjs','shtml','phtml','phtm','svg','svgz','asp[x]?','jspx?','asmx','ashx','svc',
    'vbs','ps\d+(?:xml)?','psm1','psd1','wasm','xhtml','conf','config','jar','war','ear','swf','hta',
    'scr','com','msi','vbe','jse','wsf','wsh','lnk','reg','jnlp','pif','desktop','url','application',
    'gadget','msu','msp','docm','dotm','xlsm','xltm','pptm','potm','ppsm','xml','cjs','mhtml','mht',
    'rdp','vmdk','ova','ovf',
    'vba','hlp','chm','ade','adp','mde','msc','mst','sct','shb','shs','wsc','asax','ascx','master',
    'skin','browser','compiled','cfm','cfc','cfml','psc1','psc2','shtm','stm','pyd','class','java',
    'dll','so','dylib','cab','vxd','sys','fish','docb','xlam','sldm','phpt','env','htaccess','htpasswd',
    'inc','module','command','tool','keychain','ini','log','sql','sqlite','db','yaml','yml','properties',
    'jspa','do','action','cshtml','vbhtml','pm','plx','perl','ksh','csh','tcsh','jsonp','ws',
    'bak','old','temp','tmp','json','dmg','pkg','deb','rpm','ace','apk','appref-ms','appx',
    'diagcab','vhd','vhdx','appcontent-ms','settingcontent-ms','webpnp','website','xbap',
    'xll','xnk','asa','key','pem','crt','cer','p12','pfx','der','p7b','p7c',
    'axd','xsd','xsl','htgroup','vb','xap','manifest','ts','tsx','jsx','sln','csproj',
    'vbproj','plist','axml','pub','ipa','msix(?:bundle)?','appxbundle','crx','xpi',
    'snap','flatpak','appimage','application-xml','oxt','scpt','scptd','applescript',
    'prefPane','workflow','terminal'
);
my @forbidden_extensions = split /,/, ($ENV{UPLOAD_FORBIDDEN_EXTENSIONS} || $config{UPLOAD_FORBIDDEN_EXTENSIONS} || join(',', @default_forbidden_extensions));
my $forbidden_ext_re = compile_extension_regex(@forbidden_extensions);

# SECURITY: Handle upload errors (like exceeding POST_MAX)
if (my $error = $cgi->cgi_error) {
    send_error($error, "The uploaded file is too large or another error occurred.");
}

my $dir = $cgi->param('dir') || 'incoming';
# SECURITY: Harden dir parameter with length limit and character whitelist for defense-in-depth.
if ($dir !~ /^[a-zA-Z0-9_\-]{1,64}$/) {
    send_error("400 Bad Request", "Invalid directory format");
}
# SECURITY: Strict whitelist for directory to prevent path traversal
if (!exists $allowed_dirs{$dir}) {
    send_error("403 Forbidden", "Invalid or unauthorized directory");
}
my $target_dir = File::Spec->catdir($base_dir, $dir);
# SECURITY: Ensure it's a directory and NOT a symlink to prevent traversal or redirection attacks.
if (! -d $target_dir || -l $target_dir) {
    send_error("500 Internal Server Error", "Internal server error");
}

my $file = $cgi->param('file');
my $upload_fh = $cgi->upload('file');
my $filename;

# use user_agent to figure out the submitting OS, use basename accordingly
my $user_agent = $cgi->user_agent || '';
if ($user_agent =~ /Linux/i) {
  # don't need to do anything, use defaults
} elsif ($user_agent =~ /Macintosh/i) {
  fileparse_set_fstype("MacOS");
} else {
  fileparse_set_fstype("MSWin32");
}
$filename = basename($file || '');

# SECURITY: Filename sanitization - whitelist alphanumeric, dot, underscore, dash.
# Disallow filenames starting with a dot or dash to prevent hidden files and option injection.
# Limit filename length to 255 characters.
if ($filename !~ /^[a-zA-Z0-9_][a-zA-Z0-9_\-\.]{0,254}$/) {
    send_error("400 Bad Request", "Invalid filename");
}

# SECURITY: Prevent Windows reserved filenames (e.g., CON, PRN, AUX, NUL, COM1-9, LPT1-9).
if ($filename =~ /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/i) {
    send_error("400 Bad Request", "Reserved filename");
}

# SECURITY: Extension blacklist to prevent RCE and Stored XSS.
# Checks for forbidden extensions anywhere in the filename (e.g., .php.txt).
if ($filename =~ $forbidden_ext_re) {
    send_error("403 Forbidden", "Forbidden file extension");
}

# SECURITY: Limit the number of files in the target directory to prevent DoS (Disk Exhaustion).
# Only enforced for new file uploads; overwriting existing files is permitted.
my $max_files = $ENV{UPLOAD_MAX_FILES} || $config{UPLOAD_MAX_FILES} || 1000;
my $upload_path = File::Spec->catfile($target_dir, $filename);
if (! -e $upload_path) {
    opendir(my $dh, $target_dir) or do {
        my $san_target_dir = sanitize_for_log($target_dir);
        my $san_error = sanitize_for_log($!);
        warn "$remote_ip [ERROR] opendir failed for $san_target_dir: $san_error\n";
        send_error("500 Internal Server Error", "Internal server error");
    };
    my $file_count = 0;
    while (my $entry = readdir($dh)) {
        if (-f File::Spec->catfile($target_dir, $entry)) {
            $file_count++;
        }
        last if $file_count >= $max_files;
    }
    closedir($dh);
    if ($file_count >= $max_files) {
        send_error("507 Insufficient Storage", "Maximum file limit reached for this directory.");
    }
}

# SECURITY: Verify filehandle before reading
if (!defined $upload_fh) {
    send_error("400 Bad Request", "No file uploaded or filehandle is invalid");
}
# SECURITY: Ensure the input filehandle is in binary mode
binmode $upload_fh;

# SECURITY: 3-arg open and restricted permissions
# $upload_path is already constructed above for the file count check.
# SECURITY: Use sysopen with O_CREAT | O_TRUNC | O_NOFOLLOW to prevent symlink attacks while allowing secure overwrites.
my $flags = O_WRONLY | O_CREAT | O_TRUNC;
$flags |= O_NOFOLLOW if defined &O_NOFOLLOW;
sysopen (my $local_fh, $upload_path, $flags, 0644) or do {
    my $san_upload_path = sanitize_for_log($upload_path);
    my $san_error = sanitize_for_log($!);
    warn "$remote_ip [ERROR] sysopen failed for $san_upload_path: $san_error\n";
    send_error("500 Internal Server Error", "Upload failed: Internal server error");
};
# SECURITY: Explicitly chmod to ensure strict permissions (0644) even if overwriting an existing file with loose permissions.
# This is fatal because failing to enforce permissions in a shared directory is a security risk.
chmod(0644, $local_fh) or do {
    my $san_upload_path = sanitize_for_log($upload_path);
    my $san_error = sanitize_for_log($!);
    warn "$remote_ip [ERROR] chmod failed for $san_upload_path: $san_error\n";
    close $local_fh;
    unlink $upload_path;
    send_error("500 Internal Server Error", "Internal server error");
};
binmode $local_fh;
my $sha = Digest::SHA->new(256);
my $buffer;
my $bytes_read;
my $filesize = 0;
while ($bytes_read = read($upload_fh, $buffer, 4096)) {
    $filesize += $bytes_read;
    $sha->add($buffer);
    if (!print $local_fh $buffer) {
        my $san_upload_path = sanitize_for_log($upload_path);
        my $san_error = sanitize_for_log($!);
        warn "$remote_ip [ERROR] write failed for $san_upload_path: $san_error\n";
        close $local_fh;
        unlink $upload_path;
        send_error("500 Internal Server Error", "Internal server error");
    }
}
# Check if read finished because of EOF or error
if (!defined $bytes_read && $!) {
    my $san_error = sanitize_for_log($!);
    warn "$remote_ip [ERROR] read failed from upload filehandle: $san_error\n";
    close $local_fh;
    unlink $upload_path;
    send_error("500 Internal Server Error", "Internal server error");
}
if (!close $local_fh) {
    my $san_upload_path = sanitize_for_log($upload_path);
    my $san_error = sanitize_for_log($!);
    warn "$remote_ip [ERROR] close failed for $san_upload_path: $san_error\n";
    unlink $upload_path;
    send_error("500 Internal Server Error", "Internal server error");
}

my $digest = $sha->hexdigest;

# SECURITY: Audit log the upload event
my $san_filename = sanitize_for_log($filename);
my $san_dir = sanitize_for_log($dir);
my $raw_ua = $cgi->user_agent() || '';
my $san_ua = sanitize_for_log(substr($raw_ua, 0, 255));
my $method = sanitize_for_log($cgi->request_method() || 'unknown');
warn "$remote_ip [AUDIT] File uploaded: method=$method, filename=$san_filename, dir=$san_dir, size=$filesize, digest=$digest, ua=$san_ua\n";
my $url = "$base_url/" . CGI::escape($dir) . "/" . CGI::escape($filename);

# Output success page with security headers
# SECURITY: Escape reflected output to prevent XSS. Use the sanitized filename.
my $esc_filename = $cgi->escapeHTML($filename);
my $esc_url = $cgi->escapeHTML($url);
my $esc_upload_url = $cgi->escapeHTML("$base_url/upload.html");
my $esc_digest = $cgi->escapeHTML($digest);
my $meta_csp = $cgi->escapeHTML(get_meta_csp());
print $cgi->header(%sec_headers);
print <<EOF;
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="robots" content="noindex, nofollow">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="Content-Security-Policy" content="$meta_csp">
    <title>Upload Successful</title>
</head>
<body>
<p><b>$esc_filename ($filesize bytes)</b> has been successfully uploaded...</p>
<p>SHA-256: <code>$esc_digest</code></p>
<p>The publicly accessible link to this file is:<br>
<a href="$esc_url" rel="noopener noreferrer">$esc_url</a></p>
<p>Go back to <a href="$esc_upload_url" rel="noopener noreferrer">upload another file</a></p>
</body>
</html>
EOF
