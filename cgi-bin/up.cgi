#!/usr/bin/perl
use strict;
use warnings;

my $debug = 0;
use File::Basename qw(basename fileparse_set_fstype);
use File::Spec;
use Fcntl qw(:DEFAULT O_NOFOLLOW);
use CGI;

# SECURITY: Modern security headers hash to ensure consistency
my %sec_headers = (
    -type                        => 'text/html',
    -charset                     => 'utf-8',
    -X_Frame_Options             => 'DENY',
    -X_Content_Type_Options      => 'nosniff',
    -Content_Security_Policy     => "default-src 'self'; script-src 'none'; style-src 'none'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';",
    -Strict_Transport_Security   => 'max-age=31536000; includeSubDomains',
    -Referrer_Policy             => 'no-referrer',
    -X_Permitted_Cross_Domain_Policies => 'none',
    -Permissions_Policy          => 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
);

# SECURITY: Centralized error handling
sub send_error {
    my ($cgi, $status, $message) = @_;
    print $cgi->header(%sec_headers, -status => $status);
    my $esc_message = $cgi->escapeHTML($message);
    print "<html><body><h1>Error: $status</h1><p>$esc_message</p></body></html>";
    exit;
}

# $base_dir is an actual path on your local file system that's accessible to the html server
my $base_dir = $ENV{UPLOAD_BASE_DIR} || "/var/www/html/files";
# $base_url is the URL that you would use to access $base_dir from a web browser
my $base_url = "http://server/files";

# SECURITY: Limit upload size to 100MB to prevent DoS
$CGI::POST_MAX = $ENV{CGI_POST_MAX_TEST} || (1024 * 1024 * 100);

my $cgi = new CGI;

# SECURITY: Handle upload errors (like exceeding POST_MAX)
if (my $error = $cgi->cgi_error) {
    send_error($cgi, $error, "The uploaded file is too large or another error occurred.");
}

my $dir = $cgi->param('dir') || 'incoming';
# SECURITY: Strict whitelist for directory to prevent path traversal
my %allowed_dirs = ( 'incoming' => 1 );
if (!exists $allowed_dirs{$dir}) {
    send_error($cgi, "403 Forbidden", "Invalid or unauthorized directory");
}
if (! -d File::Spec->catdir($base_dir, $dir)) {
    send_error($cgi, "500 Internal Server Error", "Target directory does not exist");
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
    send_error($cgi, "400 Bad Request", "Invalid filename");
}

# SECURITY: Extension blacklist to prevent RCE and Stored XSS.
# Checks for forbidden extensions anywhere in the filename (e.g., .php.txt).
if ($filename =~ /\.(?:pl|cgi|php\d*|phps|pht|phar|py|sh|exe|bat|cmd|html?|js|shtml|phtml|svg|asp[x]?|jspx?|vbs|ps1|wasm|conf|config)(?:\.|\z)/i) {
    send_error($cgi, "403 Forbidden", "Forbidden file extension");
}

# SECURITY: Verify filehandle before reading
if (!defined $upload_fh) {
    send_error($cgi, "400 Bad Request", "No file uploaded or filehandle is invalid");
}

# SECURITY: 3-arg open and restricted permissions
my $upload_path = File::Spec->catfile($base_dir, $dir, $filename);

# SECURITY: Use sysopen with O_CREAT | O_TRUNC | O_NOFOLLOW to prevent symlink attacks
# while allowing secure overwriting of existing files.
my $flags = O_WRONLY | O_CREAT | O_TRUNC;
$flags |= O_NOFOLLOW if defined &O_NOFOLLOW;
sysopen (my $local_fh, $upload_path, $flags, 0644) or send_error($cgi, "500 Internal Server Error", "Upload failed: Internal server error");
binmode $local_fh;
my $buffer;
while (read($upload_fh, $buffer, 4096)) {
    print $local_fh $buffer or send_error($cgi, "500 Internal Server Error", "Write failed");
}
close $local_fh or send_error($cgi, "500 Internal Server Error", "Failed to finalize upload");
chmod 0644, $upload_path;

my $filesize = (stat($upload_path))[7] || 0;
my $url = "$base_url/$dir/" . CGI::escape($filename);

# Output success page with security headers
print $cgi->header(%sec_headers);
# SECURITY: Escape reflected output to prevent XSS. Use the sanitized filename.
my $esc_filename = $cgi->escapeHTML($filename);
my $esc_url = $cgi->escapeHTML($url);
print "<html><body>";
print "<p><b>$esc_filename ($filesize bytes)</b> has been successfully uploaded...\n";
print "<p>The publicly accessible link to this file is:<br>\n";
print "<a href=\"$esc_url\">$esc_url</a><p>\n";
print "Go back to <a href=\"" . $cgi->escapeHTML("$base_url/upload.html") . "\">upload another file</a>\n";
print "</body></html>";
