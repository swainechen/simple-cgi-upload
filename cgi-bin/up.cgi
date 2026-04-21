#!/usr/bin/perl
use strict;
use warnings;

my $debug = 0;
use File::Basename qw(basename fileparse_set_fstype);
use File::Spec;
# $base_dir is an actual path on your local file system that's accessible to the html server
my $base_dir = $ENV{UPLOAD_BASE_DIR} || "/var/www/html/files";
# $base_url is the URL that you would use to access $base_dir from a web browser
my $base_url = "http://server/files";
use CGI;

# SECURITY: Limit upload size to 100MB to prevent DoS
$CGI::POST_MAX = $ENV{CGI_POST_MAX_TEST} || (1024 * 1024 * 100);

my $cgi = new CGI;

# SECURITY: Handle upload errors (like exceeding POST_MAX)
if (my $error = $cgi->cgi_error) {
    my $esc_error = $cgi->escapeHTML($error);
    print $cgi->header(-status => $error);
    print "<html><body><h1>$esc_error</h1><p>The uploaded file is too large or another error occurred.</p></body></html>";
    exit;
}

# SECURITY: Modern security headers
print $cgi->header(
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

my $dir = $cgi->param('dir') || 'incoming';
# SECURITY: Strict whitelist for directory to prevent path traversal
my %allowed_dirs = ( 'incoming' => 1 );
if (!exists $allowed_dirs{$dir}) { die "Invalid or unauthorized directory\n"; }
if (! -d File::Spec->catdir($base_dir, $dir)) { die "Target directory does not exist\n"; }

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
    die "Invalid filename\n";
}

# SECURITY: Extension blacklist to prevent RCE and Stored XSS.
# Checks for forbidden extensions anywhere in the filename (e.g., .php.txt).
if ($filename =~ /\.(?:pl|cgi|php\d*|phps|pht|phar|py|sh|exe|bat|cmd|html?|js|shtml|phtml|svg|asp[x]?|jspx?)(?:\.|\z)/i) {
    die "Forbidden file extension\n";
}

$debug && print "Input filename = $file<p>";
$debug && print "Parsed filename = $filename<p>";
$debug && print "Full path = " . $cgi->escapeHTML("$base_dir/$dir/$filename") . "<p>";

# SECURITY: 3-arg open and restricted permissions
my $upload_path = File::Spec->catfile($base_dir, $dir, $filename);
if (!defined $upload_fh) {
    die "No file uploaded or filehandle is invalid\n";
}
# SECURITY: Generic error message to prevent path leakage
open (my $local_fh, '>', $upload_path) or die "Upload failed: Internal server error\n";
binmode $local_fh;
my $buffer;
while (read($upload_fh, $buffer, 4096)) {
  print $local_fh $buffer;
}
close $local_fh;
chmod 0644, $upload_path;
my $filesize = (stat($upload_path))[7] || 0;
my $url = "$base_url/$dir/" . CGI::escape($filename);
# SECURITY: Escape reflected output to prevent XSS. Use the sanitized filename.
my $esc_filename = $cgi->escapeHTML($filename);
my $esc_url = $cgi->escapeHTML($url);
print "<p><b>$esc_filename ($filesize bytes)</b> has been successfully uploaded...\n";
print "<p>The publicly accessible link to this file is:<br>\n";
print "<a href=\"$esc_url\">$esc_url</a><p>\n";
print "Go back to <a href=\"" . $cgi->escapeHTML("$base_url/upload.html") . "\">upload another file</a>\n";
