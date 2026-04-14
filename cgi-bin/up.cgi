#!/usr/bin/perl -w
$debug = 0;
use File::Basename;
# $base_dir is an actual path on your local file system that's accessible to the html server
$base_dir = "/var/www/html/files";
# $base_url is the URL that you would use to access $base_dir from a web browser
$base_url = "http://server/files";
use CGI;

my $cgi = new CGI;
print $cgi->header();
my $dir = $cgi->param('dir') || 'incoming';
# SECURITY: Whitelist directory to prevent path traversal
if ($dir !~ /^[a-zA-Z0-9_\-]+$/) { die "Invalid directory"; }
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
$filename = basename($file);

$debug && print "Input filename = $file<p>";
$debug && print "Parsed filename = $filename<p>";
$debug && print "Full path = " . $cgi->escapeHTML("$base_dir/$dir/$filename") . "<p>";

# SECURITY: 3-arg open and restricted permissions
my $upload_path = "$base_dir/$dir/$filename";
open (my $local_fh, '>', $upload_path) or die "Upload failed: $!";
binmode $local_fh;
while (read($upload_fh, $buffer, 4096)) {
  print $local_fh $buffer;
}
close $local_fh;
chmod 0644, $upload_path;
my $filesize = (stat($upload_path))[7] || 0;
my $url = "$base_url/$dir/" . CGI::escape($filename);
# SECURITY: Escape reflected output to prevent XSS
my $esc_file = $cgi->escapeHTML($file);
my $esc_url = $cgi->escapeHTML($url);
print "<p><b>$esc_file ($filesize bytes)</b> has been successfully uploaded...\n";
print "<p>The publicly accessible link to this file is:<br>\n";
print "<a href=\"$esc_url\">$esc_url</a><p>\n";
print "Go back to <a href=\"" . $cgi->escapeHTML("$base_url/upload.html") . "\">upload another file</a>\n";
