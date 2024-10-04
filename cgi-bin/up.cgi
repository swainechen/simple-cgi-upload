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
my $dir = $cgi->param('dir');
my $file = $cgi->param('file');
my $filename;

# use user_agent to figure out the submitting OS, use basename accordingly
my $user_agent = $cgi->user_agent;
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
$debug && print "Full path = $base_dir/$dir/$filename<p>";

open (LOCAL, ">$base_dir/$dir/$filename") or die $|;
while (read($file, $buffer, 4096)) {
  print LOCAL $buffer;
}
close LOCAL;
chmod 0666, "$base_dir/$dir/$filename";
my $filesize = (stat("$base_dir/$dir/$filename"))[7];
my $url = "$base_url/$dir/" . CGI::escape($filename);
print "<p><b>$file ($filesize bytes)</b> has been successfully uploaded...\n";
print "<p>The publicly accessible link to this file is:<br>\n";
print "<a href=\"$url\">$url</a><p>\n";
print "Go back to <a href=\"$base_url/upload.html\">upload another file</a>\n";
