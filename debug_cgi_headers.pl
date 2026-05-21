use strict;
use warnings;
use CGI;

my $cgi = new CGI('');
my %headers = (
    '-x_frame_options' => 'DENY',
);

print "--- Resulting headers ---\n";
my $h = $cgi->header(%headers);
$h =~ s/\n/[N]\n/g;
$h =~ s/\r/[R]/g;
print $h;
