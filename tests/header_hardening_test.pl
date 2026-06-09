#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
my $cgi_script = File::Spec->catfile('cgi-bin', 'up.cgi');
my $boundary = "TestBoundary";
my $dummy_post = "--$boundary\r\nContent-Disposition: form-data; name=\"foo\"\r\n\r\nbar\r\n--$boundary--\r\n";
my $dummy_len = length($dummy_post);
my %tests = (
    "X-Frame-Options: DENY; mal" => qr/^X-Frame-Options: DENY\r?$/im,
    "Strict-Transport-Security: max-age=1; inc" => qr/^Strict-Transport-Security: max-age=1; inc\r?$/im,
);
while (my ($h, $re) = each %tests) {
    my $env = "PERL5LIB=extlib/lib/perl5 UPLOAD_SECURITY_HEADERS=\"$h\" REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$dummy_len";
    my $output = `echo "$dummy_post" | $env perl $cgi_script 2>&1`;
    $output =~ $re or die "Test failed for $h. Got: $output";
}
print "Header hardening tests passed\n";
