#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;

my $cgi_script = File::Spec->catfile('cgi-bin', 'up.cgi');

# Minimal multipart body for tests
my $boundary = "TestBoundary";
my $dummy_post = "--$boundary\r\nContent-Disposition: form-data; name=\"foo\"\r\n\r\nbar\r\n--$boundary--\r\n";
my $dummy_len = length($dummy_post);

# Test 1: Underscore notation override
{
    print "Testing with underscore override (UPLOAD_SECURITY_HEADERS='X_Frame_Options:SAMEORIGIN')...\n";
    # We use POST and multipart to satisfy the new security checks
    my $env = "PERL5LIB=extlib/lib/perl5 UPLOAD_SECURITY_HEADERS='X_Frame_Options:SAMEORIGIN' REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$dummy_len";
    my $output = `echo "$dummy_post" | $env perl $cgi_script 2>&1`;

    my @xfo_headers = ($output =~ /^X-Frame-Options: (.*)$/img);
    print "Found X-Frame-Options: " . join(", ", @xfo_headers) . "\n";

    if (scalar @xfo_headers == 1 && $xfo_headers[0] =~ /SAMEORIGIN/i) {
        print "[PASS] Underscore override worked and no duplicates found.\n";
    } else {
        print "[FAIL] Underscore override failed or duplicates found.\n";
    }
}

# Test 2: Dash notation override (The fix we're testing)
{
    print "\nTesting with dash override (UPLOAD_SECURITY_HEADERS='X-Frame-Options:SAMEORIGIN')...\n";
    my $env = "PERL5LIB=extlib/lib/perl5 UPLOAD_SECURITY_HEADERS='X-Frame-Options:SAMEORIGIN' REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$dummy_len";
    my $output = `echo "$dummy_post" | $env perl $cgi_script 2>&1`;

    my @xfo_headers = ($output =~ /^X-Frame-Options: (.*)$/img);
    print "Found X-Frame-Options: " . join(", ", @xfo_headers) . "\n";

    if (scalar @xfo_headers == 1 && $xfo_headers[0] =~ /SAMEORIGIN/i) {
        print "[PASS] Dash override was correctly normalized and no duplicates found.\n";
    } else {
        print "[FAIL] Dash override failed normalization or duplicates found.\n";
    }
}
