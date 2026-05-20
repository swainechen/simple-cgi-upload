#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;

my $cgi_script = File::Spec->catfile('cgi-bin', 'up.cgi');

# Test 1: Underscore notation override
{
    print "Testing with underscore override (UPLOAD_SECURITY_HEADERS='X_Frame_Options:SAMEORIGIN')...\n";
    # We use a non-POST request to trigger an error early but still get headers from send_error
    my $env = "PERL5LIB=extlib/lib/perl5 UPLOAD_SECURITY_HEADERS='X_Frame_Options:SAMEORIGIN' REQUEST_METHOD=GET";
    my $output = `$env perl $cgi_script 2>&1`;

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
    my $env = "PERL5LIB=extlib/lib/perl5 UPLOAD_SECURITY_HEADERS='X-Frame-Options:SAMEORIGIN' REQUEST_METHOD=GET";
    my $output = `$env perl $cgi_script 2>&1`;

    my @xfo_headers = ($output =~ /^X-Frame-Options: (.*)$/img);
    print "Found X-Frame-Options: " . join(", ", @xfo_headers) . "\n";

    if (scalar @xfo_headers == 1 && $xfo_headers[0] =~ /SAMEORIGIN/i) {
        print "[PASS] Dash override was correctly normalized and no duplicates found.\n";
    } else {
        print "[FAIL] Dash override failed normalization or duplicates found.\n";
    }
}
