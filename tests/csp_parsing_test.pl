#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;

my $cgi_script = File::Spec->catfile('cgi-bin', 'up.cgi');

print "Running CSP parsing and header normalization tests...\n";

# Minimal multipart body for tests
my $boundary = "TestBoundary";
my $dummy_post = "--$boundary\r\nContent-Disposition: form-data; name=\"foo\"\r\n\r\nbar\r\n--$boundary--\r\n";
my $dummy_len = length($dummy_post);

# Test 1: CSP parsing with semicolons and colons
{
    my $csp = "default-src 'self'; connect-src https://example.com; script-src 'none'";
    print "Testing CSP with semicolons and colons...\n";
    my $env = "PERL5LIB=extlib/lib/perl5 UPLOAD_SECURITY_HEADERS=\"Content-Security-Policy: $csp\" REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$dummy_len";
    my $output = `echo "$dummy_post" | $env perl $cgi_script 2>&1`;

    my @csp_headers = ($output =~ /^Content-Security-Policy: (.*)$/img);
    if (scalar @csp_headers == 1) {
        my $got = $csp_headers[0];
        $got =~ s/\r//g;
        if ($got eq $csp) {
            print "[PASS] CSP with semicolons and colons correctly parsed.\n";
        } else {
            print "[FAIL] CSP value mismatch.\n";
            print "       Expected: $csp\n";
            print "       Got:      $got\n";
        }
    } else {
        print "[FAIL] Expected 1 CSP header, found " . scalar(@csp_headers) . "\n";
    }
}

# Test 2: Header normalization (case and dash/underscore)
{
    print "\nTesting header normalization and duplicate prevention...\n";
    # We provide multiple variants of X-Frame-Options
    my $headers = "X-Frame-Options: SAMEORIGIN; x_frame_options: SAMEORIGIN; X_FRAME_OPTIONS: SAMEORIGIN";
    my $env = "PERL5LIB=extlib/lib/perl5 UPLOAD_SECURITY_HEADERS=\"$headers\" REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$dummy_len";
    my $output = `echo "$dummy_post" | $env perl $cgi_script 2>&1`;

    my @xfo_headers = ($output =~ /^X-Frame-Options: (.*)$/img);
    print "Found " . scalar(@xfo_headers) . " X-Frame-Options header(s).\n";

    if (scalar @xfo_headers == 1 && $xfo_headers[0] =~ /SAMEORIGIN/i) {
        print "[PASS] Header variants correctly normalized to a single header.\n";
    } else {
        print "[FAIL] Multiple headers or incorrect value found.\n";
        foreach my $h (@xfo_headers) {
            $h =~ s/\r//g;
            print "       Found: $h\n";
        }
    }
}

# Test 3: Unknown headers should be ignored or appended
{
    print "\nTesting unknown headers (should be ignored as keys)...\n";
    my $headers = "X-Frame-Options: DENY; Unknown-Header: Value";
    my $env = "PERL5LIB=extlib/lib/perl5 UPLOAD_SECURITY_HEADERS=\"$headers\" REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$dummy_len";
    my $output = `echo "$dummy_post" | $env perl $cgi_script 2>&1`;

    if ($output =~ /^Unknown-Header:/im) {
        print "[FAIL] Unknown-Header was incorrectly parsed as a header.\n";
    } else {
        print "[PASS] Unknown-Header was correctly ignored as a key.\n";
    }

    if ($output =~ /^X-Frame-Options: DENY\r?$/im && $output !~ /Unknown-Header: Value/i) {
        print "[PASS] Unknown-Header was correctly NOT appended to preceding recognized header.\n";
    } else {
        print "[FAIL] Unknown-Header was incorrectly appended or found in output.\n";
    }
}
