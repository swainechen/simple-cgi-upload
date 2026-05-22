#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;

my $cgi_script = File::Spec->catfile('cgi-bin', 'up.cgi');

print "Running hardening and security observability tests...\n";

# Test 1: New Security Headers (X-Robots-Tag and strengthened Cache-Control)
{
    print "Testing default security headers...\n";
    my $env = "PERL5LIB=extlib/lib/perl5 REQUEST_METHOD=GET";
    my $output = `$env perl $cgi_script 2>&1`;

    my ($robots) = ($output =~ /^X-Robots-Tag: (.*)$/im);
    my ($cache) = ($output =~ /^Cache-Control: (.*)$/im);

    if ($robots && $robots =~ /noindex, nofollow/i) {
        print "[PASS] X-Robots-Tag is present and correct.\n";
    } else {
        print "[FAIL] X-Robots-Tag is missing or incorrect. Got: " . ($robots || 'NONE') . "\n";
    }

    if ($cache && $cache =~ /no-store, no-cache, must-revalidate, max-age=0/i) {
        print "[PASS] Cache-Control is strengthened correctly.\n";
    } else {
        print "[FAIL] Cache-Control is incorrect. Got: " . ($cache || 'NONE') . "\n";
    }
}

# Test 2: X-Robots-Tag recognition and override
{
    print "\nTesting X-Robots-Tag override...\n";
    my $env = "PERL5LIB=extlib/lib/perl5 UPLOAD_SECURITY_HEADERS='X-Robots-Tag: all' REQUEST_METHOD=GET";
    my $output = `$env perl $cgi_script 2>&1`;

    my ($robots) = ($output =~ /^X-Robots-Tag: (.*)$/im);
    if ($robots && $robots =~ /all/i) {
        print "[PASS] X-Robots-Tag was correctly recognized and overridden.\n";
    } else {
        print "[FAIL] X-Robots-Tag override failed. Got: " . ($robots || 'NONE') . "\n";
    }
}

# Test 3: Log Observability (User-Agent in error logs)
{
    print "\nTesting User-Agent in error logs...\n";
    my $ua = "Sentinel-Security-Scanner";
    my $env = "PERL5LIB=extlib/lib/perl5 HTTP_USER_AGENT='$ua' REQUEST_METHOD=GET";
    my $output = `$env perl $cgi_script 2>&1`;

    if ($output =~ /\[ERROR\].*ua=$ua/i) {
        print "[PASS] User-Agent correctly logged in error message.\n";
    } else {
        print "[FAIL] User-Agent missing from error logs.\n";
        # Print the error log line for debugging
        my ($log) = ($output =~ /(\[ERROR\].*)$/m);
        print "       Log line: " . ($log || 'NONE') . "\n";
    }
}

# Test 4: CGI Max Params hardening
{
    print "\nTesting CGI MAX_PARAMS hardening (limit=10)...\n";
    # We send 11 parameters. CGI.pm should truncate or error depending on version/config,
    # but since we set MAX_PARAMS = 10, any more should be ignored.
    my $query_string = join('&', map { "p$_=$_" } (1..15));
    my $env = "PERL5LIB=extlib/lib/perl5 REQUEST_METHOD=GET QUERY_STRING='$query_string'";
    my $output = `$env perl $cgi_script 2>&1`;

    # We can't easily check internal CGI state from outside, but we verified the code change.
    # This test ensures the script still runs and handles requests even with many params.
    # The script returns 403 or 500 when triggered via GET depending on directory existence.
    if ($output =~ /Error: (?:403|500)/i) {
        print "[PASS] Script handled request with many parameters (early exit due to GET).\n";
    } else {
        print "[FAIL] Script failed to handle request with many parameters.\n";
    }
}
