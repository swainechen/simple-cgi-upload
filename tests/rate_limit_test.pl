#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Path qw(make_path remove_tree);

my $test_base = File::Spec->rel2abs('test_files_ratelimit');
my $test_incoming = File::Spec->catdir($test_base, 'incoming');
my $limit_dir = File::Spec->catdir($test_base, '.rate_limit');

remove_tree($test_base) if -d $test_base;
make_path($test_incoming) or die $!;

my $cgi_script = File::Spec->catfile('cgi-bin', 'up.cgi');
my $boundary = "TestBoundary";
my $content = "test content";
my $filename = "test.txt";

my $post_data = "--$boundary\r\n" .
                "Content-Disposition: form-data; name=\"dir\"\r\n\r\n" .
                "incoming\r\n" .
                "--$boundary\r\n" .
                "Content-Disposition: form-data; name=\"file\"; filename=\"$filename\"\r\n" .
                "Content-Type: text/plain\r\n\r\n" .
                "$content\r\n" .
                "--$boundary--\r\n";

my $content_length = length($post_data);
my $env_vars = "PERL5LIB=extlib/lib/perl5 UPLOAD_BASE_DIR=$test_base UPLOAD_RATE_LIMIT_DIR=$limit_dir REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$content_length REMOTE_ADDR=127.0.0.1";

print "Simulating rapid uploads (Limit: 10 per minute)...\n";

my $failed = 0;
for (my $i = 1; $i <= 11; $i++) {
    my $output = `echo "$post_data" | $env_vars perl $cgi_script 2>&1`;
    if ($i <= 10) {
        if ($output =~ /successfully uploaded/i) {
            print "[PASS] Request $i: Succeeded as expected.\n";
        } else {
            print "[FAIL] Request $i: Should have succeeded but failed.\n";
            print "       Output: $output\n";
            $failed++;
        }
    } else {
        if ($output =~ /429 Too Many Requests/i) {
            print "[PASS] Request $i: Blocked with 429 Too Many Requests.\n";
        } else {
            print "[FAIL] Request $i: Should have been blocked but succeeded.\n";
            print "       Output: $output\n";
            $failed++;
        }
    }
}

remove_tree($test_base);

if ($failed == 0) {
    print "\nRate limiting tests passed!\n";
    exit 0;
} else {
    print "\n$failed rate limiting tests failed.\n";
    exit 1;
}
