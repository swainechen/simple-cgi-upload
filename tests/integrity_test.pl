#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Path qw(make_path remove_tree);
use Digest::SHA;

# Set up local test directory
my $test_base = File::Spec->rel2abs('test_files_integrity');
my $test_incoming = File::Spec->catdir($test_base, 'incoming');

remove_tree($test_base) if -d $test_base;
make_path($test_incoming) or die "Failed to create test directory: $!";

my $filename = 'integrity_test.txt';
my $content = "Security integrity check content";
my $sha256 = Digest::SHA->new(256)->add($content)->hexdigest;

my $boundary = "----TestBoundary";
my $post_data = "--$boundary\r\n" .
                "Content-Disposition: form-data; name=\"dir\"\r\n\r\n" .
                "incoming\r\n" .
                "--$boundary\r\n" .
                "Content-Disposition: form-data; name=\"file\"; filename=\"$filename\"\r\n" .
                "Content-Type: text/plain\r\n\r\n" .
                "$content\r\n" .
                "--$boundary--\r\n";

my $content_length = length($post_data);
my $tmp_post = File::Spec->catfile('tests', 'post_integrity.tmp');
open my $fh, '>', $tmp_post or die $!;
binmode $fh;
print $fh $post_data;
close $fh;

my $ua = "Test-Integrity-Agent";
my $env_vars = "PERL5LIB=extlib/lib/perl5 UPLOAD_BASE_DIR=$test_base REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$content_length HTTP_USER_AGENT='$ua'";
my $cmd = "$env_vars perl cgi-bin/up.cgi < $tmp_post 2>&1";
my $output = `$cmd`;

my $failed = 0;

# Check for digest in HTML output
if ($output =~ /SHA-256: <code>$sha256<\/code>/i) {
    print "[PASS] SHA-256 digest found in HTML output: $sha256\n";
} else {
    print "[FAIL] SHA-256 digest NOT found in HTML output or incorrect.\n";
    print "       Expected: $sha256\n";
    $failed++;
}

# Check for digest in audit log (stderr)
if ($output =~ /\[AUDIT\].*digest=$sha256/i) {
    print "[PASS] SHA-256 digest found in audit log: $sha256\n";
} else {
    print "[FAIL] SHA-256 digest NOT found in audit log.\n";
    $failed++;
}

# Check for User-Agent truncation in logs
my $long_ua = "A" x 300;
$env_vars = "PERL5LIB=extlib/lib/perl5 UPLOAD_BASE_DIR=$test_base REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$content_length HTTP_USER_AGENT='$long_ua'";
$cmd = "$env_vars perl cgi-bin/up.cgi < $tmp_post 2>&1";
$output = `$cmd`;

my $expected_ua = "A" x 255;
if ($output =~ /\[AUDIT\].*ua=$expected_ua(?![A-Z])/i) {
    print "[PASS] User-Agent correctly truncated in audit log.\n";
} else {
    print "[FAIL] User-Agent truncation failed in audit log.\n";
    $failed++;
}

unlink $tmp_post;
remove_tree($test_base);

if ($failed == 0) {
    print "\nIntegrity enhancement tests passed!\n";
    exit 0;
} else {
    print "\n$failed tests failed.\n";
    exit 1;
}
