#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Path qw(make_path remove_tree);

my $test_base = File::Spec->rel2abs('test_files_perms');
my $test_incoming = File::Spec->catdir($test_base, 'incoming');
my $limit_dir = File::Spec->catdir($test_base, '.rate_limit');
my $config_file = File::Spec->catfile($test_base, 'upload.conf');

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
my $base_env = "PERL5LIB=extlib/lib/perl5 UPLOAD_BASE_DIR=$test_base REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$content_length REMOTE_ADDR=127.0.0.1";

my $failed = 0;

# Test 1: World-writable config file
print "Testing world-writable config file...\n";
open my $cfh, '>', $config_file or die $!;
print $cfh "UPLOAD_MAX_SIZE=1000\n";
close $cfh;
chmod 0666, $config_file; # World-writable

my $output = `echo "$post_data" | UPLOAD_CONFIG_FILE=$config_file $base_env perl $cgi_script 2>&1`;
if ($output =~ /Invalid UPLOAD_BASE_DIR configuration/i) {
    # If config was ignored, it falls back to defaults, which might fail on UPLOAD_BASE_DIR
    # if the default /var/www/html/files doesn't exist or is invalid.
    # In up.cgi:
    # my %config = parse_config_file(...);
    # ...
    # my $base_dir = $ENV{UPLOAD_BASE_DIR} || $config{UPLOAD_BASE_DIR} || "/var/www/html/files";
    print "[PASS] World-writable config file was ignored (fall back occurred).\n";
} else {
    # We want to be sure it didn't use the config.
    # We can use a unique value in config and check if it's NOT applied.
    # Actually, if parse_config_file returns empty hash, that's what we want.
}

# Improved Test 1: Verify config is NOT used
print "Testing world-writable config file (improved)...\n";
open $cfh, '>', $config_file or die $!;
print $cfh "UPLOAD_BASE_DIR=/non/existent/path/at/all\n";
close $cfh;
chmod 0666, $config_file;
# If config is used, it will fail with "Invalid UPLOAD_BASE_DIR configuration" because the path doesn't start with / and only contains safe chars?
# Wait, /non/existent/path/at/all IS valid according to regex m|^/[\w\.\-/]*$|.
# But it will fail later if it's not a directory.

# Let's use UPLOAD_MAX_SIZE=1 and see if we get 413. If it's IGNORED, we shouldn't get 413 for a small upload.
open $cfh, '>', $config_file or die $!;
print $cfh "UPLOAD_MAX_SIZE=1\n";
close $cfh;
chmod 0666, $config_file;
$output = `echo "$post_data" | UPLOAD_CONFIG_FILE=$config_file $base_env perl $cgi_script 2>&1`;
if ($output !~ /413 Request Entity Too Large/i) {
    print "[PASS] World-writable config file was correctly ignored.\n";
} else {
    print "[FAIL] World-writable config file was NOT ignored.\n";
    $failed++;
}

# Test 2: World-writable rate limit directory
print "\nTesting world-writable rate limit directory...\n";
make_path($limit_dir) or die $!;
chmod 0777, $limit_dir; # World-writable

$output = `echo "$post_data" | UPLOAD_RATE_LIMIT_DIR=$limit_dir $base_env perl $cgi_script 2>&1`;
if ($output =~ /Rate limit directory is invalid, a symlink, or world-writable/i) {
    print "[PASS] World-writable rate limit directory was rejected.\n";
} else {
    print "[FAIL] World-writable rate limit directory was NOT rejected.\n";
    $failed++;
}

# Test 3: World-writable rate limit file
print "\nTesting world-writable rate limit file...\n";
chmod 0700, $limit_dir; # Fix directory
use Digest::SHA;
my $ip_hash = Digest::SHA->new(256)->add("127.0.0.1")->hexdigest;
my $ip_file = File::Spec->catfile($limit_dir, $ip_hash);
open my $ifh, '>', $ip_file or die $!;
print $ifh time() . "\n";
close $ifh;
chmod 0666, $ip_file; # World-writable

$output = `echo "$post_data" | UPLOAD_RATE_LIMIT_DIR=$limit_dir $base_env perl $cgi_script 2>&1`;
if ($output =~ /Rate limit file is invalid or world-writable/i) {
    print "[PASS] World-writable rate limit file was rejected.\n";
} else {
    print "[FAIL] World-writable rate limit file was NOT rejected.\n";
    $failed++;
}

# Cleanup
remove_tree($test_base);

if ($failed == 0) {
    print "\nPermission hardening tests passed!\n";
    exit 0;
} else {
    print "\n$failed permission hardening tests failed.\n";
    exit 1;
}
