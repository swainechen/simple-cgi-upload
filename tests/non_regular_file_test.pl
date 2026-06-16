#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Path qw(make_path remove_tree);

# Set up local test directory
my $test_base = File::Spec->rel2abs('test_files_nonreg');
my $test_incoming = File::Spec->catdir($test_base, 'incoming');

remove_tree($test_base) if -d $test_base;
make_path($test_incoming) or die "Failed to create test directory: $!";

my $failed = 0;

# Test Case 1: Refuse to overwrite a FIFO
print "Testing protection against overwriting a FIFO...\n";
my $fifo_path = File::Spec->catfile($test_incoming, 'test_fifo');
system("mkfifo", $fifo_path) == 0 or die "Failed to create FIFO: $!";

my $filename = 'test_fifo';
my $boundary = "----TestBoundary";
my $content = "new content";
my $post_data = "--$boundary\r\n" .
                "Content-Disposition: form-data; name=\"dir\"\r\n\r\n" .
                "incoming\r\n" .
                "--$boundary\r\n" .
                "Content-Disposition: form-data; name=\"file\"; filename=\"$filename\"\r\n" .
                "Content-Type: text/plain\r\n\r\n" .
                "$content\r\n" .
                "--$boundary--\r\n";

my $content_length = length($post_data);
my $tmp_post = File::Spec->catfile('tests', 'post_fifo.tmp');
open my $fh, '>', $tmp_post or die $!;
binmode $fh;
print $fh $post_data;
close $fh;

my $env_vars = "PERL5LIB=extlib/lib/perl5 UPLOAD_BASE_DIR=$test_base REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$content_length";
my $output = `echo "$post_data" | $env_vars perl cgi-bin/up.cgi 2>&1`;

if ($output =~ /403 Forbidden/i && $output =~ /Invalid target file type/i) {
    print "[PASS] Protected against FIFO overwrite.\n";
} else {
    print "[FAIL] FIFO overwrite was NOT correctly blocked.\n";
    print "       Output: $output\n";
    $failed++;
}
unlink $tmp_post;

# Verify FIFO still exists and is still a FIFO
if (-p $fifo_path) {
    print "[PASS] FIFO still exists and is still a FIFO.\n";
} else {
    print "[FAIL] FIFO was removed or changed type.\n";
    $failed++;
}

# Test Case 2: Successfully overwrite a regular file
print "\nTesting successful overwrite of a regular file...\n";
my $reg_file = File::Spec->catfile($test_incoming, 'regular.txt');
open(my $reg_fh, '>', $reg_file) or die $!;
print $reg_fh "old content";
close $reg_fh;

$filename = 'regular.txt';
$post_data = "--$boundary\r\n" .
             "Content-Disposition: form-data; name=\"dir\"\r\n\r\n" .
             "incoming\r\n" .
             "--$boundary\r\n" .
             "Content-Disposition: form-data; name=\"file\"; filename=\"$filename\"\r\n" .
             "Content-Type: text/plain\r\n\r\n" .
             "$content\r\n" .
             "--$boundary--\r\n";
$content_length = length($post_data);

$output = `echo "$post_data" | $env_vars perl cgi-bin/up.cgi 2>&1`;

if ($output =~ /successfully uploaded/i) {
    print "[PASS] Regular file overwrite succeeded.\n";
} else {
    print "[FAIL] Regular file overwrite failed.\n";
    print "       Output: $output\n";
    $failed++;
}

# Verify content
open($reg_fh, '<', $reg_file) or die $!;
my $new_content = <$reg_fh>;
close $reg_fh;

if ($new_content eq $content) {
    print "[PASS] Content was correctly updated.\n";
} else {
    print "[FAIL] Content was NOT updated correctly. Got: $new_content\n";
    $failed++;
}

# Cleanup
remove_tree($test_base);

if ($failed == 0) {
    print "\nNon-regular file protection tests passed!\n";
    exit 0;
} else {
    print "\n$failed tests failed.\n";
    exit 1;
}
