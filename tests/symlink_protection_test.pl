#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Path qw(make_path remove_tree);
use Fcntl qw(:DEFAULT);

# Set up local test directory
my $test_base = File::Spec->rel2abs('test_files_symlink');
my $test_incoming = File::Spec->catdir($test_base, 'incoming');

remove_tree($test_base) if -d $test_base;
make_path($test_incoming) or die "Failed to create test directory: $!";

# 1. TEST CASE: Symlink Protection
# Create a sensitive file that we DON'T want to overwrite
my $sensitive_file = File::Spec->catfile($test_base, 'sensitive.txt');
open my $sfh, '>', $sensitive_file or die $!;
print $sfh "This is sensitive data. DO NOT OVERWRITE.\n";
close $sfh;

# Create a symlink in the 'incoming' directory pointing to the sensitive file
my $symlink_path = File::Spec->catfile($test_incoming, 'attack.txt');
symlink($sensitive_file, $symlink_path) or die "Could not create symlink: $!";

# Attempt to upload a file named 'attack.txt'
print "Running upload attempt against symlink...\n";
my $upload_success = run_upload($test_base, 'attack.txt', 'incoming', "ATTACK SUCCESSFUL - OVERWRITTEN");

# Check if the sensitive file was overwritten
open my $rfh, '<', $sensitive_file or die $!;
my $current_content = <$rfh>;
close $rfh;

my $failed = 0;
if ($current_content =~ /ATTACK SUCCESSFUL/) {
    print "[FAIL] Vulnerable to symlink attack! Sensitive file was overwritten.\n";
    $failed++;
} else {
    print "[PASS] Protected against symlink attack. Sensitive file remains intact.\n";
}

# 2. TEST CASE: Normal Overwrite (Should work)
# Create an existing file
my $normal_file = File::Spec->catfile($test_incoming, 'normal.txt');
open my $nfh, '>', $normal_file or die $!;
print $nfh "Original content\n";
close $nfh;

print "Running normal upload attempt (overwriting existing file)...\n";
run_upload($test_base, 'normal.txt', 'incoming', "New content");

open my $rfh2, '<', $normal_file or die $!;
my $new_content = <$rfh2>;
close $rfh2;

if ($new_content =~ /New content/) {
    print "[PASS] Normal overwrite succeeded as expected.\n";
} else {
    print "[FAIL] Normal overwrite failed. Content was: $new_content\n";
    $failed++;
}

sub run_upload {
    my ($base, $filename, $dir, $content) = @_;

    my $boundary = "----TestBoundary";
    my $post_data = "--$boundary\r\n" .
                    "Content-Disposition: form-data; name=\"dir\"\r\n\r\n" .
                    "$dir\r\n" .
                    "--$boundary\r\n" .
                    "Content-Disposition: form-data; name=\"file\"; filename=\"$filename\"\r\n" .
                    "Content-Type: text/plain\r\n\r\n" .
                    "$content\r\n" .
                    "--$boundary--\r\n";

    my $content_length = length($post_data);
    my $tmp_post = File::Spec->catfile('tests', 'post_data_symlink.tmp');
    open my $fh, '>', $tmp_post or die $!;
    binmode $fh;
    print $fh $post_data;
    close $fh;

    my $env_vars = "PERL5LIB=extlib/lib/perl5 UPLOAD_BASE_DIR=$base REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$content_length";
    my $cmd = "$env_vars perl cgi-bin/up.cgi < $tmp_post 2>&1";
    my $output = `$cmd`;
    unlink $tmp_post;

    return $output =~ /successfully uploaded/i;
}

exit ($failed ? 1 : 0);
