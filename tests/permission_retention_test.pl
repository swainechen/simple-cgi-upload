#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Path qw(make_path remove_tree);

# Set up local test directory
my $test_base = File::Spec->rel2abs('test_files_perms');
my $test_incoming = File::Spec->catdir($test_base, 'incoming');

remove_tree($test_base) if -d $test_base;
make_path($test_incoming) or die "Failed to create test directory: $!";

# TEST CASE: Permission Retention
# Create an existing file with loose permissions (0666)
my $target_file = File::Spec->catfile($test_incoming, 'perms.txt');
open my $fh, '>', $target_file or die $!;
print $fh "Original content\n";
close $fh;
chmod 0666, $target_file or die "Could not chmod: $!";

printf "Initial mode of %s: %04o\n", $target_file, (stat($target_file))[2] & 0777;

# Attempt to upload a file named 'perms.txt', which should overwrite the existing one
print "Running upload attempt to overwrite file with loose permissions...\n";
run_upload($test_base, 'perms.txt', 'incoming', "New content with strict permissions");

my $final_mode = (stat($target_file))[2] & 0777;
printf "Final mode of %s: %04o\n", $target_file, $final_mode;

my $failed = 0;
if ($final_mode == 0644) {
    print "[PASS] File permissions were correctly tightened to 0644 after overwrite.\n";
} else {
    print "[FAIL] File permissions were NOT tightened! Current mode: " . sprintf("%04o", $final_mode) . "\n";
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
    my $tmp_post = File::Spec->catfile('tests', 'post_data_perms.tmp');
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
