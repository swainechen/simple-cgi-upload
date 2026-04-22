#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Path qw(make_path remove_tree);

my $test_base = File::Spec->rel2abs('test_files_sym');
my $test_incoming = File::Spec->catdir($test_base, 'incoming');

remove_tree($test_base) if -d $test_base;
make_path($test_incoming) or die "Failed to create test directory: $!";

my $secret_file = File::Spec->catfile($test_base, 'secret.txt');
open my $sfh, '>', $secret_file or die $!;
print $sfh "TOP SECRET DATA\n";
close $sfh;

# Create a symlink in incoming pointing to secret.txt
my $target_link = File::Spec->catfile($test_incoming, 'attack.txt');
symlink($secret_file, $target_link) or die "symlink failed: $!";

print "Target link: $target_link\n";
print "Pointing to: $secret_file\n";

my $filename = 'attack.txt';
my $dir = 'incoming';
my $boundary = "----TestBoundary";
my $content = "PWNED";
my $post_data = "--$boundary\r\n" .
                "Content-Disposition: form-data; name=\"dir\"\r\n\r\n" .
                "$dir\r\n" .
                "--$boundary\r\n" .
                "Content-Disposition: form-data; name=\"file\"; filename=\"$filename\"\r\n" .
                "Content-Type: text/plain\r\n\r\n" .
                "$content\r\n" .
                "--$boundary--\r\n";

my $content_length = length($post_data);
my $tmp_post = 'post_data_sym.tmp';
open my $fh, '>', $tmp_post or die $!;
binmode $fh;
print $fh $post_data;
close $fh;

my $env_vars = "PERL5LIB=extlib/lib/perl5 UPLOAD_BASE_DIR=$test_base REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$content_length";
my $cmd = "$env_vars perl cgi-bin/up.cgi < $tmp_post 2>&1";
my $output = `$cmd`;

print "CGI Output: $output\n";

open my $rfh, '<', $secret_file or die $!;
my $secret_content = <$rfh>;
close $rfh;

unlink $tmp_post;
remove_tree($test_base);

if ($secret_content =~ /PWNED/) {
    print "VULNERABLE: Secret file was overwritten via symlink!\n";
    exit 1;
} else {
    print "SAFE: Secret file was not overwritten.\n";
    exit 0;
}
