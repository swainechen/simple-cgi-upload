#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Path qw(make_path remove_tree);

my $cgi_script = File::Spec->catfile('cgi-bin', 'up.cgi');
my $test_base = File::Spec->rel2abs('test_files_max');
my $incoming = File::Spec->catdir($test_base, 'incoming');

# Cleanup and setup
remove_tree($test_base);
make_path($incoming);

print "Running max file count limit tests...\n";

sub run_upload {
    my ($filename, $max_files) = @_;
    my $boundary = "TestBoundary";
    my $content = "test content";
    my $post_data = "--$boundary\r\nContent-Disposition: form-data; name=\"dir\"\r\n\r\nincoming\r\n" .
                    "--$boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"$filename\"\r\nContent-Type: text/plain\r\n\r\n$content\r\n" .
                    "--$boundary--\r\n";
    my $len = length($post_data);
    my $env = "PERL5LIB=extlib/lib/perl5 UPLOAD_BASE_DIR=$test_base UPLOAD_MAX_FILES=$max_files REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$len";
    my $output = `echo "$post_data" | $env perl $cgi_script 2>&1`;
    return $output;
}

# Test 1: Upload under the limit
{
    my $output = run_upload("file1.txt", 2);
    if ($output =~ /Upload Successful/i) {
        print "[PASS] Upload under limit succeeded.\n";
    } else {
        print "[FAIL] Upload under limit failed.\n";
    }
}

# Test 2: Upload at the limit
{
    my $output = run_upload("file2.txt", 2);
    if ($output =~ /Upload Successful/i) {
        print "[PASS] Upload at limit succeeded.\n";
    } else {
        print "[FAIL] Upload at limit failed.\n";
    }
}

# Test 3: Upload over the limit
{
    my $output = run_upload("file3.txt", 2);
    if ($output =~ /507 Insufficient Storage/i) {
        print "[PASS] Upload over limit blocked with 507.\n";
    } else {
        print "[FAIL] Upload over limit was NOT blocked or returned wrong error.\n";
    }
}

# Test 4: Overwrite existing file when at limit
{
    my $output = run_upload("file1.txt", 2);
    if ($output =~ /Upload Successful/i) {
        print "[PASS] Overwriting existing file at limit succeeded.\n";
    } else {
        print "[FAIL] Overwriting existing file at limit failed.\n";
    }
}

# Cleanup
remove_tree($test_base);
print "\nMax file count tests completed.\n";
