#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Path qw(make_path remove_tree);

# Set up local test directory
my $test_base = File::Spec->rel2abs('test_files');
my $test_incoming = File::Spec->catdir($test_base, 'incoming');

remove_tree($test_base) if -d $test_base;
make_path($test_incoming) or die "Failed to create test directory: $!";

my @test_cases = (
    { file => 'valid.txt', dir => 'incoming', expected => 'successfully uploaded', desc => 'Valid upload' },
    { file => 'script.php', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension' },
    { file => 'attack.txt', dir => 'secret', expected => 'Invalid or unauthorized directory', desc => 'Path traversal (invalid dir)' },
    { file => 'attack.txt', dir => '../cgi-bin', expected => 'Invalid or unauthorized directory', desc => 'Path traversal (parent dir)' },
    { file => 'valid.txt', dir => 'incoming', expected => 'X-Frame-Options: DENY', desc => 'Security Header: X-Frame-Options' },
    { file => 'valid.txt', dir => 'incoming', expected => 'X-Content-Type-Options: nosniff', desc => 'Security Header: X-Content-Type-Options' },
    { file => 'valid.txt', dir => 'incoming', expected => 'Content-Security-Policy: default-src', desc => 'Security Header: Content-Security-Policy' },
    { file => 'too_large.txt', dir => 'incoming', expected => '413 Request Entity Too Large', desc => 'File size limit (POST_MAX)', env => { CGI_POST_MAX_TEST => 10 } },
    { file => 'test.svg', dir => 'incoming', expected => 'Forbidden file extension', desc => 'SVG upload (XSS risk)' },
    { file => 'test.php.txt', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Double extension bypass (.php.txt)' },
    { file => '-attack.txt', dir => 'incoming', expected => 'Invalid filename', desc => 'Leading dash injection' },
    { file => '.env', dir => 'incoming', expected => 'Invalid filename', desc => 'Hidden file upload (.env)' },
    { file => 'test.asp', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.asp)' },
    { file => 'test.htm', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.htm)' },
    { file => 'test.php5', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.php5)' },
    { file => 'test.pht', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.pht)' },
    { file => 'test.phps', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.phps)' },
    { file => 'test.aspx', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.aspx)' },
    { file => 'a' x 256 . '.txt', dir => 'incoming', expected => 'Invalid filename', desc => 'Filename too long (256 chars)' },
);

my $failed = 0;

foreach my $tc (@test_cases) {
    my $filename = $tc->{file};
    my $dir = $tc->{dir};
    my $boundary = "----TestBoundary";
    my $content = "dummy content";
    my $post_data = "--$boundary\r\n" .
                    "Content-Disposition: form-data; name=\"dir\"\r\n\r\n" .
                    "$dir\r\n" .
                    "--$boundary\r\n" .
                    "Content-Disposition: form-data; name=\"file\"; filename=\"$filename\"\r\n" .
                    "Content-Type: text/plain\r\n\r\n" .
                    "$content\r\n" .
                    "--$boundary--\r\n";

    my $content_length = length($post_data);

    my $tmp_post = File::Spec->catfile('tests', 'post_data.tmp');
    open my $fh, '>', $tmp_post or die $!;
    binmode $fh;
    print $fh $post_data;
    close $fh;

    my $env_vars = "PERL5LIB=extlib/lib/perl5 UPLOAD_BASE_DIR=$test_base REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$content_length";
    if ($tc->{env}) {
        while (my ($k, $v) = each %{$tc->{env}}) {
            $env_vars .= " $k=$v";
        }
    }
    my $cmd = "$env_vars perl cgi-bin/up.cgi < $tmp_post 2>&1";
    my $output = `$cmd`;

    if ($output =~ /\Q$tc->{expected}\E/i) {
        print "[PASS] $tc->{desc}: $filename in $dir\n";
    } else {
        print "[FAIL] $tc->{desc}: $filename in $dir\n";
        print "       Expected pattern: $tc->{expected}\n";
        # Print first few lines of output for debugging
        my @lines = split /\n/, $output;
        print "       Got (first 3 lines): " . join("\n", @lines[0..2]) . "\n";
        $failed++;
    }
    unlink $tmp_post;
}

# Cleanup
# remove_tree($test_base);

if ($failed == 0) {
    print "\nAll security tests passed!\n";
    exit 0;
} else {
    print "\n$failed tests failed.\n";
    exit 1;
}
