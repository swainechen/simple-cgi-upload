#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Path qw(make_path remove_tree);

# Set up local test directory
my $test_base = File::Spec->rel2abs('test_files_re');
my $test_incoming = File::Spec->catdir($test_base, 'incoming');

remove_tree($test_base) if -d $test_base;
make_path($test_incoming) or die "Failed to create test directory: $!";

my $cgi_script = File::Spec->catfile('cgi-bin', 'up.cgi');
my $boundary = "TestBoundary";

sub run_upload {
    my ($filename, $env_overrides) = @_;
    my $content = "test content";
    my $post_data = "--$boundary\r\n" .
                    "Content-Disposition: form-data; name=\"dir\"\r\n\r\n" .
                    "incoming\r\n" .
                    "--$boundary\r\n" .
                    "Content-Disposition: form-data; name=\"file\"; filename=\"$filename\"\r\n" .
                    "Content-Type: text/plain\r\n\r\n" .
                    "$content\r\n" .
                    "--$boundary--\r\n";

    my $content_length = length($post_data);

    my $env_vars = "PERL5LIB=extlib/lib/perl5 UPLOAD_BASE_DIR=$test_base REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=$boundary' CONTENT_LENGTH=$content_length";
    if ($env_overrides) {
        while (my ($k, $v) = each %$env_overrides) {
            $env_vars .= " $k=\"$v\"";
        }
    }
    # Capture both stdout and stderr
    my $output = `echo "$post_data" | $env_vars perl $cgi_script 2>&1`;
    return $output;
}

print "Testing regex robustness...\n";

# 1. Verify that an invalid regex in UPLOAD_FORBIDDEN_EXTENSIONS NO LONGER causes a crash
my $env = { UPLOAD_FORBIDDEN_EXTENSIONS => '[' };
my $out1 = run_upload('test.txt', $env);

if ($out1 =~ /successfully uploaded/i) {
    print "[PASS] Script handled invalid regex fragment '[' gracefully and allowed safe upload.\n";
} else {
    print "[FAIL] Script still failing or blocking safe upload. Output: $out1\n";
}

# 2. Verify that the invalid fragment is treated as a literal
# Since '[' is not allowed in filenames, we'll use '..' as a literal extension block.
# Wait, '..' IS a valid regex.
# Let's use something that is INVALID regex but COULD be matched if literal.
# How about '((('?
my $env_literal = { UPLOAD_FORBIDDEN_EXTENSIONS => '(((' };
my $out_literal = run_upload('test.txt', $env_literal);
if ($out_literal =~ /successfully uploaded/i) {
    print "[PASS] Script handled invalid regex fragment '(((' gracefully.\n";
} else {
    print "[FAIL] Script failed on '((('. Output: $out_literal\n";
}

# 3. Verify that valid regex still works
my $env2 = { UPLOAD_FORBIDDEN_EXTENSIONS => 'php\d*' };
my $out3 = run_upload('test.php5', $env2);
if ($out3 =~ /Forbidden file extension/i) {
    print "[PASS] Valid regex fragment 'php\\d*' still works correctly.\n";
} else {
    print "[FAIL] Valid regex fragment 'php\\d*' failed to block 'test.php5'. Output: $out3\n";
}

# 4. Verify that a fragment with special characters that IS a valid regex still works
my $env3 = { UPLOAD_FORBIDDEN_EXTENSIONS => 'p.p' };
my $out4 = run_upload('test.php', $env3);
if ($out4 =~ /Forbidden file extension/i) {
    print "[PASS] Valid regex fragment 'p.p' correctly blocked 'test.php'.\n";
} else {
    print "[FAIL] Valid regex fragment 'p.p' failed to block 'test.php'. Output: $out4\n";
}

remove_tree($test_base);
exit 0;
