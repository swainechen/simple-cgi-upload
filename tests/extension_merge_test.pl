#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Path qw(make_path remove_tree);

# Set up local test directory
my $test_base = File::Spec->rel2abs('test_files_merge');
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
    my $output = `echo "$post_data" | $env_vars perl $cgi_script 2>&1`;
    return $output;
}

print "Testing extension merge logic...\n";

# 1. Verify default extension (.php) is blocked when NO override is set
my $out1 = run_upload('test.php', {});
if ($out1 =~ /Forbidden file extension/i) {
    print "[PASS] Default extension .php blocked without override.\n";
} else {
    print "[FAIL] Default extension .php NOT blocked without override.\n";
    exit 1;
}

# 2. Verify both custom extension (.custom) AND default extension (.php) are blocked when override is set
my $env = { UPLOAD_FORBIDDEN_EXTENSIONS => 'custom' };

my $out2 = run_upload('test.custom', $env);
if ($out2 =~ /Forbidden file extension/i) {
    print "[PASS] Custom extension .custom blocked with override.\n";
} else {
    print "[FAIL] Custom extension .custom NOT blocked with override.\n";
    exit 1;
}

my $out3 = run_upload('test.php', $env);
if ($out3 =~ /Forbidden file extension/i) {
    print "[PASS] Default extension .php STILL blocked with override (Merge working).\n";
} else {
    print "[FAIL] Default extension .php NOT blocked when override set (Overwrite detected, Merge failed!).\n";
    exit 1;
}

# 3. Verify a safe extension (.txt) is still allowed
my $out4 = run_upload('test.txt', $env);
if ($out4 =~ /successfully uploaded/i) {
    print "[PASS] Safe extension .txt allowed with override.\n";
} else {
    print "[FAIL] Safe extension .txt blocked with override.\n";
    exit 1;
}

print "Extension merge tests passed!\n";
remove_tree($test_base);
exit 0;
