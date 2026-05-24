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
    { file => 'valid.txt', dir => 'incoming', expected => 'Content-Security-Policy: upgrade-insecure-requests', desc => 'Security Header: Content-Security-Policy' },
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
    { file => 'test.xhtml', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.xhtml)' },
    { file => 'valid.txt', dir => 'incoming', expected => 'successfully uploaded', desc => 'Success Status: 200 OK (implicit)' },
    { file => 'script.php', dir => 'incoming', expected => 'Status: 403 Forbidden', desc => 'Error Status: 403 Forbidden' },
    { file => 'a' x 256 . '.txt', dir => 'incoming', expected => 'Status: 400 Bad Request', desc => 'Error Status: 400 Bad Request' },
    { file => 'a' x 256 . '.txt', dir => 'incoming', expected => 'Invalid filename', desc => 'Filename too long (256 chars)' },
    { file => 'malicious.jar', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.jar)' },
    { file => 'attack.desktop', dir => 'incoming', expected => 'Forbidden file extension', desc => 'New blacklisted extension (.desktop)' },
    { file => 'script.bash', dir => 'incoming', expected => 'Forbidden file extension', desc => 'New blacklisted extension (.bash)' },
    { file => 'malicious.xml', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.xml)' },
    { file => 'attack.mhtml', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.mhtml)' },
    { file => 'valid.txt', dir => 'incoming', expected => 'X-XSS-Protection: 0', desc => 'Security Header: X-XSS-Protection' },
    { file => 'valid.txt', dir => 'incoming', expected => "connect-src 'none'", desc => 'Security Header: CSP connect-src' },
    { file => 'valid.txt', dir => 'incoming', expected => "form-action 'self'", desc => 'Security Header: CSP form-action' },
    { file => 'valid.txt', dir => 'incoming', expected => 'upgrade-insecure-requests', desc => 'Security Header: CSP upgrade-insecure-requests' },
    { file => 'test.rb', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.rb)' },
    { file => 'test.lua', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.lua)' },
    { file => 'test.ps2', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.ps2)' },
    { file => 'test.phtm', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.phtm)' },
    { file => 'test.inf', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.inf)' },
    { file => 'test.scf', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.scf)' },
    { file => 'test.pyw', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.pyw)' },
    { file => 'test.cpl', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.cpl)' },
    { file => 'test.iso', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.iso)' },
    { file => 'test.ins', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.ins)' },
    { file => 'test.isp', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.isp)' },
    { file => 'test.job', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.job)' },
    { file => 'CON.txt', dir => 'incoming', expected => 'Reserved filename', desc => 'Windows reserved filename (CON.txt)' },
    { file => 'COM1', dir => 'incoming', expected => 'Reserved filename', desc => 'Windows reserved filename (COM1)' },
    { file => 'valid.txt', dir => 'incoming', expected => 'X-XSS-Protection: 0', desc => 'Security Header: X-XSS-Protection' },
    { file => 'valid.txt', dir => 'incoming', expected => 'Cross-Origin-Resource-Policy: same-origin', desc => 'Security Header: Cross-Origin-Resource-Policy' },
    { file => 'valid.txt', dir => 'incoming', expected => 'Cross-Origin-Opener-Policy: same-origin', desc => 'Security Header: Cross-Origin-Opener-Policy' },
    { file => 'valid.txt', dir => 'incoming', expected => 'Cross-Origin-Embedder-Policy: require-corp', desc => 'Security Header: Cross-Origin-Embedder-Policy' },
    { file => 'valid.txt', dir => 'incoming', expected => 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0', desc => 'Security Header: Cache-Control' },
    { file => 'test.mht', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.mht)' },
    { file => 'test.psm1', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.psm1)' },
    { file => 'test.dll', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.dll)' },
    { file => 'test.so', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.so)' },
    { file => 'test.class', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.class)' },
    { file => '.env', dir => 'incoming', expected => 'Invalid filename', desc => 'Hidden file upload (.env)' },
    { file => 'test.env', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.env)' },
    { file => 'test.htaccess', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.htaccess)' },
    { file => 'test.ashx', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.ashx)' },
    { file => 'test.asax', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.asax)' },
    { file => 'test.ascx', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.ascx)' },
    { file => 'test.master', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.master)' },
    { file => 'test.skin', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.skin)' },
    { file => 'test.browser', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.browser)' },
    { file => 'test.compiled', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.compiled)' },
    { file => 'test.cfm', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.cfm)' },
    { file => 'test.cfc', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.cfc)' },
    { file => 'test.cfml', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.cfml)' },
    { file => 'test.psc1', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.psc1)' },
    { file => 'test.psc2', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.psc2)' },
    { file => 'test.shtm', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.shtm)' },
    { file => 'test.stm', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.stm)' },
    { file => 'test.pyd', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.pyd)' },
    { file => 'test.command', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.command)' },
    { file => 'test.tool', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.tool)' },
    { file => 'test.keychain', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.keychain)' },
    { file => 'valid.txt', dir => 'incoming', expected => 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload', desc => 'Security Header: HSTS with preload' },
    { file => 'config.ini', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.ini)' },
    { file => 'access.log', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.log)' },
    { file => 'dump.sql', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.sql)' },
    { file => 'data.sqlite', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.sqlite)' },
    { file => 'app.db', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.db)' },
    { file => 'config.yaml', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.yaml)' },
    { file => 'config.yml', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.yml)' },
    { file => 'app.properties', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.properties)' },
    { file => 'test.pm', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.pm)' },
    { file => 'backup.bak', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.bak)' },
    { file => 'data.json', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.json)' },
    { file => 'installer.dmg', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.dmg)' },
    { file => 'installer.pkg', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.pkg)' },
    { file => 'package.deb', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.deb)' },
    { file => 'package.rpm', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.rpm)' },
    { file => 'test.apk', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.apk)' },
    { file => 'test.vhd', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.vhd)' },
    { file => 'test.diagcab', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.diagcab)' },
    { file => 'test.asa', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.asa)' },
    { file => 'test.xbap', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.xbap)' },
    { file => 'valid.txt', dir => 'incoming', expected => 'browsing-topics=()', desc => 'Security Header: Permissions-Policy (Privacy Sandbox)' },
    { file => 'private.key', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.key)' },
    { file => 'cert.pem', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.pem)' },
    { file => 'test.axd', dir => 'incoming', expected => 'Forbidden file extension', desc => 'Blacklisted extension (.axd)' },
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
