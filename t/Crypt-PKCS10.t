# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Crypt-X509-CRL.t'
use Test::More tests => 7;
BEGIN { use_ok('Crypt::PKCS10') }
$csr = loadcsr('t/csr.pem');
is( length $csr, 1078, 'csr file loaded' );
$decoded = Crypt::PKCS10->new( $csr );
ok( defined $decoded, 'new() successful' );
is( $decoded->version, "v1", 'version correct' );
is( $decoded->commonName, "test", 'correct commonName' );
is( $decoded->emailAddress, 'test@test.com', 'correct emailAddress' );
is( $decoded->subjectPublicKey, '3082010a0282010100beede8247dd24399d26dea271f64a070457579ee9c4abd10b494bec67ba058b0eb326cca2d7c4bdce75512c482c5b8bf6ad3b0b88998a9cc1762b277d010d97db32942b8f424cca86d69ff8945d282da9d080d9a3602e152fad704ed7ba0940095fbc1903c2cbd3441f09d8082caa1d3f5d84ddced8a77cb0e5300e05d03702f2a7a6c52234b9903771d29fd77093dac21ee96b3fc2cbf7b97ffc7d8a482bcebd27e4d5778dec00d2c96302e993c10ffed6567428ec680c000d10873fa7208140e40cae1446d189f7fe2f910497e060e91f6d831f9052df495f1176eb476401b88a0663dc265765dbf1849b3e9101784cc099cddf9b5b773c342d52f3b32a6bd0203010001', 'correct subjectPublicKey' );
#is( $decoded->signature, '41525241592830783230653838613829', 'correct signature' ); #seems not to be deterministic o.O

sub loadcsr {
	my $file = shift;
	open FILE, $file || die "cannot load test request" . $file . "\n";
	binmode FILE;    # HELLO Windows, dont fuss with this
	my $holdTerminator = $/;
	undef $/;        # using slurp mode to read the PEM-encoded binary certificate
	my $csr = <FILE>;
	$/ = $holdTerminator;
	close FILE;
	return $csr
}