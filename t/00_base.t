# Base tests for Crypt::PKCS10

use strict;
use warnings;

use Test::More tests => 21;

BEGIN {
    use_ok('Crypt::PKCS10');
}

require_ok('Convert::ASN1');

Crypt::PKCS10->setAPIversion(1);

my $csr = 'random junk
more stuff
-----BEGIN CERTIFICATE REQUEST-----
MIICzjCCAbYCAQAwgYgxEzARBgoJkiaJk/IsZAEZFgNvcmcxFzAVBgoJkiaJk/Is
ZAEZFgdPcGVuU1NMMRUwEwYKCZImiZPyLGQBGRYFdXNlcnMxIzALBgNVBAMMBHRl
c3QwFAYKCZImiZPyLGQBAQwGMTIzNDU2MRwwGgYJKoZIhv	cNAQkBFg10ZXN0QHRl
c3QuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4EhMEu4ppW+3
LSgp/fKGhZsEmgB9kDASa90enSMZvji0pAsAQW3FSwADQLpYC7HFEeJR4aeB7CE5
xS1B4WIm9gfRxLMCekqVHq3IjpCxAN5WjyZ5AsaUOZ0TkrJ7en8x2EeV5R1oM+5G
Eyv8BJ+flizG9Q5RHxpWIn1H1+PWD4dW2RSo/PVECmflceQQb6bmyxy+bka5Sr7W
LxG95LLPss8zBVhlTn8nzMgrKHCFF6MzajapMItWg8vz3MpJLNVjrjp00tM3Qkpk
R3HM6HBNxH5n7P8jiVh6V+OiGXgTEUpYzs0mAHG/A8l6pLLQvw4fUTECArx97nm6
nohKZSijbwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBANyLoU6t4AuVLNqs8PSJ
hkB/AYArPSxibAzqQvl3o5w9u1jbAcGJf7cqPUbIESaeRGxMII9jAwaUIW+E7MqZ
FjpgWH5b3xQHVyjknpteOZJnICHmlMHcwqX1uk+ywC3hRTcC/+k+wtnbs0hvCh6c
t17iTm9qI8Tlf4xhHFrsXeCOCmtN3/HSjy3c9dYVB/je5JDesYWiDy1Ssp5D/Fg9
OwC37p57VNLEyCj397q/bdQtd9wkMQKbYTMOC1Wm3Mco9XOvGW/evs20t4xINjbk
xTf+NvadhsWn4CRnKkUEyqOivkjokf9Lg7SBXqaXL1Q2dGbezOa+lMZ67QQUU5Jo
RyYABCGHI=
-----END CERTIFICATE REQUEST-----
trailing junk
more junk
';

my $decoded = Crypt::PKCS10->new( $csr );

ok( defined $decoded, 'new() successful' );

is( $decoded->version, "v1", 'correct version' );

is( $decoded->commonName, "test", 'correct commonName' );

is( $decoded->emailAddress, 'test@test.com', 'correct emailAddress' );

is( $decoded->subjectPublicKey, '3082010a0282010100e0484c12ee29a56fb72d2829fdf286859b049a007d9030126bdd1e9d2319be38b4a40b00416dc54b000340ba580bb1c511e251e1a781ec2139c52d41e16226f607d1c4b3027a4a951eadc88e90b100de568f267902c694399d1392b27b7a7f31d84795e51d6833ee46132bfc049f9f962cc6f50e511f1a56227d47d7e3d60f8756d914a8fcf5440a67e571e4106fa6e6cb1cbe6e46b94abed62f11bde4b2cfb2cf330558654e7f27ccc82b28708517a3336a36a9308b5683cbf3dcca492cd563ae3a74d2d337424a644771cce8704dc47e67ecff2389587a57e3a2197813114a58cecd260071bf03c97aa4b2d0bf0e1f51310202bc7dee79ba9e884a6528a36f0203010001', 'correct subjectPublicKey' );

is( $decoded->signature, 'dc8ba14eade00b952cdaacf0f48986407f01802b3d2c626c0cea42f977a39c3dbb58db01c1897fb72a3d46c811269e446c4c208f63030694216f84ecca99163a60587e5bdf14075728e49e9b5e3992672021e694c1dcc2a5f5ba4fb2c02de1453702ffe93ec2d9dbb3486f0a1e9cb75ee24e6f6a23c4e57f8c611c5aec5de08e0a6b4ddff1d28f2ddcf5d61507f8dee490deb185a20f2d52b29e43fc583d3b00b7ee9e7b54d2c4c828f7f7babf6dd42d77dc2431029b61330e0b55a6dcc728f573af196fdebecdb4b78c483636e4c537fe36f69d86c5a7e024672a4504caa3a2be48e891ff4b83b4815ea6972f54367466decce6be94c67aed04145392684726', 'correct signature' );

is( scalar $decoded->subject, '/DC=org/DC=OpenSSL/DC=users/CN=test/UID=123456/emailAddress=test@test.com', 'correct subject' );

# Note that this is the input, but re-wrapped because the encoder has
# a different line length from OpenSSL.

my $extcsr = << '~~~';
-----BEGIN CERTIFICATE REQUEST-----
MIICzjCCAbYCAQAwgYgxEzARBgoJkiaJk/IsZAEZFgNvcmcxFzAVBgoJkiaJk/IsZAEZFgdPcGVu
U1NMMRUwEwYKCZImiZPyLGQBGRYFdXNlcnMxIzALBgNVBAMMBHRlc3QwFAYKCZImiZPyLGQBAQwG
MTIzNDU2MRwwGgYJKoZIhvcNAQkBFg10ZXN0QHRlc3QuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA4EhMEu4ppW+3LSgp/fKGhZsEmgB9kDASa90enSMZvji0pAsAQW3FSwADQLpY
C7HFEeJR4aeB7CE5xS1B4WIm9gfRxLMCekqVHq3IjpCxAN5WjyZ5AsaUOZ0TkrJ7en8x2EeV5R1o
M+5GEyv8BJ+flizG9Q5RHxpWIn1H1+PWD4dW2RSo/PVECmflceQQb6bmyxy+bka5Sr7WLxG95LLP
ss8zBVhlTn8nzMgrKHCFF6MzajapMItWg8vz3MpJLNVjrjp00tM3QkpkR3HM6HBNxH5n7P8jiVh6
V+OiGXgTEUpYzs0mAHG/A8l6pLLQvw4fUTECArx97nm6nohKZSijbwIDAQABoAAwDQYJKoZIhvcN
AQELBQADggEBANyLoU6t4AuVLNqs8PSJhkB/AYArPSxibAzqQvl3o5w9u1jbAcGJf7cqPUbIESae
RGxMII9jAwaUIW+E7MqZFjpgWH5b3xQHVyjknpteOZJnICHmlMHcwqX1uk+ywC3hRTcC/+k+wtnb
s0hvCh6ct17iTm9qI8Tlf4xhHFrsXeCOCmtN3/HSjy3c9dYVB/je5JDesYWiDy1Ssp5D/Fg9OwC3
7p57VNLEyCj397q/bdQtd9wkMQKbYTMOC1Wm3Mco9XOvGW/evs20t4xINjbkxTf+NvadhsWn4CRn
KkUEyqOivkjokf9Lg7SBXqaXL1Q2dGbezOa+lMZ67QQUU5JoRyY=
-----END CERTIFICATE REQUEST-----
~~~

is( $decoded->csrRequest(1), $extcsr, 'can extract PEM from CSR' );

#is( $decoded->pkAlgorithm, 'RSA encryption', 'correct encryption algorithm' );
is( $decoded->pkAlgorithm, 'rsaEncryption', 'correct encryption algorithm' );

#is( $decoded->signatureAlgorithm, 'SHA-256 with RSA encryption', 'correct signature algorithm' );
is( $decoded->signatureAlgorithm, 'sha256WithRSAEncryption', 'correct signature algorithm' );

ok( !defined $decoded->certificateTemplate, 'certificateTemplate not present' );

ok( !defined $decoded->extensionValue('foo'), 'extensionValue no extensions present' );

$csr = << '_CSR';
-----BEGIN CERTIFICATE REQUEST-----
MIICyjCCAjMCAQAwgbMxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRl
MRAwDgYDVQQHDAdteSBjaXR5MSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQxEDAOBgNVBAsMB0JpZyBvcmcxFDASBgNVBAsMC1NtYWxsZXIgb3JnMRAw
DgYDVQQDDAdNeSBOYW1lMSAwHgYJKoZIhvcNAQkBFhFub25lQG5vLWVtYWlsLmNv
bTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzOlneyhk1u32kaP0pnULKPmV
Mfr7jhMawWyQxtQH2GozC4WT79bXHnICD+OAVXDBA1O+k3m4jTX2wK+gFw0hTR6k
zKeGgjxzHtMyjPoJeQRgMe+UHSlRcczrFYF9SO4rTTgoKlRIlJfMyPuk+nVhtmCw
TUR62b4grk/y1xP7W8sCAwEAAaCB1TCB0gYJKoZIhvcNAQkOMYHEMIHBMAkGA1Ud
EwQCMAAwCwYDVR0PBAQDAgXgMIGmBgNVHREEgZ4wgZuBDm5vd2F5QG5vbmUuY29t
hhhodHRwczovL2ZyZWQuZXhhbXBsZS5uZXSBG3NvbWVkYXlAbm93aGVyZS5leGFt
cGxlLmNvbYIPd3d3LmV4YW1wbGUubmV0gg93d3cuZXhhbXBsZS5jb22CC2V4YW1w
bGUubmV0ggtleGFtcGxlLmNvbYcECgIDBIcQIAENuAdBAAAAAAAAAAAAADANBgkq
hkiG9w0BAQUFAAOBgQA6Q+I5b4pQmJuu92BXqkLmEb0PSidYo/OoEA81ADMMCzLv
K5+fw2CvpFMTGDqqgKnhgIMOUWhmxkd+kN8cEUcGWFszm2vEP2QKe+CuqTW+mRzU
KBw5bVq5Nq3W2s0ZOvfz/67Qhxdsoabn+pfEno8hNmYnt66L3rixdQA4BaodpA==
-----END CERTIFICATE REQUEST-----
_CSR

$decoded= Crypt::PKCS10->new($csr);
ok( defined $decoded, 'new() successful' );

my $altname = $decoded->extensionValue('subjectAltName');
ok( defined $altname && ref $altname eq 'ARRAY' && @$altname == 9, 'subjectAltName decode successful' );

my $result;
foreach my $item (@$altname) {
    push @$result,  "$_=$item->{$_}" foreach( keys %$item );
}

is( join( ", ", @$result ), 'rfc822Name=noway@none.com, uniformResourceIdentifier=https://fred.example.net, rfc822Name=someday@nowhere.example.com, dNSName=www.example.net, dNSName=www.example.com, dNSName=example.net, dNSName=example.com, iPAddress=10.2.3.4, iPAddress=2001:0DB8:0741:0000:0000:0000:0000:0000', "correct subjectAltName values" );

is( $decoded->subjectAltName, 'rfc822Name:noway@none.com,uniformResourceIdentifier:https://fred.example.net,rfc822Name:someday@nowhere.example.com,dNSName:www.example.net,dNSName:www.example.com,dNSName:example.net,dNSName:example.com,iPAddress:10.2.3.4,iPAddress:2001:0DB8:0741:0000:0000:0000:0000:0000', "correct subjectAltName components" );

is( join( ',', sort $decoded->subjectAltName ), 'dNSName,iPAddress,rfc822Name,uniformResourceIdentifier', 'correct subjectAltName as string' );

is( join( ',', $decoded->subjectAltName( 'iPAddress' )), '10.2.3.4,2001:0DB8:0741:0000:0000:0000:0000:0000', 'correct extraction of IP address list' );

is( $decoded->subjectAltName( 'iPAddress' ), '10.2.3.4', 'correct extraction of first IP address' );
