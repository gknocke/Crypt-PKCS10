#
# Crypt::PKCS10
#
# ABSTRACT: parse PKCS #10 certificate requests
#
# This software is copyright (c) 2014 by Gideon Knocke.
#
# This is free software; you can redistribute it and/or modify it under
# the same terms as the Perl 5 programming language system itself.
#
# Terms of the Perl programming language system itself
#
# a) the GNU General Public License as published by the Free
#   Software Foundation; either version 1, or (at your option) any
#   later version, or
# b) the "Artistic License"
#
# See LICENSE for details.
#

package Crypt::PKCS10;

use strict;
use warnings;
use Carp;

use overload( q("") => \&_stringify );

use Convert::ASN1;
use Encode ();
use MIME::Base64;
use Scalar::Util ();

our $VERSION = 1.4_03;

my $apiVersion = undef;  # 0 for compatibility.  1 for prefered
my $error;

# N.B. Names are exposed in the API.
#      %shortnames follows & depends on (some) values.
# When adding OIDs, re-generate the documentation (see "for MAINTAINER" below)
#
# New OIDs don't need the [ ] syntax, which is [ prefered name, deprecated name ]
# Some of the deprecated names are used in the ASN.1 definition. and in the $self
# structure, which unfortunately is exposed with the attributes() method.
# Dealing with the deprecated names causes some messy code.

my %oids = (
    '2.5.4.6'                       => 'countryName',
    '2.5.4.8'                       => 'stateOrProvinceName',
    '2.5.4.10'                      => 'organizationName',
    '2.5.4.11'                      => 'organizationalUnitName',
    '2.5.4.3'                       => 'commonName',
    '1.2.840.113549.1.9.1'          => 'emailAddress',
    '1.2.840.113549.1.9.2'          => 'unstructuredName',
    '1.2.840.113549.1.9.7'          => 'challengePassword',
    '1.2.840.113549.1.1.1'          => [ 'rsaEncryption', 'RSA encryption' ],
    '1.2.840.113549.1.1.5'          => [ 'sha1WithRSAEncryption', 'SHA1 with RSA encryption' ],
    '1.2.840.113549.1.1.4'          => [ 'md5WithRSAEncryption', 'MD5 with RSA encryption' ],
    '1.2.840.113549.1.9.14'         => 'extensionRequest',
    '1.3.6.1.4.1.311.13.2.3'        => 'OS_Version',                   # Microsoft
    '1.3.6.1.4.1.311.13.2.2'        => 'EnrollmentCSP',                # Microsoft
    '1.3.6.1.4.1.311.21.20'         => 'ClientInformation',            # Microsoft REQUEST_CLIENT_INFO
    '1.3.6.1.4.1.311.21.7'          => 'certificateTemplate',          # Microsoft
    '2.5.29.37'                     => [ 'extKeyUsage', 'EnhancedKeyUsage' ],
    '2.5.29.15'                     => [ 'keyUsage', 'KeyUsage' ],
    '1.3.6.1.4.1.311.21.10'         => 'ApplicationCertPolicies',      # Microsoft APPLICATION_CERT_POLICIES
    '2.5.29.14'                     => [ 'subjectKeyIdentifier', 'SubjectKeyIdentifier' ],
    '2.5.29.17'                     => 'subjectAltName',
    '1.3.6.1.4.1.311.20.2'          => 'certificateTemplateName',      # Microsoft
    '2.16.840.1.113730.1.1'         => 'netscapeCertType',
    '2.16.840.1.113730.1.2'         => 'netscapeBaseUrl',
    '2.16.840.1.113730.1.4'         => 'netscapeCaRevocationUrl',
    '2.16.840.1.113730.1.7'         => 'netscapeCertRenewalUrl',
    '2.16.840.1.113730.1.8'         => 'netscapeCaPolicyUrl',
    '2.16.840.1.113730.1.12'        => 'netscapeSSLServerName',
    '2.16.840.1.113730.1.13'        => 'netscapeComment',

    #untested
    '2.5.29.19'                     => [ 'basicConstraints', 'Basic Constraints' ],
    '1.2.840.10040.4.1'             => [ 'dsa', 'DSA' ],
    '1.2.840.10040.4.3'             => [ 'dsaWithSha1', 'DSA with SHA1' ],
    '0.9.2342.19200300.100.1.25'    => 'domainComponent',
    '0.9.2342.19200300.100.1.1'     => 'userID',
    '2.5.4.7'                       => 'localityName',
    '1.2.840.113549.1.1.11'         => [ 'sha256WithRSAEncryption', 'SHA-256 with RSA encryption' ],
    '1.2.840.113549.1.1.12'         => 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13'         => [ 'sha512WithRSAEncryption', 'SHA-512 with RSA encryption' ],
    '1.2.840.113549.1.1.14'         => 'sha224WithRSAEncryption',
    '1.2.840.113549.1.1.2'          => [ 'md2WithRSAEncryption', 'MD2 with RSA encryption' ],
    '1.2.840.113549.1.1.3'          => 'md4WithRSAEncryption',
    '1.2.840.113549.1.1.6'          => 'rsaOAEPEncryptionSET',
    '1.2.840.113549.1.1.7'          => 'RSAES-OAEP',
    '1.2.840.113549.1.9.15'         => [ 'smimeCapabilities', 'SMIMECapabilities' ],
    '1.3.14.3.2.29'                 => [ 'sha1WithRSAEncryption', 'SHA1 with RSA signature' ],
    '1.3.6.1.4.1.311.13.1'          => 'RENEWAL_CERTIFICATE',          # Microsoft
    '1.3.6.1.4.1.311.13.2.1'        => 'ENROLLMENT_NAME_VALUE_PAIR',   # Microsoft
    '1.3.6.1.4.1.311.13.2.2'        => 'ENROLLMENT_CSP_PROVIDER',      # Microsoft
    '1.3.6.1.4.1.311.2.1.14'        => 'CERT_EXTENSIONS',              # Microsoft
    '1.3.6.1.5.2.3.5'               => [ 'keyPurposeKdc', 'KDC Authentication' ],
    '1.3.6.1.5.5.7.9.5'             => 'countryOfResidence',
    '2.16.840.1.101.3.4.2.1'        => [ 'sha256', 'SHA-256' ],
    '2.5.4.12'                      => [ 'title', 'Title' ],
    '2.5.4.13'                      => [ 'description', 'Description' ],
    '2.5.4.14'                      => 'searchGuide',
    '2.5.4.15'                      => 'businessCategory',
    '2.5.4.16'                      => 'postalAddress',
    '2.5.4.17'                      => 'postalCode',
    '2.5.4.18'                      => 'postOfficeBox',
    '2.5.4.19',                     => 'physicalDeliveryOfficeName',
    '2.5.4.20',                     => 'telephoneNumber',
    '2.5.4.23',                     => 'facsimileTelephoneNumber',
    '2.5.4.4'                       => [ 'surname', 'Surname' ],
    '2.5.4.41'                      => [ 'name', 'Name' ],
    '2.5.4.42'                      => 'givenName',
    '2.5.4.43'                      => 'initials',
    '2.5.4.44'                      => 'generationQualifier',
    '2.5.4.45'                      => 'uniqueIdentifier',
    '2.5.4.46'                      => 'dnQualifier',
    '2.5.4.51'                      => 'houseIdentifier',
    '2.5.4.65'                      => 'pseudonym',
    '2.5.4.5'                       => 'serialNumber',
    '2.5.4.9'                       => 'streetAddress',
    '2.5.29.32'                     => 'certificatePolicies',
    '2.5.29.32.0'                   => 'anyPolicy',
    '1.3.6.1.5.5.7.2.1'             => 'CPS',
    '1.3.6.1.5.5.7.2.2'             => 'userNotice',
);

my %variantNames;

foreach (keys %oids) {
    my $val = $oids{$_};
    if( ref $val ) {
	$variantNames{$_} = $val;                   # OID to [ new, trad ]
	$variantNames{$val->[0]} = $val->[1];       # New name to traditional for lookups
	$variantNames{'$' . $val->[1]} = $val->[0]; # \$Traditional to new
	$oids{$_} = $val->[!$apiVersion || 0];
    }
}

my %oid2extkeyusage = (
                '1.3.6.1.5.5.7.3.1'        => 'serverAuth',
                '1.3.6.1.5.5.7.3.2'        => 'clientAuth',
                '1.3.6.1.5.5.7.3.3'        => 'codeSigning',
                '1.3.6.1.5.5.7.3.4'        => 'emailProtection',
                '1.3.6.1.5.5.7.3.8'        => 'timeStamping',
                '1.3.6.1.5.5.7.3.9'        => 'OCSPSigning',

		'1.3.6.1.5.5.7.3.21'       => 'sshClient',
		'1.3.6.1.5.5.7.3.22'       => 'sshServer',

		# Microsoft usages

                '1.3.6.1.4.1.311.10.3.1'   => 'msCTLSign',
                '1.3.6.1.4.1.311.10.3.2'   => 'msTimeStamping',
                '1.3.6.1.4.1.311.10.3.3'   => 'msSGC',
                '1.3.6.1.4.1.311.10.3.4'   => 'msEFS',
                '1.3.6.1.4.1.311.10.3.4.1' => 'msEFSRecovery',
                '1.3.6.1.4.1.311.10.3.5'   => 'msWHQLCrypto',
                '1.3.6.1.4.1.311.10.3.6'   => 'msNT5Crypto',
                '1.3.6.1.4.1.311.10.3.7'   => 'msOEMWHQLCrypto',
                '1.3.6.1.4.1.311.10.3.8'   => 'msEmbeddedNTCrypto',
                '1.3.6.1.4.1.311.10.3.9'   => 'msRootListSigner',
                '1.3.6.1.4.1.311.10.3.10'  => 'msQualifiedSubordination',
                '1.3.6.1.4.1.311.10.3.11'  => 'msKeyRecovery',
                '1.3.6.1.4.1.311.10.3.12'  => 'msDocumentSigning',
                '1.3.6.1.4.1.311.10.3.13'  => 'msLifetimeSigning',
                '1.3.6.1.4.1.311.10.3.14'  => 'msMobileDeviceSoftware',

                '1.3.6.1.4.1.311.2.1.21'   => 'msCodeInd',
                '1.3.6.1.4.1.311.2.1.22'   => 'msCodeCom',
                '1.3.6.1.4.1.311.20.2.2'   => 'msSmartCardLogon',


	        # Netscape
                '2.16.840.1.113730.4.1'    => 'nsSGC',
);

my %shortnames = (
		  countryName            => 'C',
		  stateOrProvinceName    => 'ST',
		  organizationName       => 'O',
		  organizationalUnitName => 'OU',
		  commonName             => 'CN',
#		  emailAddress           => 'E', # Deprecated & not recognized by some software
		  domainComponent        => 'DC',
		  localityName           => 'L',
		  userID                 => 'UID',
		  surname                => 'SN',
		  givenName              => 'GN',
);

my %name2oid;

# For generating documentation, not part of API

sub __listOIDs {
    my $class = shift;
    my ( $hash ) = @_;

    sub _cmpOID {
	my @a = split( /\./, $a );
	my @b = split( /\./, $b );

	while( @a && @b ) {
	    my $c = shift @a <=> shift @b;
	    return $c if( $c );
	}
	return @a <=> @b;
    }

    my @max = (0) x 3;
    foreach my $oid ( keys %$hash ) {
	my $len;

	$len = length $oid;
	$max[0] = $len if( $len > $max[0] );
	if( exists $variantNames{$oid} ) {
	    $len = length $variantNames{$oid}[0];
	    $max[1] = $len if( $len > $max[1] );
	    $len = length $variantNames{$oid}[1];
	    $max[2] = $len if( $len > $max[2] );
	} else {
	    $len = length $hash->{$oid};
	    $max[1] = $len if( $len > $max[1] );
	}
    }

    printf( " %-*s %-*s %s\n %s %s %s\n", $max[0], 'OID', $max[1], 'Name (API v1)', 'Old Name (API v0)', '-' x $max[0], '-' x $max[1], '-' x $max[2] );

    foreach my $oid ( sort _cmpOID keys %$hash ) {
	printf( " %-*s %-*s", $max[0], $oid, $max[1], (exists $variantNames{$oid})? $variantNames{$oid}[0]: $hash->{$oid} );
	printf( " (%-s)", $variantNames{$oid}[1] ) if( exists $variantNames{$oid} );
	print( "\n" );
    }
    return;
}

sub _listOIDs {
    my $class = shift;

    $class->setAPIversion(1);
    $class-> __listOIDs( { %oids, %oid2extkeyusage } );

    return;
}

sub setAPIversion {
    my( $class, $version ) = @_;

    $version = 0 unless( defined $version );
    croak( ($error = "Unsupported API version $version\n" ) ) unless( $version >= 0 && $version <= 1 );
    $apiVersion = $version;

    $version = !$version || 0;

    foreach (keys %variantNames) {
	$oids{$_} = $variantNames{$_}[$version] if( /^\d/ ); # Map OID to selected name
    }
    %name2oid = reverse (%oids, %oid2extkeyusage);

    return 1;
}

sub name2oid {
    my $class = shift;
    my( $oid ) = @_;

    return undef unless( defined $oid && $apiVersion > 0 );
    return $name2oid{$oid};
}

# Currently undocumented

sub oid2name {
    my $class = shift;
    my( $oid ) = @_;

    return $oid unless( $apiVersion > 0 );

    return $class->_oid2name( @_ );
}

# Should not be exported, as overloading may break ASN lookups

sub _oid2name {
    my $class = shift;
    my( $oid ) = @_;

    if( exists $oids{$oid} ) {
	$oid = $oids{$oid};
    }elsif( exists $oid2extkeyusage{$oid} ) {
	$oid = $oid2extkeyusage{$oid};
    }
    return $oid;
}

# registerOID( $oid ) => true if $oid is registered, false if not
# registerOID( $oid, $longname ) => Register an OID with its name
# registerOID( $oid, $longname, $shortname ) => Register an OID with an abbreviation for RDNs.

sub registerOID {
    my( $class, $oid, $longname, $shortname ) = @_;

    unless( defined $apiVersion ) {
	carp( "${class}::setAPIversion MUST be called before registerOID().  Defaulting to legacy mode\n" );
	$class->setAPIversion(0);
    }

    return exists $oids{$oid} || exists $oid2extkeyusage{$oid} if( @_ == 2 && defined $oid );

    croak( "Not enough arguments" )          unless( @_ >= 3 && defined $oid && defined $longname );
    croak( "Invalid oid $oid" )              unless( defined $oid && $oid =~ /^\d+(?:\.\d+)*$/ );
    croak( "$oid already registered" )       if( exists $oids{$oid} || exists $oid2extkeyusage{$oid} );
    croak( "$longname already registered" )  if( grep /^$longname$/, values %oids );
    croak( "$shortname already registered" ) if( defined $shortname && grep /^\U$shortname\E$/, values %shortnames );

    $oids{$oid} = $longname;
    $shortnames{$longname} = uc $shortname   if( defined $shortname );
    return 1;
}

sub new {
    my $class = shift;

    undef $error;

    my $self = eval {
	return $class->_new( @_ );
    }; if( $@ ) {
	$error = $@;
	croak( $@ ) if( $apiVersion == 0 );
	return undef;
    }

    return $self;
}

sub error {
    my $class = shift;

    return $error;
}

sub _new {
    my $class  = shift;
    my $der    = shift;
    my %options = (
		   acceptPEM     => 1,
		   escapeStrings => 1,
		   @_
		  );

    unless( defined $apiVersion ) {
	carp( "${class}::setAPIversion MUST be called before new().  Defaulting to legacy mode\n" );
	$class->setAPIversion(0);
    }

    my $self = {};

    $self->{"_$_"} = delete $options{$_} foreach (grep { /^(?:escapeStrings|acceptPEM)$/ } keys %options);
    if( keys %options ) {
	croak( "Invalid option(s) specified: " . join( ', ', sort keys %options ) . "\n" );
    }

    my $parser;

    #malformed requests can produce various warnings; don't proceed in that case.

    local $SIG{__WARN__} = sub { croak @_ };

    if( Scalar::Util::openhandle( $der ) ) {
	local $/;

	binmode $der unless( $self->{_acceptPEM} );

	$der = <$der>;
	croak( "Failed to read request: $!\n" ) unless( defined $der );
    }

    if( $self->{_acceptPEM} && $der =~ /^-----BEGIN\s(?:NEW\s)?CERTIFICATE\sREQUEST-----\s(.*)\s-----END\s(?:NEW\s)?CERTIFICATE\sREQUEST-----$/ms) { #if PEM, convert to DER
        $der = decode_base64($1);
    }

    #some Requests may contain information outside of the regular ASN.1 structure. These parts need to be stripped off

    $der = eval { # Catch out of range errors caused by bad DER & report as format errors.
	use bytes;
	return substr( $der, 0, unpack("n*", substr($der, 2, 2)) + 4 );
    }; croak( "Invalid format for request\n" ) if( $@ );

    $self->{_der} = $der;

    bless( $self, $class );

    $self->{_bmpenc} = Encode::find_encoding('UCS2-BE');

    my $asn = Convert::ASN1->new;
    $self->{_asn} = $asn;
    $asn->prepare(<<ASN1) or croak( $asn->error );

    DirectoryString ::= CHOICE {
      teletexString   TeletexString,
      printableString PrintableString,
      bmpString       BMPString,
      universalString UniversalString,
      utf8String      UTF8String,
      ia5String       IA5String,
      integer         INTEGER}

    Algorithms ::= CHOICE {
        undef         ANY
    }

    Name ::= SEQUENCE OF RelativeDistinguishedName
    RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
    AttributeTypeAndValue ::= SEQUENCE {
      type  OBJECT IDENTIFIER,
      value DirectoryString}

    Attributes ::= SET OF Attribute
    Attribute ::= SEQUENCE {
      type   OBJECT IDENTIFIER,
      values SET OF ANY}


    AlgorithmIdentifier ::= SEQUENCE {
      algorithm  OBJECT IDENTIFIER,
      parameters Algorithms}

    SubjectPublicKeyInfo ::= SEQUENCE {
      algorithm        AlgorithmIdentifier,
      subjectPublicKey BIT STRING}

    --- Certificate Request ---

    CertificationRequest ::= SEQUENCE {
      certificationRequestInfo  CertificationRequestInfo,
      signatureAlgorithm        AlgorithmIdentifier,
      signature                 BIT STRING},

    CertificationRequestInfo ::= SEQUENCE {
      version       INTEGER ,
      subject       Name OPTIONAL,
      subjectPKInfo SubjectPublicKeyInfo,
      attributes    [0] Attributes OPTIONAL}

    --- Extensions ---

    BasicConstraints ::= SEQUENCE {
        cA                  BOOLEAN OPTIONAL, -- DEFAULT FALSE,
        pathLenConstraint   INTEGER OPTIONAL}

    OS_Version ::= IA5String
    emailAddress ::= IA5String

    EnrollmentCSP ::= SEQUENCE {
        KeySpec     INTEGER,
        Name        BMPString,
        Signature   BIT STRING}

    ENROLLMENT_CSP_PROVIDER ::= SEQUENCE { -- MSDN
        keySpec     INTEGER,
        cspName     BMPString,
        signature   BIT STRING}

    ENROLLMENT_NAME_VALUE_PAIR ::= EnrollmentNameValuePair -- MSDN: SEQUENCE OF

    EnrollmentNameValuePair ::= SEQUENCE { -- MSDN
         name       BMPString,
         value      BMPString}

    ClientInformation ::= SEQUENCE { -- MSDN
        clientId       INTEGER,
        MachineName    UTF8String,
        UserName       UTF8String,
        ProcessName    UTF8String}

    extensionRequest ::= SEQUENCE OF Extension
    Extension ::= SEQUENCE {
      extnID    OBJECT IDENTIFIER,
      critical  BOOLEAN OPTIONAL,
      extnValue OCTET STRING}

    SubjectKeyIdentifier ::= OCTET STRING

    certificateTemplate ::= SEQUENCE {
       templateID              OBJECT IDENTIFIER,
       templateMajorVersion    INTEGER OPTIONAL, -- (0..4294967295)
       templateMinorVersion    INTEGER OPTIONAL} -- (0..4294967295)

    EnhancedKeyUsage ::= SEQUENCE OF OBJECT IDENTIFIER
    KeyUsage ::= BIT STRING
    netscapeCertType ::= BIT STRING

    ApplicationCertPolicies ::= SEQUENCE OF PolicyInformation -- Microsoft

    PolicyInformation ::= SEQUENCE {
        policyIdentifier   OBJECT IDENTIFIER,
        policyQualifiers   SEQUENCE OF PolicyQualifierInfo OPTIONAL}

    PolicyQualifierInfo ::= SEQUENCE {
       policyQualifierId    OBJECT IDENTIFIER,
       qualifier            ANY}

    certificatePolicies ::= SEQUENCE OF certPolicyInformation -- RFC 3280

    certPolicyInformation ::= SEQUENCE {
        policyIdentifier    CertPolicyId,
        policyQualifier     SEQUENCE OF certPolicyQualifierInfo OPTIONAL}

    CertPolicyId ::= OBJECT IDENTIFIER

    certPolicyQualifierInfo ::= SEQUENCE {
        policyQualifierId CertPolicyQualifierId,
        qualifier         ANY DEFINED BY policyQualifierId}

    CertPolicyQualifierId ::= OBJECT IDENTIFIER

    CertPolicyQualifier ::= CHOICE {
        cPSuri     CPSuri,
        userNotice UserNotice }

    CPSuri ::= IA5String

    UserNotice ::= SEQUENCE {
        noticeRef     NoticeReference OPTIONAL,
        explicitText  DisplayText OPTIONAL}

    NoticeReference ::= SEQUENCE {
        organization     DisplayText,
        noticeNumbers    SEQUENCE OF INTEGER }

    DisplayText ::= CHOICE {
        ia5String        IA5String,
        visibleString    VisibleString,
        bmpString        BMPString,
        utf8String       UTF8String }

    unstructuredName ::= CHOICE {
        Ia5String       IA5String,
        directoryString DirectoryString}

    challengePassword ::= DirectoryString

    subjectAltName ::= SEQUENCE OF GeneralName

    GeneralName ::= CHOICE {
         otherName                       [0]     AnotherName,
         rfc822Name                      [1]     IA5String,
         dNSName                         [2]     IA5String,
         x400Address                     [3]     ANY, --ORAddress,
         directoryName                   [4]     Name,
         ediPartyName                    [5]     EDIPartyName,
         uniformResourceIdentifier       [6]     IA5String,
         iPAddress                       [7]     OCTET STRING,
         registeredID                    [8]     OBJECT IDENTIFIER}

    AnotherName ::= SEQUENCE {
         type           OBJECT IDENTIFIER,
         value      [0] EXPLICIT ANY }

    EDIPartyName ::= SEQUENCE {
         nameAssigner            [0]     DirectoryString OPTIONAL,
         partyName               [1]     DirectoryString }

    certificateTemplateName ::= CHOICE {
        octets          OCTET STRING,
        directoryString DirectoryString}
ASN1

    $asn->registertype( 'qualifier', '1.3.6.1.5.5.7.2.1', $self->_init('CPSuri') );
    $asn->registertype( 'qualifier', '1.3.6.1.5.5.7.2.2', $self->_init('UserNotice') );

    $parser = $self->_init( 'CertificationRequest' );

    my $top =
	$parser->decode( $der ) or
	  confess( "decode: " . $parser->error .
		   "Cannot handle input or missing ASN.1 definitons" );

    $self->{certificationRequestInfo}{subject}
        = $self->_convert_rdn( $top->{certificationRequestInfo}{subject} );

    $self->{certificationRequestInfo}{version}
        = $top->{certificationRequestInfo}{version};

    $self->{certificationRequestInfo}{attributes} = $self->_convert_attributes(
        $top->{certificationRequestInfo}{attributes} );

    $self->{_pubkey} = "-----BEGIN PUBLIC KEY-----\n" .
      encode_base64( $self->_init('SubjectPublicKeyInfo')->
		     encode( $top->{certificationRequestInfo}{subjectPKInfo} ) ) .
		       "-----END PUBLIC KEY-----\n";

    $self->{certificationRequestInfo}{subjectPKInfo} = $self->_convert_pkinfo(
        $top->{certificationRequestInfo}{subjectPKInfo} );

    $self->{signature} = $top->{signature};

    $self->{signatureAlgorithm}
        = $self->_convert_signatureAlgorithm( $top->{signatureAlgorithm} );

    return $self;
}

# Convert::ASN1 returns BMPStrings as 16-bit fixed-width characters, e.g. UCS2-BE

sub _bmpstring {
    my $self = shift;

    my $enc = $self->{_bmpenc};

    $_ = $enc->decode( $_ ) foreach (@_);

    return;
}

# Find the obvious BMPStrings in a value and convert them
# This doesn't catch direct values, but does find them in hashes
# (generally as a result of a CHOICE)
#
# Convert iPAddresses as well

sub _scanvalue {
    my $self = shift;

    my( $value ) = @_;

    return unless( ref $value );
    if( ref $value eq 'ARRAY' ) {
	foreach (@$value) {
	    $self->_scanvalue( $_ );
	}
	return;
    }
    if( ref $value eq 'HASH' ) {
	foreach my $k (keys %$value) {
	    if( $k eq 'bmpString' ) {
		$self->_bmpstring( $value->{bmpString} );
		next;
	    }
	    if( $k eq 'iPAddress' ) {
		use bytes;
		my $addr = $value->{iPAddress};
		if( length $addr == 4 ) {
		    $value->{iPAddress} = sprintf( '%vd', $addr );
		} else {
		    $addr = sprintf( '%*v02X', ':', $addr );
		    $addr =~ s/([[:xdigit:]]{2}):([[:xdigit:]]{2})/$1$2/g;
		    $value->{iPAddress} = $addr;
		}
		next;
	    }
	    $self->_scanvalue( $value->{$k} );
	}
	return;
    }
    return;
}

sub _convert_signatureAlgorithm {
    my $self = shift;

    my $signatureAlgorithm = shift;
    $signatureAlgorithm->{algorithm}
        = $oids{$signatureAlgorithm->{algorithm}}
	  if( defined $signatureAlgorithm->{algorithm}
	    && exists $oids{$signatureAlgorithm->{algorithm}} );

    if ($signatureAlgorithm->{parameters}{undef}) {
        delete ($signatureAlgorithm->{parameters});
    }
    return $signatureAlgorithm;
}

sub _convert_pkinfo {
    my $self = shift;

    my $pkinfo = shift;

    $pkinfo->{algorithm}{algorithm}
        = $oids{$pkinfo->{algorithm}{algorithm}}
	  if( defined $pkinfo->{algorithm}{algorithm}
	    && exists $oids{$pkinfo->{algorithm}{algorithm}} );
    if ($pkinfo->{algorithm}{parameters}{undef}) {
        delete ($pkinfo->{algorithm}{parameters});
    }
    return $pkinfo;
}

# OIDs requiring some sort of special handling
#
# Called with decoded value, returns updated value.
# Key is ASN macro name

my %special;
%special =
(
 EnhancedKeyUsage => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     foreach (@{$value}) {
	 $_ = $oid2extkeyusage{$_} if(defined $oid2extkeyusage{$_});
     }
     return $value;
 },
KeyUsage => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     my $bit =  unpack('C*', @{$value}[0]); #get the decimal representation
     my $length = int(log($bit) / log(2) + 1); #get its bit length
     my @usages = reverse( $id eq 'KeyUsage'? # Following are in order from bit 0 upwards
			   qw(digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement keyCertSign cRLSign encipherOnly decipherOnly) :
			   qw(client server email objsign reserved sslCA emailCA objCA) );
     my $shift = ($#usages + 1) - $length; # computes the unused area in @usages

     @usages = @usages[ grep { $bit & (1 << $_ - $shift) } 0 .. $#usages ]; #transfer bitmap to barewords

     return [ @usages ] if( $apiVersion >= 1 );

     return join( ', ', @usages );
 },
netscapeCertType => sub {
     goto &{$special{KeyUsage}};
 },
SubjectKeyIdentifier => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     return unpack( "H*", $value );
 },
ApplicationCertPolicies => sub {
     goto &{$special{certificatePolicies}} if( $apiVersion > 0 );

     my $self = shift;
     my( $value, $id ) = @_;

     foreach my $entry (@{$value}) {
	 $entry->{policyIdentifier} = $self->_oid2name( $entry->{policyIdentifier} );
     }

     return $value;
 },
certificateTemplate => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     $value->{templateID} = $self->_oid2name( $value->{templateID} ) if( $apiVersion > 0 );
     return $value;
 },
ENROLLMENT_NAME_VALUE_PAIR => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     $self->_bmpstring( @{$value}{qw/name value/} );

     return $value;
 },
EnrollmentCSP => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     $self->_bmpstring( $value->{Name} );

     return $value;
 },
ENROLLMENT_CSP_PROVIDER => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     $self->_bmpstring( $value->{cspName} );

     return $value;
 },
certificatePolicies => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     foreach my $policy (@$value) {
	 $policy->{policyIdentifier} = $self->_oid2name( $policy->{policyIdentifier} );
	 if( exists $policy->{policyQualifier} ) {
	     foreach my $qualifier (@{$policy->{policyQualifier}}) {
		 $qualifier->{policyQualifierId} = $self->_oid2name( $qualifier->{policyQualifierId} );
		 my $qv = $qualifier->{qualifier};
		 if( ref $qv eq 'HASH' ) {
		     foreach my $qt (keys %$qv) {
			 if( $qt eq 'explicitText' ) {
			     $qv->{$qt} = (values %{$qv->{$qt}})[0];
			 } elsif( $qt eq 'noticeRef' ) {
			     my $userNotice = $qv->{$qt};
			     $userNotice->{organization} = (values %{$userNotice->{organization}})[0];
			 }
		     }
		     $qv->{userNotice} = delete $qv->{noticeRef}
		       if( exists $qv->{noticeRef} );
		 }
	     }
	 }
     }
     return $value;
 },
CERT_EXTENSIONS => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     return $self->_convert_extensionRequest( [ $value ] ) if( $apiVersion > 0 ); # Untested
 },
BasicConstraints => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     my $string = sprintf( 'CA:%s', ($value->{cA}? 'TRUE' : 'FALSE') );
     $string .= sprintf( ',pathlen:%d', $value->{pathLenConstraint} ) if( exists $value->{pathLenConstraint} );
     return $string;
 },
unstructuredName => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     return $self->_hash2string( $value );
 },
challengePassword => sub {
     my $self = shift;
     my( $value, $id ) = @_;

     return $self->_hash2string( $value );
 },
); # %special

sub _convert_attributes {
    my $self = shift;
    my( $typeandvalues ) = @_;

    foreach my $entry ( @{$typeandvalues} ) {
	my $oid = $entry->{type};
	my $name = $oids{$oid};
	$name = $variantNames{$name} if( defined $name && exists $variantNames{$name} );

	next unless( defined $name );

	$entry->{type} = $name;

	if ($name eq 'extensionRequest') {
	    $entry->{values} = $self->_convert_extensionRequest($entry->{values}[0]);
	} else {
	    my $parser = $self->_init( $name, 1 ) or next; # Skip unknown attributes

	    if($entry->{values}[1]) {
		confess( "Incomplete parsing of attribute type: $name" );
	    }
	    my $value = $entry->{values} = $parser->decode($entry->{values}[0]) or
	      confess( "Looks like damaged input parsing $name" );

	    if( exists $special{$name} ) {
		my $action = $special{$name};
		$entry->{values} = $action->($self, $value, $name );
	    }
	}
    }
    return $typeandvalues;
}

sub _convert_extensionRequest {
    my $self = shift;
    my( $extensionRequest ) = @_;

    my $parser = $self->_init('extensionRequest');
    my $decoded = $parser->decode($extensionRequest) or return [];

    foreach my $entry (@{$decoded}) {
	my $name = $oids{ $entry->{extnID} };
	$name = $variantNames{$name} if( defined $name && exists $variantNames{$name} );
        if (defined $name) {
	    my $asnName = $name;
	    $asnName =~ tr/ //d;
            my $parser = $self->_init($asnName, 1);
            if(!$parser) {
                $entry = undef;
                next;
            }
            $entry->{extnID} = $name;
            my $dec = $parser->decode($entry->{extnValue}) or
	      confess( $parser->error . ".. looks like damaged input parsing $asnName" );

            $entry->{extnValue} = $self->_mapExtensions($asnName, $dec);
        }
    }
    @{$decoded} = grep { defined } @{$decoded};
    return $decoded;
}

sub _mapExtensions {
    my $self = shift;

    my( $id, $value ) = @_;

    $self->_scanvalue( $value );

    if( exists $special{$id} ) {
	my $action = $special{$id};
	$value = $action->($self, $value, $id );
    }

    return $value
}


sub _convert_rdn {
    my $self = shift;
    my $typeandvalue = shift;
    my %hash = ( _subject => [], );
    foreach my $entry ( @$typeandvalue ) {
	foreach my $item (@$entry) {
	    my $oid = $item->{type};
	    my $name = (exists $variantNames{$oid})? $variantNames{$oid}[1]: $oids{ $oid };
	    if( defined $name ) {
		push @{$hash{$name}}, values %{$item->{value}};
		push @{$hash{_subject}}, $name, [ values %{$item->{value}} ];
		my @names = (exists $variantNames{$oid})? @{$variantNames{$oid}} : ( $name );
		foreach my $name ( @names ) {
		    unless( $self->can( $name ) ) {
			no strict 'refs';
			*$name =  sub {
			    my $self = shift;
			    return @{ $self->{certificationRequestInfo}{subject}{$name} } if( wantarray );
			    return $self->{certificationRequestInfo}{subject}{$name}[0] || '';
			}
		    }
		}
	    }
	}
    }

    return \%hash;
}

sub _init {
    my $self = shift;
    my( $node, $optional ) = @_;

    my $parsed = $self->{_asn}->find($node);

    unless( defined $parsed || $optional ) {
	croak( "Missing node $node in ASN.1\n" );
    }
    return $parsed;
}

###########################################################################
# interface methods

sub csrRequest {
    my $self = shift;
    my $format = shift;

    return( "-----BEGIN CERTIFICATE REQUEST-----\n" .
	    encode_base64( $self->{_der} ) .
	    "-----END CERTIFICATE REQUEST-----\n" ) if( $format );

    return $self->{_der};
}

# Common subject components documented to be always present:

foreach my $component (qw/commonName organizationalUnitName organizationName
                          emailAddress stateOrProvinceName countryName domainComponent/ ) {
    no strict 'refs';

    unless( defined &$component ) {
	*$component = sub {
	    my $self = shift;
	    return @{ $self->{certificationRequestInfo}{subject}{$component} || [] } if( wantarray );
	    return $self->{certificationRequestInfo}{subject}{$component}[0] || '';
	}
    }
}

# Complete subject

sub subject {
    my $self = shift;
    my $long = shift;

    return @{ $self->{certificationRequestInfo}{subject}{_subject} } if( wantarray );

    my @subject = @{ $self->{certificationRequestInfo}{subject}{_subject} };

    my $subj = '';
    while( @subject ) {
	my( $name, $value ) = splice( @subject, 0, 2 );
	$name = $shortnames{$name} if( !$long && exists $shortnames{$name} );
	$subj .= "/$name=" . join( ',', @$value );
    }

    return $subj;
}

sub subjectAltName {
    my $self = shift;
    my( $type ) = @_;

    my $san = $self->extensionValue( 'subjectAltName' );
    unless( defined $san ) {
	return () if( wantarray );
	return undef;
    }

    if( !defined $type ) {
	if( wantarray ) {
	    my %comps;
	    $comps{$_} = 1 foreach (map { keys %$_ } @$san);
	    return keys %comps;
	}
	my @string;
	foreach my $comp (@$san) {
	    push @string, join( '+', map { "$_:$comp->{$_}" } sort keys %$comp );
	}
	return join( ',', @string );
    }

    my $result = [ map { $_->{$type} } grep { exists $_->{$type} } @$san ];

    return @$result if( wantarray );
    return $result->[0];
}

sub version {
    my $self = shift;
    my $v = $self->{certificationRequestInfo}{version};
    return sprintf( "v%u", $v+1 );
}

sub pkAlgorithm {
    my $self = shift;
    return $self->{certificationRequestInfo}{subjectPKInfo}{algorithm}{algorithm};
}

sub subjectPublicKey {
    my $self = shift;
    my $format = shift;

    return $self->{_pubkey} if( $format );
    return unpack('H*', $self->{certificationRequestInfo}{subjectPKInfo}{subjectPublicKey}[0]);
}

sub signatureAlgorithm {
    my $self = shift;
    return $self->{signatureAlgorithm}{algorithm};
}

sub signature {
    my $self = shift;
    unpack('H*', $self->{signature}[0]);
}

sub _attributes {
    my $self = shift;

    my $attributes = $self->{certificationRequestInfo}{attributes};
    return undef unless( defined $attributes );

    return { map { $_->{type} => $_->{values} } @$attributes };
}

sub attributes {
    my $self = shift;
    my( $name ) = @_;

    if( $apiVersion < 1 ) {
	my $attributes = $self->{certificationRequestInfo}{attributes};
	return () unless( defined $attributes );

	my %hash = map { $_->{type} => $_->{values} }
	  @{$attributes};
	return %hash;
    }

    my $attributes = $self->_attributes;
    unless( defined $attributes ) {
	return () if( wantarray );
	return undef;
    }

    unless( defined $name ) {
	return grep { $_  ne 'extensionRequest' } keys %$attributes;
    }

    if( $name eq 'extensionRequest' ) { # Meaningless, and extensions/extensionValue handle
	return () if( wantarray );
	return undef;
    }

    my @attrs = grep { $_ eq $name } keys %$attributes;
    unless( @attrs ) {
	return () if( wantarray );
	return undef;
    }

    my @values;
    foreach my $attr (@attrs) {
	my $values = $attributes->{$attr};
	$values = [ $values ] unless( ref $values eq 'ARRAY' );
	foreach my $value (@$values)  {
	    my $value = $self->_hash2string( $value );
	    push @values, (wantarray? $value : $self->_value2strings( $value ));
	}
    }
    return @values if( wantarray );

    if( @values == 1 ) {
	$values[0] =~ s/^\((.*)\)$/$1/;
	return $values[0];
    }
    return join( ',', @values );
}

sub certificateTemplate {
    my $self = shift;

    return $self->extensionValue( 'certificateTemplate', @_ );
}

# If a hash contains one string (e.g. a CHOICE containing type=>value), return the string.
# If the hash is nested, try recursing.
# If the string can't be identified (clutter in the hash), return the hash
# Some clutter can be filtered by specifying $exclude (a regexp)

sub _hash2string {
    my $self = shift;
    my( $hash, $exclude ) = @_;

    return $hash unless( ref $hash eq 'HASH' );

    my @keys = keys %$hash;

    @keys = grep { $_ !~ /$exclude/ } @keys if( defined $exclude );

    return $hash if( @keys != 1 );

    return $self->_hash2string( $hash->{$keys[0]} ) if( ref $hash->{$keys[0]} eq 'HASH' );

    return $hash->{$keys[0]};
}

# Convert a value to a printable string

sub _value2strings {
    my $self = shift;
    my( $value ) = @_;

    my @strings;
    if( ref $value eq 'ARRAY' ) {
	foreach my $value (@$value) {
	    push @strings, $self->_value2strings( $value );
	}
	return '(' . join( ',', @strings ) . ')' if( @strings > 1 );
	return join( ',', @strings );
    }
    if( ref $value eq 'HASH' ) {
	foreach my $k (sort keys %$value) {
	    push @strings, "$k=" . $self->_value2strings( $value->{$k} );
	}
	return '(' . join( ',', @strings ) . ')' if( @strings > 1 );
	return join( ',', @strings );
    }

    return $value if( $value =~ /^\d+$/ );

    # OpenSSL and Perl-compatible string syntax

    $value =~ s/(["\\\$])/\\$1/g if( $self->{_escapeStrings} );

    return $value if( $value =~ m{\A[\w!$%^&*_=+\[\]\{\}:;|\\<>./?"'-]+\z} ); # Barewords

    return '"' . $value . '"'; # Must quote: whitespace, non-printable, comma, (), null string
}

sub extensions {
    my $self = shift;

    my $attributes = $self->_attributes;
    return () unless( defined $attributes && exists $attributes->{extensionRequest} );

    my @present =  map { $_->{extnID} } @{$attributes->{extensionRequest}};
    if( $apiVersion >= 1 ) {
	foreach my $ext (@present) {
	    $ext = $variantNames{'$' . $ext} if( exists $variantNames{'$' . $ext} );
	}
    }
    return @present;
}

sub extensionValue {
    my $self = shift;
    my( $extensionName, $format ) = @_;

    my $attributes = $self->_attributes;
    my $value;
    return undef unless( defined $attributes && exists $attributes->{extensionRequest} );
    $extensionName = $variantNames{$extensionName} if( exists $variantNames{$extensionName} );

    foreach my $entry (@{$attributes->{extensionRequest}}) {
        if ($entry->{extnID} eq $extensionName) {
            $value = $entry->{extnValue};
	    if( $apiVersion == 0 ) {
		while (ref $value eq 'HASH') {
		    my @keys = keys %{$value};
		    $value = $value->{ shift @keys } ;
		}
	    } else {
		$value = $self->_hash2string( $value, '(?i:^(?:critical|.*id)$)' );
		$value = $self->_value2strings( $value ) if( $format );
	    }
	    last;
        }
    }
    $value =~ s/^\((.*)\)$/$1/ if( $format );

    return $value;
}

sub extensionPresent {
    my $self = shift;
    my( $extensionName ) = @_;

    my $attributes = $self->_attributes;
    return undef unless( defined $attributes && exists $attributes->{extensionRequest} );

    $extensionName = $variantNames{$extensionName} if( exists $variantNames{$extensionName} );

    foreach my $entry (@{$attributes->{extensionRequest}}) {
        if ($entry->{extnID} eq $extensionName) {
	    return 2 if ($entry->{critical});
	    return 1;
        }
    }
    return undef;
}

sub _wrap {
    my( $to, $text ) = @_;

    my $wid = 76 - $to;

    my $out = substr( $text, 0, $wid, '' );

    while( length $text ) {
	$out .= "\n" . (' ' x $to) . substr( $text, 0, $wid, '' );
    }
    return $out;
}

sub _stringify {
    my $self = shift;

    local $self->{_escapeStrings} = 0;

    my $max = 0;
    foreach ($self->attributes, $self->extensions, qw/Version Subject Key_algorithm Public_key Signature_algorithm Signature/) {
	$max = length if( length > $max );
    }

    my $string = sprintf( "%-*s: %s\n", $max, 'Version', $self->version ) ;

    $string .= sprintf( "%-*s: %s\n", $max, 'Subject', _wrap( $max+2, scalar $self->subject ) );

    $string .= "\n          --Attributes--\n";

    $string .= "     --None--" unless( $self->attributes );

    foreach ($self->attributes) {
	$string .= sprintf( "%-*s: %s\n", $max, $_, _wrap( $max+2, scalar $self->attributes($_) ) );
    }

    $string .= "\n          --Extensions--\n";

    $string .= "     --None--" unless( $self->extensions );

    foreach ($self->extensions) {
	my $critical = $self->extensionPresent($_) == 2? 'critical,': '';

	$string .= sprintf( "%-*s: %s\n", $max, $_,
			    _wrap( $max+2, $critical . ($_ eq 'subjectAltName'? scalar $self->subjectAltName: $self->extensionValue($_, 1) ) ) );
    }

    $string .= "\n          --Key and signature--\n";
    $string .= sprintf( "%-*s: %s\n", $max, 'Key algorithm', $self->pkAlgorithm );
    $string .= sprintf( "%-*s: %s\n", $max, 'Public key', _wrap( $max+2, $self->subjectPublicKey ) );
    $string .= $self->subjectPublicKey(1);
    $string .= sprintf( "%-*s: %s\n", $max, 'Signature algorithm', $self->signatureAlgorithm );
    $string .= sprintf( "%-*s: %s\n", $max, 'Signature', _wrap( $max+2, $self->signature ) );

    $string .= "\n          --Request--\n" . $self->csrRequest(1);

    return $string;
}

1;

__END__

=pod

=begin readme text

This file is automatically generated by pod2readme from PKCS10.pm and Changes.

=end readme

=head1 NAME

Crypt::PKCS10 - parse PKCS #10 certificate requests

=begin readme pod

=head1 RELEASE NOTES

Version 1.4 has several API changes.  Most users should have a painless migration.

ALL users must call Crypt::PKCS10->setAPIversion.  If not, a warning will be generated
by the first class method called.  This warning will be made a fatal exception in a
future release.

Other than that requirement, the legacy mode is compatible with previous versions.

C<new> will no longer generate exceptions.  C<undef> is returned on all errors. Use
the error class method to retrieve the reason.

new will accept an open file handle in addition to a request.

Users are encouraged to migrate to the version 1 API.  It is much easier to use,
and does not require the application to navigate internal data structures.

=head1 INSTALLATION
    To install this module type the following:

       perl Makefile.PL
       make
       make test
       make install

=head1 REQUIRES

Convert::ASN1

=end readme

=head1 SYNOPSIS

    use Crypt::PKCS10;

    Crypt::PKCS10->setAPIversion( 1 );
    my $decoded = Crypt::PKCS10->new( $csr ) or die Crypt::PKCS10->error;

    print $decoded;

    @names = $decoded->extensionValue('subjectAltName' );
    @names = $decoded->subject unless( @names );

    %extensions = map { $_ => $decoded->extensionValue( $_ ) } $decoded->extensions

=head1 DESCRIPTION

C<Crypt::PKCS10> parses PKCS #10 certificate requests (CSRs) and provides accessor methods to extract the data in usable form.

Common object identifiers will be translated to their corresponding names.
Additionally, accessor methods allow extraction of single data fields.
Bit Strings like signatures will be returned in their hexadecimal representation.

The access methods return the value corresponding to their name.  If called in scalar context, they return the first value (or an empty string).  If called in array context, they return all values.

=head1 METHODS

Access methods may exist for subject name components that are not listed here.  To test for these, use code of the form:

  $locality = $decoded->localityName if( $decoded->can('localityName') );

If a name component exists in a CSR, the method will be present.  The converse is not (always) true.

=head2 class method setAPIversion( $version )

Selects the API version (0 or 1) expected.

Must be called before calling any other method.

=over 4

=item Version 0 - B<DEPRECATED>

Some OID names have spaces and descriptions

This is the format used for C<Crypt::PKCS10> version 1.3 and lower.  The attributes method returns legacy data.

=item Version 1

OID names from RFCs - or at least compatible with OpenSSL and ASN.1 notation.  The attributes method conforms to version 1.

=back

If not called, a warning will be generated and the API will default to version 0.

In a future release, the warning will be changed to a fatal exception.

To ease migration, both old and new names are accepted by the API.

Every program should call C<setAPIversion(1)>.

=cut

=head2 class method new( $csr, %options )

Constructor, creates a new object containing the parsed PKCS #10 certificate request.

C<$csr> may be a scalar containing the request, or a file handle from which to read it.

If a file handle is supplied, the caller should specify C<< acceptPEM => 0 >> if the contents are DER.

The request may be PEM or binary DER encoded.  Only one request is processed.

If PEM, other data (such as mail headers) may precede or follow the CSR.

    my $decoded = Crypt::PKCS10->new( $csr ) or die Crypt::PKCS10->error;

Returns C<undef> if there is an I/O error or the request can not be parsed successfully.

Call C<error()> to obtain more detail.

=head3 options

=over 4

=item acceptPEM

If B<false>, the input must be in DER format.  C<binmode> will be called on a file handle.

If B<true>, the input is checked for a PEM certificate request.  If not found, the csr
is assumed to be in DER format.

Default is B<true>.

=item escapeStrings

If B<true>, strings returned for extension and attribute values are '\'-escaped when formatted.
This is compatible with OpenSSL configuration files.

The special characters are: '\', '$', and '"'

If B<false>, these strings are not '\'-escaped.  This is useful when they are being displayed
to a human.

The default is B<true>.

=back

No exceptions are generated.

The object will stringify to a human-readable representation of the CSR.  This is
useful for debugging and perhaps for displaying a request.  However, the format
is not part of the API and may change.  It should not be parsed by automated tools.

Exception: The public key and extracted request are PEM blocks, which other tools
can extract.

=head2 class method error

Returns a string describing the last error encountered;

=head2 class method name2oid( $oid )

Returns the OID corresponding to a name returned by an access method.

Not in API v0;

=head2 csrRequest( $format )

Returns the binary (ASN.1) request (after conversion from PEM and removal of any data beyond the length of the ASN.1 structure.

If $format is B<true>, the request is returned as a PEM CSR.  Otherwise as a binary string.

=head2 Access methods for the subject's distinguished name

Note that B<subjectAltName> is prefered, and that modern certificate users will ignore the subject if B<subjectAltName> is present.

=head3 subject( $format )

Returns the entire subject of the CSR.

In scalar context, returns the subject as a string in the form C</componentName=value,value>.
  If format is B<true>, long component names are used.  By default, abbreviations are used when they exist.

  e.g. /countryName=AU/organizationalUnitName=Big org/organizationalUnitName=Smaller org
  or     /C=AU/OU=Big org/OU=Smaller org

In array context, returns an array of C<(componentName, [values])> pairs.  Abbreviations are not used.

Note that the order of components in a name is significant.

=head3 commonName

Returns the common name(s) from the subject.

    my $cn = $decoded->commonName();

=head3 organizationalUnitName

Returns the organizational unit name(s) from the subject

=head3 organizationName

Returns the organization name(s) from the subject.

=head3 emailAddress

Returns the email address from the subject.

=head3 stateOrProvinceName

Returns the state or province name(s) from the subject.

=head3 countryName

Returns the country name(s) from the subject.

=head2 subjectAltName( $type )

Convenience method.

When $type is specified: returns the subject alternate name values of the specified type in list context, or the first value
of the specified type in scalar context.

Returns undefined/empty list if no values of the specified type are present, or if the B<subjectAltName>
extension is not present.

Types can be any of:

   otherName
 * rfc822Name
 * dNSName
   x400Address
   directoryName
   ediPartyName
 * uniformResourceIdentifier
 * iPAddress
 * registeredID

The types marked with '*' are the most common.

If C<$type> is not specified:
 In list context returns the types present in the subjectAlternate name.
 In scalar context, returns the SAN as a string.

=head2 version

Returns the structure version as a string, e.g. "v1" "v2", or "v3"

=head2 pkAlgorithm

Returns the public key algorithm according to its object identifier.

=head2 subjectPublicKey( $format )

If C<$format> is B<true>, the public key will be returned in PEM format.

Otherwise, the public key will be returned in its hexadecimal representation

=head2 signatureAlgorithm

Returns the signature algorithm according to its object identifier.

=head2 signature

The signature will be returned in its hexadecimal representation

=head2 attributes( $name )

A request may contain a set of attributes. The attributes are OIDs with values.
The most common is a list of requested extensions, but other OIDs can also
occur.  Of those, B<challengePassword> is typical.

For API version 0, this method returns a hash consisting of all
attributes in an internal format.  This usage is B<deprecated>.

For API version 1:

If $name is not specified, a list of attribute names is returned.  The list does not
include the requestedExtensions attribute.  For that, use extensions();

If no attributes are present, the empty list (C<undef> in scalar context) is returned.

If $name is specified, the value of the extension is returned.

In scalar context, a single string is returned, which may include lists and labels.

  cspName="Microsoft Strong Cryptographic Provider",keySpec=2,signature=("",0)

Special characters are escaped as described in options.

In array context, the value(s) are returned as a list of items, which may be references.

 print( " $_: ", scalar $decoded->attributes($_), "\n" )
                                   foreach ($decoded->attributes);

=head2 extensions

Returns an array containing the names of all extensions present in the CSR.  If no extensions are present,
the empty list is returned.

The names vary depending on the API version; however, the returned names are acceptable to C<extensionValue>, C<extensionPresent>, and C<name2oid>.

The values of extensions vary, however the following code fragment will dump most extensions and their value(s).

 print( "$_: ", $decoded->extensionValue($_,1), "\n" ) foreach ($decoded->extensions);


The sample code fragment is not guaranteed to handle all cases.
Production code needs to select the extensions that it understands and should respect
the B<critical> boolean.  B<critical> can be obtained with extensionPresent.

=head2 extensionValue( $name, $format )

Returns the value of an extension by name, e.g. C<extensionValue( 'keyUsage' )>.  The name SHOULD be an API v1 name, but API v0 names are accepted for compatibility.

If C<$format> is 1, the value is a formatted string, which may include lists and labels.
Special characters are escaped as described in options;

If C<$format> is 0 or not defined, a string, or an array reference may be returned.
The array many contain any Perl variable type.

To interpret the value(s), you need to know the structure of the OID.

=head2 extensionPresent( $name )

Returns B<true> if a named extension is present:
    If the extension is B<critical>, returns 2.
    Otherwise, returns 1, indicating B<not critical>, but present.

If the extension is not present, returns C<undef>.

=begin readme pod

See the module documentation for a list of known OID names.

=end readme

=for readme stop

The following OID names are known (not all are extensions):

=begin MAINTAINER

 To generate the following table, use:
    perl -Mwarnings -Mstrict -MCrypt::PKCS10 -e'Crypt::PKCS10->_listOIDs'

=end MAINTAINER

 OID                        Name (API v1)              Old Name (API v0)
 -------------------------- -------------------------- ---------------------------
 0.9.2342.19200300.100.1.1  userID
 0.9.2342.19200300.100.1.25 domainComponent
 1.2.840.10040.4.1          dsa                        (DSA)
 1.2.840.10040.4.3          dsaWithSha1                (DSA with SHA1)
 1.2.840.113549.1.1.1       rsaEncryption              (RSA encryption)
 1.2.840.113549.1.1.2       md2WithRSAEncryption       (MD2 with RSA encryption)
 1.2.840.113549.1.1.3       md4WithRSAEncryption
 1.2.840.113549.1.1.4       md5WithRSAEncryption       (MD5 with RSA encryption)
 1.2.840.113549.1.1.5       sha1WithRSAEncryption      (SHA1 with RSA encryption)
 1.2.840.113549.1.1.6       rsaOAEPEncryptionSET
 1.2.840.113549.1.1.7       RSAES-OAEP
 1.2.840.113549.1.1.11      sha256WithRSAEncryption    (SHA-256 with RSA encryption)
 1.2.840.113549.1.1.12      sha384WithRSAEncryption
 1.2.840.113549.1.1.13      sha512WithRSAEncryption    (SHA-512 with RSA encryption)
 1.2.840.113549.1.1.14      sha224WithRSAEncryption
 1.2.840.113549.1.9.1       emailAddress
 1.2.840.113549.1.9.2       unstructuredName
 1.2.840.113549.1.9.7       challengePassword
 1.2.840.113549.1.9.14      extensionRequest
 1.2.840.113549.1.9.15      smimeCapabilities          (SMIMECapabilities)
 1.3.6.1.4.1.311.2.1.14     CERT_EXTENSIONS
 1.3.6.1.4.1.311.2.1.21     msCodeInd
 1.3.6.1.4.1.311.2.1.22     msCodeCom
 1.3.6.1.4.1.311.10.3.1     msCTLSign
 1.3.6.1.4.1.311.10.3.2     msTimeStamping
 1.3.6.1.4.1.311.10.3.3     msSGC
 1.3.6.1.4.1.311.10.3.4     msEFS
 1.3.6.1.4.1.311.10.3.4.1   msEFSRecovery
 1.3.6.1.4.1.311.10.3.5     msWHQLCrypto
 1.3.6.1.4.1.311.10.3.6     msNT5Crypto
 1.3.6.1.4.1.311.10.3.7     msOEMWHQLCrypto
 1.3.6.1.4.1.311.10.3.8     msEmbeddedNTCrypto
 1.3.6.1.4.1.311.10.3.9     msRootListSigner
 1.3.6.1.4.1.311.10.3.10    msQualifiedSubordination
 1.3.6.1.4.1.311.10.3.11    msKeyRecovery
 1.3.6.1.4.1.311.10.3.12    msDocumentSigning
 1.3.6.1.4.1.311.10.3.13    msLifetimeSigning
 1.3.6.1.4.1.311.10.3.14    msMobileDeviceSoftware
 1.3.6.1.4.1.311.13.1       RENEWAL_CERTIFICATE
 1.3.6.1.4.1.311.13.2.1     ENROLLMENT_NAME_VALUE_PAIR
 1.3.6.1.4.1.311.13.2.2     ENROLLMENT_CSP_PROVIDER
 1.3.6.1.4.1.311.13.2.3     OS_Version
 1.3.6.1.4.1.311.20.2       certificateTemplateName
 1.3.6.1.4.1.311.20.2.2     msSmartCardLogon
 1.3.6.1.4.1.311.21.7       certificateTemplate
 1.3.6.1.4.1.311.21.10      ApplicationCertPolicies
 1.3.6.1.4.1.311.21.20      ClientInformation
 1.3.6.1.5.2.3.5            keyPurposeKdc              (KDC Authentication)
 1.3.6.1.5.5.7.2.1          CPS
 1.3.6.1.5.5.7.2.2          userNotice
 1.3.6.1.5.5.7.3.1          serverAuth
 1.3.6.1.5.5.7.3.2          clientAuth
 1.3.6.1.5.5.7.3.3          codeSigning
 1.3.6.1.5.5.7.3.4          emailProtection
 1.3.6.1.5.5.7.3.8          timeStamping
 1.3.6.1.5.5.7.3.9          OCSPSigning
 1.3.6.1.5.5.7.3.21         sshClient
 1.3.6.1.5.5.7.3.22         sshServer
 1.3.6.1.5.5.7.9.5          countryOfResidence
 1.3.14.3.2.29              sha1WithRSAEncryption      (SHA1 with RSA signature)
 2.5.4.3                    commonName
 2.5.4.4                    surname                    (Surname)
 2.5.4.5                    serialNumber
 2.5.4.6                    countryName
 2.5.4.7                    localityName
 2.5.4.8                    stateOrProvinceName
 2.5.4.9                    streetAddress
 2.5.4.10                   organizationName
 2.5.4.11                   organizationalUnitName
 2.5.4.12                   title                      (Title)
 2.5.4.13                   description                (Description)
 2.5.4.14                   searchGuide
 2.5.4.15                   businessCategory
 2.5.4.16                   postalAddress
 2.5.4.17                   postalCode
 2.5.4.18                   postOfficeBox
 2.5.4.19                   physicalDeliveryOfficeName
 2.5.4.20                   telephoneNumber
 2.5.4.23                   facsimileTelephoneNumber
 2.5.4.41                   name                       (Name)
 2.5.4.42                   givenName
 2.5.4.43                   initials
 2.5.4.44                   generationQualifier
 2.5.4.45                   uniqueIdentifier
 2.5.4.46                   dnQualifier
 2.5.4.51                   houseIdentifier
 2.5.4.65                   pseudonym
 2.5.29.14                  subjectKeyIdentifier       (SubjectKeyIdentifier)
 2.5.29.15                  keyUsage                   (KeyUsage)
 2.5.29.17                  subjectAltName
 2.5.29.19                  basicConstraints           (Basic Constraints)
 2.5.29.32                  certificatePolicies
 2.5.29.32.0                anyPolicy
 2.5.29.37                  extKeyUsage                (EnhancedKeyUsage)
 2.16.840.1.101.3.4.2.1     sha256                     (SHA-256)
 2.16.840.1.113730.1.1      netscapeCertType
 2.16.840.1.113730.1.2      netscapeBaseUrl
 2.16.840.1.113730.1.4      netscapeCaRevocationUrl
 2.16.840.1.113730.1.7      netscapeCertRenewalUrl
 2.16.840.1.113730.1.8      netscapeCaPolicyUrl
 2.16.840.1.113730.1.12     netscapeSSLServerName
 2.16.840.1.113730.1.13     netscapeComment
 2.16.840.1.113730.4.1      nsSGC

=for readme continue

=head2 registerOID( )

Class method.

Register a custom OID, or a public OID that has not been added to Crypt::PKCS10 yet.

The OID may be an extension identifier or an RDN component.

The oid is specified as a string in numeric form, e.g. C<'1.2.3.4'>

=head3 registerOID( $oid )

Returns B<true> if the specified OID is registered, B<false> otherwise.

=head3 registerOID( $oid, $longname, $shortname )

Registers the specified OID with the associated long name.
The long name should be Hungarian case (B<commonName>), but this is not currently
enforced.

Optionally, specify the short name used for extracting the subject.
The short name should be upper-case (and will be upcased).

E.g. built-in are C<< $oid => '2.4.5.3', $longname => 'commonName', $shortname => 'CN' >>


Generates an exception if any argument is not valid, or is in use.

Returns B<true> otherwise.

=head2 certificateTemplate

C<CertificateTemplate> returns the B<certificateTemplate> attribute.

Equivalent to C<extensionValue( 'certificateTemplate' )>, which is prefered.

=begin readme pod

=head1 CHANGES

=for readme include file=Changes type=text start=^1\.0

For detailed change listing, see Commitlog.

=end readme

=head1 AUTHORS

Gideon Knocke

Timothe Litt made most of the changes for V1.4

C<Crypt::PKCS10> is based on the generic ASN.1 module by Graham Barr and on the
 x509decode example by Norbert Klasen. It is also based upon the
works of Duncan Segrest's C<Crypt-X509-CRL> module.

=head1 COPYRIGHT

This software is copyright (c) 2014 by Gideon Knocke.

Changes in V1.4 are copyright (C) 2016, Timothe Litt

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

Terms of the Perl programming language system itself

a) the GNU General Public License as published by the Free
   Software Foundation; either version 1, or (at your option) any
   later version, or

b) the "Artistic License"

=cut
