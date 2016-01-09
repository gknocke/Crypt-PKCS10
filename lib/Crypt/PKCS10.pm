#
# Crypt::PKCS10
#
# PKCS #10 certificate request parser
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

use Convert::ASN1;
use MIME::Base64;

our $VERSION = 1.3;

# N.B. Names are exposed in the API.
#      %shortnames follows & depends on (some) values.

my %oids = (
    '2.5.4.6'                       => 'countryName',
    '2.5.4.8'                       => 'stateOrProvinceName',
    '2.5.4.10'                      => 'organizationName',
    '2.5.4.11'                      => 'organizationalUnitName',
    '2.5.4.3'                       => 'commonName',
    '1.2.840.113549.1.9.1'          => 'emailAddress',
    '1.2.840.113549.1.9.2'          => 'unstructuredName',
    '1.2.840.113549.1.9.7'          => 'challengePassword',
    '1.2.840.113549.1.1.1'          => 'RSA encryption',
    '1.2.840.113549.1.1.5'          => 'SHA1 with RSA encryption',
    '1.2.840.113549.1.1.4'          => 'MD5 with RSA encryption',
    '1.2.840.113549.1.9.14'         => 'extensionRequest',
    '1.3.6.1.4.1.311.13.2.3'        => 'OS_Version',
    '1.3.6.1.4.1.311.13.2.2'        => 'EnrollmentCSP',
    '1.3.6.1.4.1.311.21.20'         => 'ClientInformation',
    '1.3.6.1.4.1.311.21.7'          => 'certificateTemplate',
    '2.5.29.37'                     => 'EnhancedKeyUsage',
    '2.5.29.15'                     => 'KeyUsage',
    '1.3.6.1.4.1.311.21.10'         => 'ApplicationCertPolicies',
    '2.5.29.14'                     => 'SubjectKeyIdentifier',
    '2.5.29.17'                     => 'subjectAltName',
    '1.3.6.1.4.1.311.20.2'          => 'certificateTemplateName',
    '2.16.840.1.113730.1.1'         => 'netscapeCertType',
    '2.16.840.1.113730.1.2'         => 'netscapeBaseUrl',
    '2.16.840.1.113730.1.4'         => 'netscapeCaRevocationUrl',
    '2.16.840.1.113730.1.7'         => 'netscapeCertRenewalUrl',
    '2.16.840.1.113730.1.8'         => 'netscapeCaPolicyUrl',
    '2.16.840.1.113730.1.12'        => 'netscapeSSLServerName',
    '2.16.840.1.113730.1.13'        => 'netscapeComment',

    #untested
    '2.5.29.19'                     => 'BasicConstraints',
    '1.2.840.10040.4.1'             => 'DSA',
    '1.2.840.10040.4.3'             => 'DSA with SHA1',
    '0.9.2342.19200300.100.1.25'    => 'domainComponent',
    '0.9.2342.19200300.100.1.1'     => 'userID',
    '2.5.4.7'                       => 'localityName',
    '1.2.840.113549.1.1.11'         => 'SHA-256 with RSA encryption',
    '1.2.840.113549.1.1.13'         => 'SHA-512 with RSA encryption',
    '1.2.840.113549.1.1.2'          => 'MD2 with RSA encryption',
    '1.2.840.113549.1.9.15'         => 'SMIMECapabilities',
    '1.3.14.3.2.29'                 => 'SHA1 with RSA signature',
    '1.3.6.1.4.1.311.13.1'          => 'RENEWAL_CERTIFICATE',
    '1.3.6.1.4.1.311.13.2.1'        => 'ENROLLMENT_NAME_VALUE_PAIR',
    '1.3.6.1.4.1.311.13.2.2'        => 'ENROLLMENT_CSP_PROVIDER',
    '1.3.6.1.4.1.311.2.1.14'        => 'CERT_EXTENSIONS',
    '1.3.6.1.5.2.3.5'               => 'KDC Authentication',
    '1.3.6.1.5.5.7.9.5'             => 'countryOfResidence',
    '2.16.840.1.101.3.4.2.1'        => 'SHA-256',
    '2.5.4.12'                      => 'Title',
    '2.5.4.13'                      => 'Description',
    '2.5.4.17'                      => 'postalCode',
    '2.5.4.4'                       => 'Surname',
    '2.5.4.41'                      => 'Name',
    '2.5.4.42'                      => 'givenName',
    '2.5.4.43'                      => 'initials',
    '2.5.4.44'                      => 'generationQualifier',
    '2.5.4.45'                      => 'uniqueIdentifier',
    '2.5.4.46'                      => 'dnQualifier',
    '2.5.4.5'                       => 'serialNumber',
);

my %oid2extkeyusage = (
                '1.3.6.1.5.5.7.3.1' => 'serverAuth',
                '1.3.6.1.5.5.7.3.2' => 'clientAuth',
                '1.3.6.1.5.5.7.3.3' => 'codeSigning',
                '1.3.6.1.5.5.7.3.4' => 'emailProtection',
                '1.3.6.1.5.5.7.3.8' => 'timeStamping',
                '1.3.6.1.5.5.7.3.9' => 'OCSPSigning',
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
);


# registerOID( $oid ) => true if $oid is registered, false if not
# registerOID( $oid, $longname ) => Register an OID with its name
# registerOID( $oid, $longname, $shortname ) => Register an OID with an abbreviation for RDNs.

sub registerOID {
    my( $class, $oid, $longname, $shortname ) = @_;

    return exists $oids{$oid} if( @_ == 2 && defined $oid );

    croak( "Not enough arguments" )          unless( @_ >= 3 && defined $oid && defined $longname );
    croak( "Invalid oid $oid" )              unless( defined $oid && $oid =~ /^\d+(?:\.\d+)*$/ );
    croak( "$oid already registered" )       if( exists $oids{$oid} );
    croak( "$longname already registered" )  if( grep /^$longname$/, values %oids );
    croak( "$shortname already registered" ) if( defined $shortname && grep /^\U$shortname\E$/, values %shortnames );

    $oids{$oid} = $longname;
    $shortnames{$longname} = uc $shortname   if( defined $shortname );
    return 1;
}

sub new {
    my $class  = shift;
    my $der = shift;

    my $parser = _init();

    if($der =~ /^-----BEGIN\s(?:NEW\s)?CERTIFICATE\sREQUEST-----\s(.*)\s-----END\s(?:NEW\s)?CERTIFICATE\sREQUEST-----$/ms) { #if PEM, convert to DER
        $der = decode_base64($1);
    }

    use bytes;
    #some Requests may contain information outside of the regular ASN.1 structure. These parts need to be stripped of
    my $substr = substr( $der, 0, unpack("n*", substr($der, 2, 2)) + 4 );
    no bytes;

    my $self = { _der => $substr };
    bless( $self, $class );

    my $top =
	$parser->decode($substr) or confess "decode: ", $parser->error, "Cannot handle input or missing ASN.1 definitons";

    $self->{'certificationRequestInfo'}{'subject'}
        = $self->_convert_rdn( $top->{'certificationRequestInfo'}{'subject'} );

    $self->{'certificationRequestInfo'}{'version'}
        = $top->{'certificationRequestInfo'}{'version'};

    $self->{'certificationRequestInfo'}{'attributes'} = $self->_convert_attributes(
        $top->{'certificationRequestInfo'}{'attributes'} );

    $self->{_pubkey} = "-----BEGIN PUBLIC KEY-----\n" .
      encode_base64( $parser->find('SubjectPublicKeyInfo')->encode( $top->{'certificationRequestInfo'}{'subjectPKInfo'} ) ) .
	"-----END PUBLIC KEY-----\n";
    $self->{'certificationRequestInfo'}{'subjectPKInfo'} = $self->_convert_pkinfo(
        $top->{'certificationRequestInfo'}{'subjectPKInfo'} );

    $self->{'signature'} = $top->{'signature'};

    $self->{'signatureAlgorithm'}
        = $self->_convert_signatureAlgorithm( $top->{'signatureAlgorithm'} );

    return $self;
}

sub _convert_signatureAlgorithm {
    my $self = shift;

    my $signatureAlgorithm = shift;
    $signatureAlgorithm->{'algorithm'}
        = $oids{ $signatureAlgorithm->{'algorithm'}} if(defined $signatureAlgorithm->{'algorithm'});

    if ($signatureAlgorithm->{'parameters'}{'undef'}) {
        delete ($signatureAlgorithm->{'parameters'});
    }
    return $signatureAlgorithm;
}

sub _convert_pkinfo {
    my $self = shift;

    my $pkinfo = shift;

    $pkinfo->{'algorithm'}{'algorithm'}
        = $oids{ $pkinfo->{'algorithm'}{'algorithm'}};
    if ($pkinfo->{'algorithm'}{'parameters'}{'undef'}) {
        delete ($pkinfo->{'algorithm'}{'parameters'});
    }
    return $pkinfo;
}

sub _convert_attributes {
    my $self = shift;

    my $typeandvalues = shift;
    foreach my $entry ( @{$typeandvalues} ) {
         if (defined $oids{ $entry->{'type'}}) {
            $entry->{'type'} = $oids{ $entry->{'type'} };
            my $parser = _init($entry->{'type'}) or confess "Parser error: ", $entry->{'type'}, " needs entry in ASN.1 definition";

            if ($entry->{'type'} eq 'extensionRequest') {
                $entry->{'values'} = $self->_convert_extensionRequest($entry->{'values'}[0]);
            }
            else {
                if($entry->{'values'}->[1]) {confess "Incomplete parsing of attribute type: ", $entry->{'type'};}
                $entry->{'values'} = $parser->decode($entry->{'values'}->[0]) or confess "Looks like damaged input";
            }
         }
    }
    return $typeandvalues;
}

sub _convert_extensionRequest {
    my $self = shift;

    my $extensionRequest = shift;
    my $parser = _init('extensionRequest');
    my $decoded = $parser->decode($extensionRequest) or return [];
    foreach my $entry (@{$decoded}) {
	my $name = $oids{ $entry->{'extnID'} };
        if (defined $name) {
            my $parser = _init($name);
            if(!$parser) {
                $entry = undef;
                next;
            }
            $entry->{'extnID'} = $name;
            $entry->{'extnValue'} = $parser->decode($entry->{'extnValue'}) or confess $parser->error, ".. looks like damaged input";
            $entry->{'extnValue'} = $self->_mapExtensions($name, $entry->{'extnValue'});
        }
    }
    @{$decoded} = grep { defined } @{$decoded};
    return $decoded;
}

sub _mapExtensions {
    my $self = shift;

    my $id =shift;
    my $value = shift;
    if ($id =~ /^(KeyUsage|netscapeCertType)$/) {
        my $bit =  unpack('C*', @{$value}[0]); #get the decimal representation
        my $length = int(log($bit) / log(2) + 1); #get its bit length
        my @usages = reverse( $1 eq 'KeyUsage'? # Following are in order from bit 0 upwards
			      qw(digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement keyCertSign cRLSign encipherOnly decipherOnly) :
			      qw(client server email objsign reserved sslCA emailCA objCA) );
        my $shift = ($#usages + 1) - $length; # computes the unused area in @usages
        $value = join ", ", @usages[ grep { $bit & (1 << $_ - $shift) } 0 .. $#usages ]; #transfer bitmap to barewords
    } elsif ($id eq 'EnhancedKeyUsage') {
        foreach (@{$value}) {
            $_ = $oid2extkeyusage{$_} if(defined $oid2extkeyusage{$_});
        }
    } elsif ($id eq 'SubjectKeyIdentifier') {
        $value = (unpack "H*", $value);
    } elsif ($id eq 'ApplicationCertPolicies') {
        foreach my $entry (@{$value}) {
            $entry->{'policyIdentifier'} = $oid2extkeyusage{$entry->{'policyIdentifier'}} if(defined $oid2extkeyusage{$entry->{'policyIdentifier'}});
        }
    } elsif( $id eq 'BasicConstraints' ) {
	my $string = sprintf( 'CA:%s', ($value->{cA}? 'TRUE' : 'FALSE') );
	$string .= sprintf( ',pathlen:%d', $value->{pathLenConstraint} ) if( exists $value->{pathLenConstraint} );
	$value = $string;
    } elsif (ref $value->[0] eq 'HASH') {
	foreach my $entry (@{$value}) {
	    if( exists $entry->{iPAddress} ) {
		use bytes;
		my $addr = $entry->{iPAddress};
		if( length $addr == 4 ) {
		    $entry->{iPAddress} = sprintf( '%vd', $addr );
		} else {
		    $addr = sprintf( '%*v02X', ':', $addr );
		    $addr =~ s/([[:xdigit:]]{2}):([[:xdigit:]]{2})/$1$2/g;
		    $entry->{iPAddress} = $addr;
		}
	    }
	}
    }
    return $value
}


sub _convert_rdn {
    my $self = shift;
    my $typeandvalue = shift;
    my %hash;
    foreach my $entry ( @$typeandvalue ) {
	foreach my $item (@$entry) {
	    my $name = $oids{ $item->{'type'} };
	    if( defined $name ) {
		push @{$hash{$name}}, values %{$item->{'value'}};
		push @{$hash{_subject}}, $name, [ values %{$item->{'value'}} ];
		unless( $self->can( $name ) ) {
		    no strict 'refs';
		    *$name =  sub {
			my $self = shift;
			return @{ $self->{'certificationRequestInfo'}{'subject'}{$name} } if( wantarray );
			return $self->{'certificationRequestInfo'}{'subject'}{$name}->[0] || '';
		    }
		}
	    }
	}
    }

    return \%hash;
}

sub _init {
    my $node = shift;
    if ( !defined $node ) { $node = 'CertificationRequest' }
    my $asn = Convert::ASN1->new;
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

    ClientInformation ::= SEQUENCE {
        ClientID    INTEGER,
        User        UTF8String,
        Machine     UTF8String,
        Process     UTF8String}

    extensionRequest ::= SEQUENCE OF Extension
    Extension ::= SEQUENCE {
      extnID    OBJECT IDENTIFIER,
      critical  BOOLEAN OPTIONAL,
      extnValue OCTET STRING}

    SubjectKeyIdentifier ::= OCTET STRING

    certificateTemplate ::= SEQUENCE {
       templateID              OBJECT IDENTIFIER,
       templateMajorVersion    INTEGER,
       templateMinorVersion    INTEGER OPTIONAL}

    EnhancedKeyUsage ::= SEQUENCE OF OBJECT IDENTIFIER
    KeyUsage ::= BIT STRING
    netscapeCertType ::= BIT STRING

    ApplicationCertPolicies ::= SEQUENCE OF PolicyInformation

    PolicyInformation ::= SEQUENCE {
        policyIdentifier   OBJECT IDENTIFIER,
        policyQualifiers   SEQUENCE OF PolicyQualifierInfo OPTIONAL}

    PolicyQualifierInfo ::= SEQUENCE {
       policyQualifierId    OBJECT IDENTIFIER,
       qualifier            ANY}

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

    my $parsed = $asn->find($node);
    return $parsed;
}

###########################################################################
# interface methods

sub csrRequest {
    my $self = shift;
    my $format = shift;

    return "-----BEGIN CERTIFICATE REQUEST-----\n" .
      encode_base64( $self->{_der} ) . "-----END CERTIFICATE REQUEST-----\n" if( $format );

    return $self->{_der};
}

# Common subject components documented to be always present:

foreach my $component (qw/commonName organizationalUnitName organizationName
                          emailAddress stateOrProvinceName countryName domainComponent/ ) {
    no strict 'refs';

    unless( defined &$component ) {
	*$component = sub {
	    my $self = shift;
	    return @{ $self->{'certificationRequestInfo'}{'subject'}{$component} || [] } if( wantarray );
	    return $self->{'certificationRequestInfo'}{'subject'}{$component}->[0] || '';
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
    unless( defined $san && defined $type ) {
	return () if( wantarray );
	return undef;
    }

    my $result = [ map { $_->{$type} } grep { exists $_->{$type} } @$san ];

    return @$result if( wantarray );
    return $result->[0];
}

sub version {
    my $self = shift;
    my $v = $self->{'certificationRequestInfo'}{'version'};
    return sprintf( "v%u", $v+1 );
}

sub pkAlgorithm {
    my $self = shift;
    return $self->{'certificationRequestInfo'}{'subjectPKInfo'}{'algorithm'}{'algorithm'};
}

sub subjectPublicKey {
    my $self = shift;
    my $format = shift;

    return $self->{_pubkey} if( $format );
    return unpack('H*', $self->{'certificationRequestInfo'}{'subjectPKInfo'}{'subjectPublicKey'}->[0]);
}

sub signatureAlgorithm {
    my $self = shift;
    return $self->{'signatureAlgorithm'}{'algorithm'};
}

sub signature {
    my $self = shift;
    unpack('H*', $self->{'signature'}->[0]);
}

sub attributes {
    my $self = shift;
    my $attributes = $self->{'certificationRequestInfo'}{'attributes'};
    return () unless( defined $attributes );

    my %hash = map { $_->{'type'} => $_->{'values'} }
        @{$attributes};
    return %hash;
}

sub certificateTemplate {
    my $self = shift;
    my %attributes = attributes($self);
    my $template;
    return undef unless( exists $attributes{'extensionRequest'} );
    my @space = @{$attributes{'extensionRequest'}};
    foreach my $entry (@space) {
        if ($entry->{'extnID'} eq 'certificateTemplate') {
            $template = $entry->{'extnValue'};
        }
    }
    return $template;
}

sub extensionValue {
    my $self = shift;
    my $extensionName = shift;
    my %attributes = attributes($self);
    my $value;
    return undef unless( exists $attributes{'extensionRequest'} );
    my @space = @{$attributes{'extensionRequest'}};
    foreach my $entry (@space) {
        if ($entry->{'extnID'} eq $extensionName) {
            $value = $entry->{'extnValue'};
            # reduce the hash items to the scalar value #??
            while (ref $value eq 'HASH') {
                my @keys = keys %{$value};
                $value = $value->{ shift @keys } ;
            }
	    last;
        }
    }
    return $value;
}

sub extensionPresent {
    my $self = shift;
    my $extensionName = shift;
    my %attributes = attributes($self);
    my $value;
    return undef unless( exists $attributes{'extensionRequest'} );
    my @space = @{$attributes{'extensionRequest'}};
    foreach my $entry (@space) {
        if ($entry->{'extnID'} eq $extensionName) {
	    return 2 if ($entry->{critical});
	    return 1;
        }
    }
    return undef;
}

1;

__END__

=pod

=head1 NAME

Crypt::PKCS10 - parse PKCS #10 certificate requests

=head1 SYNOPSIS

    use Crypt::PKCS10;

    my $decoded = Crypt::PKCS10->new( $csr );
    my $subject = $decoded->subject;

=head1 REQUIRES

Convert::ASN1

=head1 DESCRIPTION

Crypt::PKCS10 parses PKCS #10 requests and provides accessor methods to extract the requested data.
First, the request will be parsed using the included ASN.1 definition. Common object identifiers will be translated to their corresponding names.
Additionally, accessor methods allow to extract single data fields. Bit Strings like signatures will be printed in their hexadecimal representation.

The access methods return the value corresponding to their name.  If called in scalar context, they return the first value (or an empty string).  If called in array context, they return all values.

=head1 METHODS

Access methods may exist for subject name components that are not listed here.  To test for these, use code of the form:

  $locality = $decoded->localityName if( $decoded->can('localityName') );

If a component exists, the method will be present.  The converse is not (always) true.

=head2 new

Constructor, creates a new object containing the parsed PKCS #10 request. It takes the request itself as an argument. PEM and DER encoding is supported.

    use Crypt::PKCS10;
    my $decoded = Crypt::PKCS10->new( $csr );

=head2 csrRequest( $format )

Returns the binary (ASN.1) request (after conversion from PEM and removal of any data beyond the length of the ASN.1 structure.

If $format is true, the request is returned as a PEM CSR.  Otherwise as a binary string.

=head2 commonName

Returns the common name as stored in the request.

    my $cn = $decoded->commonName();

=head2 organizationalUnitName

Returns the organizational unit name.

=head2 organizationName

Returns the organization name.

=head2 emailAddress

Returns the email address.

=head2 stateOrProvinceName

Returns the state or province name.

=head2 countryName

Returns the country name.

=head2 subject(format)

Returns the subject of the CSR.

In scalar context, returns the subject as a string in the form /componentName=value,value.
  If format is true, long component names are used.  By default, abbreviations are used when known.

  e.g. /countryName=AU/organizationalUnitName=Big org/organizationalUnitName=Smaller org
  or     /C=AU/OU=Big org/OU=Smaller org

In array context, returns an array of (componentName, [values]) pairs.  Abbreviations are not used.

Note that the order of components in a name is significant.

=head2 subjectAltName($type)

Convenience method.

Returns the subject alternate name values of the specified type in list context, or the first value
of the specified type in scalar context.

Returns undefined/empty list if no values of the specified type are present, or if the subjectAltName
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

=head2 version

Returns the structure version as a string, e.g. "v1" "v2", or "v3"

=head2 pkAlgorithm

Returns the public key algorithm according to its object identifier.

=head2 subjectPublicKey( $format )

If $format is true, the public key will be returned in PEM format.

Otherwise, the public key will be returned in its hexadecimal representation

=head2 signatureAlgorithm

Returns the signature algorithm according to its object identifier.

=head2 signature

The signature will be returned in its hexadecimal representation

=head2 attributes

A request may contain a set of attributes. This method returns a reference to a hash consisting of all attributes.

    %attributes = $decoded->attributes;
    print Dumper(\%attributes);

=head2 extensionValue

Returns the value of an extension by name, e.g. extensionValue( 'KeyUsage' )

=head2 extensionPresent

Returns true if a named extension is present:
    If the extension is 'critical', returns 2.
    Otherwise, returns 1 not 'critical', but present.

If the extension is not present, returns undef.

The following OID names are known (not all are extensions):

 countryName
 stateOrProvinceName
 organizationName
 organizationalUnitName
 commonName
 emailAddress
 unstructuredName
 challengePassword
 RSA encryption
 SHA1 with RSA encryption
 MD5 with RSA encryption
 extensionRequest
 OS_Version
 EnrollmentCSP
 ClientInformation
 certificateTemplate
 EnhancedKeyUsage
 KeyUsage
 netscapeCertType
 netscapeBaseURL
 netscapeCaRevocationUrl
 netscapeCertRenewalUrl
 netscapeCaPolicyUrl
 netscapeSSLServerName
 netscapeComment
 ApplicationCertPolicies
 SubjectKeyIdentifier
 subjectAltName
 certificateTemplateName
 BasicConstraints
 DSA
 DSA with SHA1
 domainComponent
 localityName
 SHA-256 with RSA encryption
 SHA-512 with RSA encryption
 MD2 with RSA encryption
 SMIMECapabilities
 SHA1 with RSA signature
 RENEWAL_CERTIFICATE
 ENROLLMENT_NAME_VALUE_PAIR
 ENROLLMENT_CSP_PROVIDER
 CERT_EXTENSIONS
 KDC Authentication
 countryOfResidence
 SHA-256
 Title
 Description
 postalCode
 Surname
 Name
 givenName
 initials
 generationQualifier
 uniqueIdentifier
 userID
 dnQualifier
 serialNumber

=head2 registerOID

Class method.

Register a custom OID, or a public OID that has not been added to Crypt::PKCS10 yet.

The OID may be an extension identifier or an RDN component.

The oid is specified as a string in numeric form, e.g. '1.2.3.4'

=head3 registerOID( $oid )

Returns true if the specified OID is registered, false otherwise.

=head3 registerOID( $oid, $longname, $shortname )

Registers the specified OID with the associated long name.
The long name should be Hungarian case (commonName), but this is not currently
enforced.

Optionally, specify the short name used for extracting the subject.
The short name should be upper-case (and will be upcased).

E.g. built-in are $oid => '2.4.5.3', $longname => 'commonName', $shortname => 'CN'


Generates an exception if any argument is not valid, or is in use.

Returns true otherwise.

=head2 certificateTemplate

CertificateTemplate is an attribute widely used by Windows certification authorities.

=head1 AUTHORS

Gideon Knocke

=head1 COPYRIGHT

This software is copyright (c) 2014 by Gideon Knocke.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

Terms of the Perl programming language system itself

a) the GNU General Public License as published by the Free
   Software Foundation; either version 1, or (at your option) any
   later version, or

b) the "Artistic License"

=cut
