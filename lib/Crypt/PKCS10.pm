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

use Exporter;
use Convert::ASN1 qw(:all);
use MIME::Base64;

our @EXPORT  = qw();
our @ISA     = qw(Exporter);
our $VERSION = 0.1;

my %oids = (
    '2.5.4.6'              => 'countryName',
    '2.5.4.8'              => 'stateOrProvinceName',
    '2.5.4.10'             => 'organizationName',
    '2.5.4.11'             => 'organizationalUnitName',
    '2.5.4.3'              => 'commonName',
    '1.2.840.113549.1.9.1' => 'emailAddress',
    '1.2.840.113549.1.9.2' => 'unstructuredName',
    '1.2.840.113549.1.9.7' => 'challengePassword',
    '1.2.840.113549.1.1.1' => 'RSA encryption',
    '1.2.840.113549.1.1.5' => 'SHA1 with RSA encryption',
    '1.2.840.113549.1.1.4' => 'MD5 with RSA encryption',
    '1.2.840.113549.1.9.14' => 'extensionRequest',
    '1.3.6.1.4.1.311.13.2.3' => 'OS_Version',
    '1.3.6.1.4.1.311.13.2.2' => 'EnrollmentCSP',
    '1.3.6.1.4.1.311.21.20' => 'ClientInformation',
    '1.3.6.1.4.1.311.21.7' => 'certificateTemplate',
    '2.5.29.37'            => 'EnhancedKeyUsage',
    '2.5.29.15'            => 'KeyUsage',
    '1.3.6.1.4.1.311.21.10' => 'ApplicationCertPolicies',
    '2.5.29.14'             => 'SubjectKeyIdentifier',
    '2.5.29.17'             => 'subjectAltName',
    '1.3.6.1.4.1.311.20.2'  => 'certificateTemplateName',
    #untested
    '2.5.29.19'                     => 'Basic Constraints',#ASN
    '1.2.840.10040.4.1'             => 'DSA',
    '1.2.840.10040.4.3'             => 'DSA with SHA1',
    '0.9.2342.19200300.100.1.25'    => 'domainComponent',
    '2.5.4.7'                       => 'localityName', #ASN
    '1.2.840.113549.1.1.11'         => 'SHA-256 with RSA encryption',
    '1.2.840.113549.1.1.13'         => 'SHA-512 with RSA encryption',
    '1.2.840.113549.1.1.2'          => 'MD2 with RSA encryption',
    '1.2.840.113549.1.9.15'         => 'SMIMECapabilities', #ASN
    '1.3.14.3.2.29'                 => 'SHA1 with RSA signature',
    '1.3.6.1.4.1.311.13.1'          => 'RENEWAL_CERTIFICATE', #MS
    '1.3.6.1.4.1.311.13.2.1'        => 'ENROLLMENT_NAME_VALUE_PAIR', #MS
    '1.3.6.1.4.1.311.13.2.2'        => 'ENROLLMENT_CSP_PROVIDER', #MS
    '1.3.6.1.4.1.311.2.1.14'        => 'CERT_EXTENSIONS', #MS
    '1.3.6.1.5.2.3.5'               => 'KDC Authentication',
    '1.3.6.1.5.5.7.9.5'             => 'countryOfResidence',
    '2.16.840.1.101.3.4.2.1'        => 'SHA-256',
    '2.5.4.12'                      => 'Title', #ASN
    '2.5.4.13'                      => 'Description', #ASN
    '2.5.4.17'                      => 'postalCode', #ASN
    '2.5.4.4'                       => 'Surname', #ASN
    '2.5.4.41'                      => 'Name', #ASN
    '2.5.4.42'                      => 'givenName', #ASN
    '2.5.4.46'                      => 'dnQualifier', #ASN
    '2.5.4.12'                      => 'serialNumber', #ASN    
);

my %oid2extkeyusage = (
                        '1.3.6.1.5.5.7.3.1' => 'serverAuth',
                        '1.3.6.1.5.5.7.3.2' => 'clientAuth',
                        '1.3.6.1.5.5.7.3.3' => 'codeSigning',
                        '1.3.6.1.5.5.7.3.4' => 'emailProtection',
                        '1.3.6.1.5.5.7.3.8' => 'timeStamping',
                        '1.3.6.1.5.5.7.3.9' => 'OCSPSigning',
);

sub new {
    my $class  = shift;
    my $der = shift;

    my $parser = _init();

    if($der =~ /^\W+\w+\s+\w+\s+\w+\W+\s(.*)\s+\W+.*$/s) { #if PEM, convert to DER
        $der = decode_base64($1);
    }
    #comment in if you get parser errors
    #asn_dump($der);

    use bytes;
    #some Requests may contain information outside of the regular ASN.1 structure. These parts need to be stripped of
    my $i = unpack("n*", substr($der, 2, 2)) + 4;
    my $substr = substr $der, 0, $i;
    no bytes;

    my $self = {};
    bless( $self, $class );

    my $top =
	$parser->decode($substr) or confess "decode: ", $parser->error, "Cannot handle input or missing ASN.1 definitons";

    $self->{'certificationRequestInfo'}->{'subject'}
        = $self->_convert_rdn( $top->{'certificationRequestInfo'}->{'subject'} );

    $self->{'certificationRequestInfo'}->{'version'}
        = $top->{'certificationRequestInfo'}->{'version'};

    $self->{'certificationRequestInfo'}->{'attributes'} = $self->_convert_attributes(
        $top->{'certificationRequestInfo'}->{'attributes'} );

    $self->{'certificationRequestInfo'}->{'subjectPKInfo'} = $self->_convert_pkinfo(
        $top->{'certificationRequestInfo'}->{'subjectPKInfo'} );

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
  
    if ($signatureAlgorithm->{'parameters'}->{'undef'}) {
        delete ($signatureAlgorithm->{'parameters'});
    }
    return $signatureAlgorithm;
}

sub _convert_pkinfo {
    my $self = shift;

    my $pkinfo = shift;
    $pkinfo->{'algorithm'}->{'algorithm'}
        = $oids{ $pkinfo->{'algorithm'}->{'algorithm'}};
    if ($pkinfo->{'algorithm'}->{'parameters'}->{'undef'}) {
        delete ($pkinfo->{'algorithm'}->{'parameters'});
    }   
    return $pkinfo;
}

sub _convert_attributes {
    my $self = shift;

    my $typeandvalues = shift;
    foreach my $entry ( @{$typeandvalues} ) {
         if (defined $oids{ $entry->{'type'}}) {
            $entry->{'type'} = $oids{ $entry->{'type'} };
            my $parser = _init($entry->{'type'}) or confess "Parser error: ", $entry->{'type'}, " needs entry in ASN.1 definition!";

            if ($entry->{'type'} eq 'extensionRequest') { #extensionRequest need a new layer
                #In case the DER representation of 'extensionRequest' is needed. works for each attribute.          
                $entry->{'values'} = $self->_convert_extensionRequest($entry->{'values'}[0]);
            }
            else {
                #maybe there can be more than one value, haven't seen jet. 
                if($entry->{'values'}->[1]) {confess "Incomplete parsing of attribute type: ", $entry->{'type'};}
                $entry->{'values'} = $parser->decode($entry->{'values'}->[0]) or confess ".. looks like damaged input";
            }
         }    
    }
    return $typeandvalues;
}

sub _convert_extensionRequest {
    my $self = shift;

    my $extensionRequest = shift;
    my $parser = _init('extensionRequest');
    my $decoded = $parser->decode($extensionRequest) or confess $parser->error, ".. looks like damaged input";
    foreach my $entry (@{$decoded}) {        
        if (defined $oids{ $entry->{'extnID'}}) {
            $entry->{'extnID'} = $oids{ $entry->{'extnID'} };
            my $parser = _init($entry->{'extnID'}) or confess "parser error: ", $entry->{'extnID'}, " needs entry in ASN.1 definition!";
            $entry->{'extnValue'} = $parser->decode($entry->{'extnValue'}) or confess $parser->error, ".. looks like damaged input";
            
            #extension specific mapping
            $entry->{'extnValue'} = $self->_mapExtensions($entry->{'extnID'}, $entry->{'extnValue'});
        }
    }
    return $decoded;
}

sub _mapExtensions {
    my $self = shift;

    my $id =shift;
    my $value = shift;
    if ($id eq 'KeyUsage') {
        #cannot see an easier way for this stupid task
        my $bit =  unpack('C*', @{$value}[0]); #get the decimal representation
        my $length = int(log($bit) / log(2) + 1); # some algebra to get the bit length
        my @usages = reverse(qw(digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement keyCertSign cRLSign encipherOnly decipherOnly));
        my $shift = ($#usages + 1) - $length; # computes the area we dont need in @usages
        $value = join ", ", @usages[ grep { $bit & (1 << $_ - $shift) } 0 .. $#usages ]; # ugly hack to transfer bitmap to barewords
    }
    if ($id eq 'EnhancedKeyUsage') {
        foreach (@{$value}) {
            $_ = $oid2extkeyusage{$_} if(defined $oid2extkeyusage{$_});
        }       
    }
    if ($id eq 'SubjectKeyIdentifier') {
        $value = (unpack "H*", $value);
    }
    if ($id eq 'ApplicationCertPolicies') {
        foreach(@{$value}) {
            $_->{'policyIdentifier'} = $oid2extkeyusage{$_->{'policyIdentifier'}} if(defined $oid2extkeyusage{$_->{'policyIdentifier'}});
        }       
    }
    return $value
}


sub _convert_rdn {
    my $self = shift;

    my $typeandvalue = shift;
    my %hash;
    foreach my $entry ( @{$typeandvalue}) {
        if (defined $oids{ $entry->[0]->{'type'}}) {
            $hash{ $oids{ $entry->[0]->{'type'} } } = $entry->[0]->{'value'};
        }
    }
    return \%hash;
}

sub _init {
    my $node = shift;
    if ( !defined $node ) { $node = 'CertificationRequest' }
    my $asn = Convert::ASN1->new;
    $asn->prepare(<<ASN1);
    
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

sub commonName {
    my $self = shift;
    return $self->{'certificationRequestInfo'}->{'subject'}->{'commonName'}
        {'utf8String'} || '';
}

sub organizationalUnitName {
    my $self = shift;
    return $self->{'certificationRequestInfo'}->{'subject'}->{'organizationalUnitName'}->{'utf8String'} || '';
}


###########################################################################
# interface methods

sub emailAddress {
    my $self = shift;
    return $self->{'certificationRequestInfo'}->{'subject'}->{'emailAddress'}
        {'ia5String'} || '';
}

sub stateOrProvinceName {
    my $self = shift;
    return $self->{'certificationRequestInfo'}->{'subject'}->{'stateOrProvinceName'}->{'utf8String'} || '';
}

sub countryName {
    my $self = shift;
    return $self->{'certificationRequestInfo'}->{'subject'}->{'countryName'}->{'printableString'} || '';
}

sub version {
    my $self = shift;
    my $v    = $self->{'certificationRequestInfo'}->{'version'};
    return "v1" if $v == 0;
    return "v2" if $v == 1;
    return "v3" if $v == 2;
}

sub pkAlgorithm {
    my $self = shift;
    return $self->{'certificationRequestInfo'}->{'subjectPKInfo'}->{'algorithm'}->{'algorithm'};
}

sub subjectPublicKey {
    my $self = shift;
    return unpack('H*', $self->{'certificationRequestInfo'}->{'subjectPKInfo'}->{'subjectPublicKey'}->[0]);
}

sub signatureAlgorithm {
    my $self = shift;
    return $self->{'signatureAlgorithm'}->{'algorithm'};
}

sub signature {
    my $self = shift;
    unpack('H*', $self->{'signature'}->[0]);
}

sub attributes {
    my $self       = shift;
    my $attributes = $self->{'certificationRequestInfo'}->{'attributes'};
    my %hash = map { $_->{'type'} => $_->{'values'} }
        @{$attributes};
    return %hash;
}

sub certificateTemplate {
    my $self = shift;
    my %attributes = attributes($self);
    my $template;
    my @space = @{$attributes{'extensionRequest'}};
    foreach my $entry (@space) {
        if ($entry->{'extnID'} eq 'certificateTemplate') {
            $template = $entry->{'extnValue'};
        }
    }
    return $template; 
}

1;

__END__

=head1 NAME

Crypt::PKCS10 - parse PKCS #10 certificate requests

=head1 SYNOPSIS

    use Crypt::PKCS10;

    my $decoded = Crypt::PKCS10->new( $csr );
    my $cn = $decoded->commonName();

=head1 REQUIRES

Convert::ASN1

=head1 DESCRIPTION

Crypt::PKCS10 parses PKCS #10 requests and provides accessor methods to extract the requested data.
First, the request will be parsed using the included ASN.1 definition. Common object identifiers will be translated to their corresponding names.
Additionally, accessor methods allow to extract single data fields. Bit Strings like signatures will be printed in their hexadecimal representation.

=head1 METHODS

=head2 new

Constructor, creates a new object containing the parsed PKCS #10 request. It takes the request itself as an argument. PEM and DER encoding is supported.

    use Crypt::PKCS10;
    my $decoded = Crypt::PKCS10->new( $csr );

=head2 commonName

Returns the common name as stored in the request.

    my $cn = $decoded->commonName();

=head2 organizationalUnitName

Returns the organizational unit name.

=head2 emailAddress

Returns the email address.

=head2 stateOrProvinceName

Returns the state or province name.

=head2 countryName

Returns the country name.

=head2 version

The version is stored as an Integer where 0 means 'v1'. Note, there is an offset by one!

=head2 pkAlgorithm

Returns the public key algorithm according to its object identifier.

=head2 subjectPublicKey

The public key will be returned in its hexadecimal representation

=head2 signatureAlgorithm

Returns the signature algorithm according to its object identifier.

=head2 signature

The signature will be returned in its hexadecimal representation

=head2 attributes

A request may contain a set of attributes. This method returns a reference to a hash consisting of all attributes.

    %attributes = $decoded->attributes;
    print Dumper(\%attributes);
    
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
