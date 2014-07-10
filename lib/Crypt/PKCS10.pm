package Crypt::PKCS10;

use strict;
use warnings;
use Exporter;
use Convert::ASN1 qw(:debug);
use MIME::Base64;
use Data::Dumper;
$Data::Dumper::Useqq = 1;

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
    '1.2.840.113549.1.1.5' => 'SHA-1 with RSA Encryption',
    '1.2.840.113549.1.9.14' => 'extensionRequest',
    '1.3.6.1.4.1.311.13.2.3' => 'OS_Version',
    '1.3.6.1.4.1.311.13.2.2' => 'EnrollmentCSP',
    '1.3.6.1.4.1.311.21.20' => 'ClientInformation',
    '1.3.6.1.4.1.311.21.7' => 'certificateTemplate',
    '2.5.29.37'			   => 'EnhancedKeyUsage',
    '2.5.29.15' 		   => 'KeyUsage',
    '1.3.6.1.4.1.311.21.10' => 'ApplicationCertPolicies',
    '2.5.29.14' 		    => 'SubjectKeyIdentifier',
    '2.5.29.17'             => 'subjectAltName',
    '1.3.6.1.4.1.311.20.2'  => 'certificateTemplateName'
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
    my $parser = _init();
    my $der = shift;

    if($der =~ /^\W+\w+\s+\w+\s+\w+\W+\s(.*)\s+\W+.*$/s) { #if PEM, convert to DER
        $der = decode_base64($1);
    }

    my $self   = $parser->decode($der) or die "decode: ", $parser->error, "Cannot handle input or missing ASN.1 definitons";
    my $req->{'certificationRequestInfo'}{'subject'}
        = convert_rdn( $self->{'certificationRequestInfo'}{'subject'} );
    $req->{'certificationRequestInfo'}{'version'}
        = $self->{'certificationRequestInfo'}{'version'};
    $req->{'certificationRequestInfo'}{'attributes'} = convert_attributes(
        $self->{'certificationRequestInfo'}{'attributes'} );
    $req->{'certificationRequestInfo'}{'subjectPKInfo'} = convert_pkinfo(
        $self->{'certificationRequestInfo'}{'subjectPKInfo'} );
    $req->{'signature'} = $self->{'signature'};
    $req->{'signatureAlgorithm'}
        = convert_signatureAlgorithm( $self->{'signatureAlgorithm'} );
    bless( $req, $class );
    return $req;
}

sub convert_signatureAlgorithm {
    my $signatureAlgorithm = shift;
    $signatureAlgorithm->{'algorithm'}
        = $oids{ $signatureAlgorithm->{'algorithm'}} if(defined $signatureAlgorithm->{'algorithm'});
    if ($signatureAlgorithm->{'parameters'}{'undef'}) {
    	delete ($signatureAlgorithm->{'parameters'});
    }
    return $signatureAlgorithm;
}

sub convert_pkinfo {
    my $pkinfo = shift;
    $pkinfo->{'algorithm'}{'algorithm'}
        = $oids{ $pkinfo->{'algorithm'}{'algorithm'}};
    if ($pkinfo->{'algorithm'}{'parameters'}{'undef'}) {
    	delete ($pkinfo->{'algorithm'}{'parameters'});
    }   
    return $pkinfo;
}

sub convert_attributes {
    my $typeandvalues = shift;
    foreach ( @{$typeandvalues} ) {
    	 if (defined $oids{ $_->{'type'}}) {
    	 	$_->{'type'} = $oids{ $_->{'type'} };
    	 	my $parser = _init($_->{'type'}) or die "Parser error: ", $_->{'type'}, " needs entry in ASN.1 definition!";
    	 	if ($_->{'type'} eq 'extensionRequest') { #extensionRequest need a new layer
                #In case the DER representation of 'extensionRequest' is needed. works for each attribute.	 		
                $_->{'values'} = convert_extensionRequest($_->{'values'}[0]);
    	 	}
    	 	else {
                #maybe there can be more than one value, haven't seen jet. 
                if($_->{'values'}[1]) {warn "Incomplete parsing of attribute type: ", $_->{'type'};}
    	 		$_->{'values'} = $parser->decode($_->{'values'}[0]) or die $parser->error, ".. looks like damaged input";
    	 	}
    	 }    
    }
    return $typeandvalues;
}

sub convert_extensionRequest {
	my $extensionRequest = shift;
	my $parser = _init('extensionRequest');
	my $decoded = $parser->decode($extensionRequest) or die $parser->error, ".. looks like damaged input";
	foreach (@{$decoded}) {
		if (defined $oids{ $_->{'extnID'}}) {
			$_->{'extnID'} = $oids{ $_->{'extnID'} };
			my $parser = _init($_->{'extnID'}) or die "parser error: ", $_->{'extnID'}, " needs entry in ASN.1 definition!";
			$_->{'extnValue'} = $parser->decode($_->{'extnValue'}) or die $parser->error, ".. looks like damaged input";
			#extension specific mapping
			$_->{'extnValue'} = mapExtensions($_->{'extnID'}, $_->{'extnValue'});
		}
	}
	return $decoded;
}

sub mapExtensions {
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
		foreach(@{$value}) {
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


sub convert_rdn {
    my $typeandvalue = shift;
    my %hash;
    foreach ( @{$typeandvalue}) {
    	if (defined $oids{ $_->[0]->{'type'}}) {
    		$hash{ $oids{ $_->[0]->{'type'} } } = $_->[0]->{'value'};
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
    	undef 		  ANY
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
	  certificationRequestInfo 	CertificationRequestInfo,
	  signatureAlgorithm  		AlgorithmIdentifier,
	  signature         		BIT STRING}

	CertificationRequestInfo ::= SEQUENCE {
	  version       INTEGER ,
	  subject       Name OPTIONAL,
	  subjectPKInfo SubjectPublicKeyInfo,
	  attributes    [0] Attributes OPTIONAL}

	--- Extensions ---

	OS_Version ::= IA5String

	EnrollmentCSP ::= SEQUENCE {
		KeySpec		INTEGER,
		Name		BMPString,
		Signature	BIT STRING}

	ClientInformation ::= SEQUENCE {
		ClientID 	INTEGER,
		User		UTF8String,
		Machine 	UTF8String,
		Process 	UTF8String}

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
       policyQualifierId	OBJECT IDENTIFIER,
       qualifier        	ANY}

  	unstructuredName ::= CHOICE {
  		Ia5String 		IA5String,
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

    certificateTemplateName ::= BMPString
ASN1

    my $self = $asn->find($node);
    return $self;
}

sub commonName {
    my $self = shift;
    return $self->{'certificationRequestInfo'}{'subject'}{'commonName'}
        {'utf8String'} || '';
}

sub organizationalUnitName {
    my $self = shift;
    return $self->{'certificationRequestInfo'}{'subject'}
        {'organizationalUnitName'}{'utf8String'} || '';
}

sub emailAddress {
    my $self = shift;
    return $self->{'certificationRequestInfo'}{'subject'}{'emailAddress'}
        {'ia5String'} || '';
}

sub stateOrProvinceName {
    my $self = shift;
    return $self->{'certificationRequestInfo'}{'subject'}
        {'stateOrProvinceName'}{'utf8String'} || '';
}

sub countryName {
    my $self = shift;
    return $self->{'certificationRequestInfo'}{'subject'}{'countryName'}
        {'printableString'} || '';
}

sub version {
    my $self = shift;
    my $v    = $self->{'certificationRequestInfo'}{'version'};
    return "v1" if $v == 0;
    return "v2" if $v == 1;
    return "v3" if $v == 2;
}

sub pkAlgorithm {
    my $self = shift;
    return $self->{'certificationRequestInfo'}{'subjectPKInfo'}{'algorithm'}
        {'algorithm'};
}

sub subjectPublicKey {
    my $self = shift;
    return unpack('H*', $self->{'certificationRequestInfo'}{'subjectPKInfo'}
        {'subjectPublicKey'}[0]);
}

sub signatureAlgorithm {
    my $self = shift;
    return $self->{'signatureAlgorithm'}{'algorithm'};

}

sub signature {
    my $self = shift;
    return unpack('H*', $self->{'signature'});
}

sub attributes {
    my $self       = shift;
    my $attributes = $self->{'certificationRequestInfo'}{'attributes'};
    my %hash = map { $_->{'type'} => $_->{'values'} }
        @{$attributes};
    return %hash;
}

sub certificateTemplate {
	my $self = shift;
	my %attributes = attributes($self);
	my $template;
	my @space = @{$attributes{'extensionRequest'}};
	foreach (@space) {
		if ($_->{'extnID'} eq 'certificateTemplate') {
			$template = $_->{'extnValue'};
		}
	}
	return $template; 
}
1;

__END__