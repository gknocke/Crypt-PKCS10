use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile
(
  "ABSTRACT" => "Parses PKCS #10 requests to perl data structure.",
  "AUTHOR" => "Gideon Knocke <gknocke\@cpan.org>",
  "BUILD_REQUIRES" => {
    "ExtUtils::MakeMaker" => "6.46",
  },
  "CONFIGURE_REQUIRES" => {
    "ExtUtils::MakeMaker" => "6.31"
  },
  "DISTNAME" => "Crypt-PKCS10",
  "LICENSE" => "perl",
  "MIN_PERL_VERSION" => "5.006",
  "NAME" => "Crypt::PKCS10",
  "PREREQ_PM" => {
    "Convert::ASN1" => "0.27"
  },
  "VERSION_FROM" => 'lib/Crypt/PKCS10.pm',
  "TEST_REQUIRES" => {
    "Test::More" => 0
  },
  "test" => {
    "TESTS" => "t/*.t"
  }
);