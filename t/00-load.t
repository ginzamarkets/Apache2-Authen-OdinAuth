#!perl -T

use Test::More tests => 2;

BEGIN {
    use_ok( 'Apache2::Authen::OdinAuth' ) || print "Bail out!\n";
    use_ok( 'Crypt::OdinAuth' ) || print "Bail out!\n";
}

diag( "Testing Apache2::Authen::OdinAuth $Apache2::Authen::OdinAuth::VERSION, Perl $], $^X" );
