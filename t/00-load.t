#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Crypt::OdinAuth' ) || print "Bail out!\n";
}

diag( "Testing Crypt::OdinAuth $Crypt::OdinAuth::VERSION, Perl $], $^X" );
