#!perl -T

use Test::More tests => 10;
use Test::Exception;

use Crypt::OdinAuth;

use constant EXAMPLE_TIMESTAMP => 1337357387;
use constant EXAMPLE_HMAC => '349b7135f43bd4c0111564960e7d9d583dde0c5c';

is( EXAMPLE_HMAC, Crypt::OdinAuth::hmac_for(
  'secret', 'login_name', 'role1,role2,role3', EXAMPLE_TIMESTAMP, 'netcat'),
    'hmac_for' );

# beware of leap seconds?
my $tm = time();
my $hm = Crypt::OdinAuth::hmac_for( 'secret', 'login_name', 'role1,role2,role3',
                                    $tm, 'netcat');

is( "login_name-role1,role2,role3-$tm-$hm",
    Crypt::OdinAuth::cookie_for('secret', 'login_name', 'role1,role2,role3', 'netcat'),
    'cookie_for without timestamp');

is( "login_name-role1,role2,role3-".EXAMPLE_TIMESTAMP."-".EXAMPLE_HMAC,
    Crypt::OdinAuth::cookie_for('secret', 'login_name', 'role1,role2,role3', 'netcat', EXAMPLE_TIMESTAMP),
    'cookie_for with timestamp');

lives_and {
  my ( $user, $roles ) =
    Crypt::OdinAuth::check_cookie(
      'secret',
      Crypt::OdinAuth::cookie_for(
        'secret', 'login_name', 'role1,role2,role3', 'netcat'),
      'netcat');

  is ( 'login_name', $user );
  is ( 'role1,role2,role3', $roles );
} 'check_cookie valid';

throws_ok {
  Crypt::OdinAuth::check_cookie(
    'secret',
    Crypt::OdinAuth::cookie_for(
      'a_different_secret', 'login_name', 'role1,role2,role3', 'netcat'),
    'netcat')
  } qr/^Invalid signature$/;

throws_ok {
  Crypt::OdinAuth::check_cookie(
    'secret',
    Crypt::OdinAuth::cookie_for(
      'secret', 'login_name', 'role1,role2,role3', 'netcat',
      time()-2*Crypt::OdinAuth::OLD_COOKIE),
    'netcat')
  } qr/^Cookie is old$/;

throws_ok {
  Crypt::OdinAuth::check_cookie(
    'secret',
    Crypt::OdinAuth::cookie_for(
      'secret', 'login_name', 'role1,role2,role3', 'netcat', time()+10*60),
    'netcat')
  } qr/^Cookie is in future$/;

sub try_to_authorize {
  my ( $user, $roles );
  eval {
    ( $user, $roles ) = Crypt::OdinAuth::check_cookie(
      'secret'.(shift||''),
      Crypt::OdinAuth::cookie_for(
        'secret', 'login_name', 'role1,role2,role3', 'netcat'),
      'netcat');
  } or return $@;
  return $user;
}

lives_and { is ( 'login_name', try_to_authorize ); };
lives_and { is ( "Invalid signature\n", try_to_authorize('fail') ); };
