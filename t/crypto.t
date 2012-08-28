#!perl -T

use Test::More tests => 10;
use Test::Exception;

use MIME::Base64 qw(encode_base64url decode_base64url);

use Crypt::OdinAuth;

use constant EXAMPLE_TIMESTAMP => 1337357387;
use constant EXAMPLE_HMAC => '0803ddb6d45144663a92255ace8bbe0b3811acae7ff675d7b708d2cc0c99a2a2';

is( EXAMPLE_HMAC, Crypt::OdinAuth::hmac_for(
  'secret', 'login_name', 'role1,role2,role3', EXAMPLE_TIMESTAMP, 'netcat'),
    'hmac_for' );

# beware of leap seconds?
my $tm = time();
my $hm = Crypt::OdinAuth::hmac_for( 'secret', 'login_name', 'role1,role2,role3',
                                    $tm, 'netcat');
my $b64_u = encode_base64url('login_name');
my $b64_r = encode_base64url('role1,role2,role3');

is( "$b64_u,$b64_r,$tm,$hm",
    Crypt::OdinAuth::cookie_for('secret', 'login_name', 'role1,role2,role3', 'netcat'),
    'cookie_for without timestamp');

is( "$b64_u,$b64_r,".EXAMPLE_TIMESTAMP.",".EXAMPLE_HMAC,
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
