package Apache2::Authen::OdinAuth;

use 5.006;
use strict;
use warnings;

=head1 NAME

Apache2::Authen::OdinAuth - A cookie-based single sign-on module for Apache.

=head1 VERSION

Version 0.4.1

=cut

our $VERSION = '0.4.1';

use Crypt::OdinAuth;

use Apache2::Log;
use Apache2::RequestRec ();
use Apache2::RequestUtil;
use Apache2::ServerUtil ();
use Apache2::Connection;
use Apache2::Const -compile => qw(OK REDIRECT REMOTE_NOLOOKUP FORBIDDEN);
use APR::Table;
use YAML::XS;

use Sys::Hostname;

=head1 SYNOPSIS

This module defines an Apache handler for the Odin Authenticator
single sign-on system. The system is based on the GodAuth script,
available at L<http://github.com/exflickr/GodAuth/>.

=head1 USAGE

To make Apache use the handler for authentication, enable mod_perl and
add following directives in apache2.conf:

    PerlSetVar odinauth_config /path/to/odin_auth.yml
    PerlFixupHandler Apache2::Authen::OdinAuth

The C<PerlSetVar> statement needs to be global; the
C<PerlFixupHandler> statement can be global or occur in a
C<VirtualHost>, C<Directory>, or C<Location> section.

=head2 YAML CONFIG

The handler reads (and automatically reloads if it's older than
C<reload_timeout> seconds) an additional YAML config file. It sets
configures the shared secret, cookie name, authorizer app URL, and
permissions (which are unfortunately regexp-based).

A sample configuration file looks like this:

    # Sample config for Apache2::Authen::OdinAuth
    
    permissions:
      # URLs no auth
      - url: !!perl/regexp ^localhost
        who: all
      # Require a role
      - url: !!perl/regexp ^dev\.myapp\.com
        who: role:admin
      # Require username
      - url: !!perl/regexp ^debug\.myapp\.com/
        who: cal
      # A list is fine too
      - url: !!perl/regexp ^debug2\.myapp\.com/
        who:
          - role:devel
          - cal
          - myles
      # Allow any authenticated user
      - url: !!perl/regexp ^debug3\.myapp\.com/
        who: authed
    
    
    # log_file: /tmp/odin.log
    secret: ****************
    reload_timeout: 600
    need_auth_url: http://example.com/?NA
    invalid_cookie_url: http://example.com/?CIU
    not_on_list_url: http://example.com/?NOL
    cookie: oa

NOTE: The config is better than original GodAuth configuration, but
will probably need to be refactored; it would be best to make it live
inside Apache's configuration. I'm still not sure how to make it
happen in mod_perl.

=cut

use constant RELOAD_TIMEOUT => 10*60; # reload config every 10 minutes

{
  my $last_reload_time = -1;
  my $config_file = undef;
  my $config = undef;

  sub config {
    if ( time() - $last_reload_time > RELOAD_TIMEOUT ) {
      $config = YAML::XS::LoadFile($config_file);
    }
    $config;
  }

  sub init_config {
    my $r = shift;
    $config_file ||=
      $r->server->dir_config('odinauth_config');
    config;
  }
}

$| = 1;


sub handler {
  #
  # get URL
  #

  my $r = shift;

  my $domain = $r->headers_in->{'Host'} || 'UNKNOWN-HOST';
  my $path = $r->unparsed_uri;

  my $host = hostname;

  $ENV{OdinAuth_User} = '';

  my $url = $domain . $path;
  my $log = "OdinAuth :: $url";

  init_config($r);


  #########################################################
  #
  # 1) check we have a cookie secret
  #
  config->{'secret'} ||=  'nottherightsecret';


  #########################################################
  #
  # 1) determine if we need to perform access control for this url
  #

  my $allow = 'none';

  for my $obj (@{config->{'permissions'}}) {
    if ($url =~ $obj->{url}) {
      $allow = $obj->{who};
      last;
    }
  }

  $log .= " allow:$allow";


  #########################################################
  #
  # 2) we might need auth - see if we have a valid cookie
  #

  my $cookie_is_invalid = 'by default';
  my $cookie_user = '?';
  my $cookie_roles = '_';

  my $cookies = &parse_cookie_jar($r->headers_in->{'Cookie'});
  my $cookie = $cookies->{config->{cookie}};

  if ($cookie) {
      my ( $user, $roles );
      eval {
          ( $user, $roles ) =
              Crypt::OdinAuth::check_cookie(
                  config->{secret},
                  $cookie,
                  $r->headers_in->{'User-Agent'});
      };

      if ( $@ ) {
          $cookie_user = $user;
          $cookie_roles = $roles;
          chomp ( $cookie_is_invalid = $@ );
          $log .= "(invalid cookie: $cookie_is_invalid)";
      } else {
          $cookie_is_invalid = undef;
          $cookie_user = $user;
          $cookie_roles = $roles;

          $r->headers_in->set('OdinAuth-User', $cookie_user);
          $r->headers_in->set('OdinAuth-Roles', $cookie_roles);

          $ENV{OdinAuth_User} = $cookie_user;
          $ENV{OdinAuth_Roles} = $cookie_roles;

          $r->notes->add("OdinAuth_User" => $cookie_user);
          $r->notes->add("OdinAuth_Roles" => $cookie_roles);

          $log .= " (valid cookie: $cookie_user $cookie_roles)";
      }
  } else {
      $log .= " (no cookie)";
  }

  $r->log->debug($log);

  if ( $cookie_is_invalid ) {
      $r->log->warn("Invalid cookie for $cookie_user($cookie_roles): $cookie_is_invalid");
  }

  #########################################################
  #
  # 3) exit now if we got an 'all'
  #

  if (ref $allow ne 'ARRAY') {
    if ($allow eq 'all') {
      return Apache2::Const::OK;
    }
  }


  #########################################################
  #
  # 4) if we don't have a valid cookie, redirect to the auther
  #

  if (!$cookie) {
    return &redir($r, $url, config->{need_auth_url});
  }

  if ($cookie_is_invalid) {
    return &redir($r, $url, config->{invalid_cookie_url}, $cookie_is_invalid);
  }


  #########################################################
  #
  # 5) set user; exit now for authed
  #

  $r->user($cookie_user);
  $r->subprocess_env('REMOTE_USER' => $cookie_user);
  $r->set_basic_credentials($cookie_user, '*****');

  if (ref $allow ne 'ARRAY') {
    if ($allow eq 'authed') {
      return Apache2::Const::OK;
    }
  }


  #########################################################
  #
  # 5) now we need to match usernames and/or roles
  #

  # get arrayref of allowed roles
  unless (ref $allow eq 'ARRAY'){
    $allow = [$allow];
  }

  # get arrayref of our roles
  my $matches = [$cookie_user];
  for my $role (split /,/, $cookie_roles) {
    if ($role ne '_') {
      push @{$matches}, 'role:'.$role;
    }
  }


  for my $a (@{$allow}) {
    for my $b (@{$matches}) {

      if ($a eq $b) {
        return Apache2::Const::OK;
      }
    }
  }


  #
  # send the user to the not-on-list page
  #

  return &redir($r, $url, config->{not_on_list_url});
}


sub redir {
  my ($r, $ref, $url, $reason) = @_;

  $ref = &urlencode('http://'.$ref);
  $url .= ($url =~ /\?/) ? "&ref=$ref" : "?ref=$ref";
  $url .= '&reason='.urlencode($reason) if $reason;

  $r->headers_out->set('Location', $url);
  return Apache2::Const::REDIRECT;
}


sub parse_cookie_jar {
  my ($jar) = @_;

  return {} unless defined $jar;

  my @bits = split /;\s*/, $jar;
  my $out = {};
  for my $bit (@bits) {
    my ($k, $v) = split '=', $bit, 2;
    $k = &urldecode($k);
    $v = &urldecode($v);
    $out->{$k} = $v;
  }
  return $out;
}


sub urldecode {
  $_[0] =~ s!\+! !g;
  $_[0] =~ s/%([a-fA-F0-9]{2,2})/chr(hex($1))/eg;
  return $_[0];
}

sub urlencode {
  $_[0] =~ s!([^a-zA-Z0-9-_ ])! sprintf('%%%02x', ord $1) !gex;
  $_[0] =~ s! !+!g;
  return $_[0];
}


=head1 AUTHOR

Maciej Pasternacki, C<< <maciej at pasternacki.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-apache2-authen-odinauth at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Apache2-Authen-OdinAuth>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Apache2::Authen::OdinAuth


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Apache2-Authen-OdinAuth>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Apache2-Authen-OdinAuth>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Apache2-Authen-OdinAuth>

=item * Search CPAN

L<http://search.cpan.org/dist/Apache2-Authen-OdinAuth/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 Maciej Pasternacki.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Apache2::Authen::OdinAuth
