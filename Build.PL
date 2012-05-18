use 5.006;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Apache2::Authen::OdinAuth',
    license             => 'perl',
    dist_abstract       => 'Single Sign-on system for Apache',
    dist_author         => q{Maciej Pasternacki <maciej@pasternacki.net>},
    dist_version_from   => 'lib/Apache2/Authen/OdinAuth.pm',
    build_requires => {
        'Test::More' => 0,
        'Test::Exception' => 0,
    },
    requires => {
        'perl' => 5.006,
        'Digest::SHA1' => 0,
        'YAML::XS' => 0,
        'File::Slurp' => 0,
    },
    add_to_cleanup      => [ 'Apache2-Authen-OdinAuth-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
