##########
# Win32::LongPath
#
# 1.0	R. Boisvert	8/6/2013
# First release.
##########

use inc::Module::Install;

# determine build environment
use Win32;
my @vers = Win32::GetOSVersion ();
my $WinVer = sprintf ('0x%02x%02x', $vers [1], $vers [2]);
 
# metadata
name            'Win32-LongPath';
abstract        'Windows file functions that use very long paths and Unicode.';
author          'Robert Boisvert <rdboisvert@juno.com>';
version         '0.01';
license         'perl';
requires        'Carp' => 0;
requires        'Encode' => 0;
requires        'Fcntl' => 0;
requires        'File::Spec::Functions' => 0;
requires        'Time::Local' => 0;
repository      'https://github.com/rdboisvert/Win32-LongPath';
bugtracker      'https://github.com/rdboisvert/Win32-LongPath/issues';
win32;

# XS
configure_requires
                'ExtUtils::ParseXS';
use_ppport;
cc_define       "-DWINVER=$WinVer -D_WIN32_WINNT=$WinVer";
cc_warnings;
cc_src_paths    'xs';

# tests
tests           't/*.t';
test_requires   'Test::More' => 0;

# dist
use_ptar;

# create Makefile
WriteAll;
