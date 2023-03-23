use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME => 'Mail::SpamAssassin::Plugin::ScriptInfo',
    VERSION_FROM => 'lib/Mail/SpamAssassin/Plugin/ScriptInfo.pm',
    PREREQ_PM => {
        'Mail::SpamAssassin' => '4.0.1',
        'HTML::Parser'       => 0,
    },
    AUTHOR => 'Kent Oyer <kent@mxguardian.net>',
    LICENSE => 'apache_2_0',
    ABSTRACT => 'SpamAssassin plugin to analyze scripts embedded in HTML messages and attachments',
    BUILD_REQUIRES => {
        'Test::More'          => 0,
        'ExtUtils::MakeMaker' => 6.31
    },
);
