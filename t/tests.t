use strict;
use warnings FATAL => 'all';
use Test::More;
use Mail::SpamAssassin;
use Data::Dumper;

my $data_dir = 't/data';
my $spamassassin = Mail::SpamAssassin->new(
    {
        dont_copy_prefs    => 1,
        local_tests_only   => 1,
        use_bayes          => 0,
        use_razor2         => 0,
        use_pyzor          => 0,
        use_dcc            => 0,
        use_auto_whitelist => 0,
        debug              => 0,
        pre_config_text        => <<'EOF'
            loadplugin Mail::SpamAssassin::Plugin::ScriptInfo
            body    SCRIPT_INFO_01     eval:check_script_contains_email()
            script  SCRIPT_INFO_02     /(\\x[a-f0-9]{2}){5}/i
            script  SCRIPT_INFO_03     /\batob\(/
            script  SCRIPT_INFO_04     /\babcdefghi/
EOF
            ,
    }
);

my @files = (
    {
        name  => 'msg1.eml',
        hits => {
            'SCRIPT_INFO_01' => 1,
        },
        pattern_hits => {}
    },
    {
        name         => 'msg2.eml',
        hits         => {
            'SCRIPT_INFO_02' => 1,
        },
        pattern_hits => {
            'SCRIPT_INFO_02' => '\x62\x63\x62\x35\x37'
        }
    },
    {
        name         => 'msg3.eml',
        hits         => {
            'SCRIPT_INFO_03' => 1,
        },
        pattern_hits => {
            'SCRIPT_INFO_03' => 'atob('
        }
    },
    {
        name         => 'msg4.eml',
        hits         => {
            'SCRIPT_INFO_04' => 1,
        },
        pattern_hits => {
            'SCRIPT_INFO_04' => 'abcdefghi'
        }
    }
);

plan tests => scalar(@files) * 2;

# test each file
foreach my $file (@files) {
    print "Testing $file->{name}\n";
    my $path = "$data_dir/".$file->{name};
    open my $fh, '<', $path or die "Can't open $path: $!";
    my $msg = $spamassassin->parse($fh);
    my $pms = $spamassassin->check($msg);
    close $fh;
    my $hits = $pms->get_names_of_tests_hit_with_scores_hash();
    my $pattern_hits = $pms->{pattern_hits};
    # print Dumper($hits);
    foreach my $test (keys %$hits) {
        delete $hits->{$test} unless $test =~ /^SCRIPT_INFO/;
    }
    foreach my $test (keys %$pattern_hits) {
        delete $pattern_hits->{$test} unless $test =~ /^SCRIPT_INFO/;
    }
    is_deeply($hits, $file->{hits}, $file->{name});
    is_deeply($pattern_hits, $file->{pattern_hits}, $file->{name});
}

