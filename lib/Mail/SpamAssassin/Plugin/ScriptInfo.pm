use strict;
use warnings;
package Mail::SpamAssassin::Plugin::ScriptInfo;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger ();
use Mail::SpamAssassin::Util qw(compile_regexp);

our @ISA = qw(Mail::SpamAssassin::Plugin);
our $VERSION = 0.01;

=head1 NAME

Mail::SpamAssassin::Plugin::ScriptInfo - SpamAssassin plugin to analyze scripts embedded in HTML messages
and attachments

=head1 SYNOPSIS

    loadplugin     Mail::SpamAssassin::Plugin::ScriptInfo

=head1 DESCRIPTION

This plugin analyzes scripts embedded in HTML messages and attachments. Most of the time this will be
JavaScript, but it will match any text found inside a <script> tag.

=head1 CONFIGURATION

The following configuration options are available:

=over 4

=item script

This directive allows you to check for a particular pattern in the script text.
The first argument is the name of the rule, and the second argument is a
regular expression to match against the script text.

    # sample rules
    script  JS_OBFUSCATION  /(?:\/x\d\d){10,}/
    score   JS_OBFUSCATION  5.0

    script  JS_REDIRECT     /\bwindow\.location(\.href)?\s*=/
    score   JS_REDIRECT     5.0

=item check_script_contains_email()

This rule checks for the presence of the recipient's email address in the
script text.  This is useful for detecting phishing attacks.

    # sample rule
    body  JS_PHISHING     eval:check_script_contains_email()
    score JS_PHISHING     5.0

=back

=head1 AUTHOR

   Kent Oyer <kent@mxguardian.net>
   Copyright (C) 2023 MXGuardian, LLC

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it
under the terms of the Apache License, Version 2.0.

=cut

sub dbg { Mail::SpamAssassin::Logger::dbg ("ScriptInfo: @_"); }

sub new {
    my $class = shift;
    my $mailsaobject = shift;

    # some boilerplate...
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsaobject);
    bless ($self, $class);

    $self->set_config($mailsaobject->{conf});

    $self->register_eval_rule("check_script_contains_email");

    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;

    push (@cmds, {
        setting => 'script',
        is_priv => 1,
        code => sub {
            my ($self, $key, $value, $line) = @_;

            if ($value !~ /^(\S+)\s+(.+)$/) {
                return $Mail::SpamAssassin::Conf::INVALID_VALUE;
            }
            my $name = $1;
            my $pattern = $2;

            my ($re, $err) = compile_regexp($pattern, 1);
            if (!$re) {
                dbg("Error parsing rule: invalid regexp '$pattern': $err");
                return $Mail::SpamAssassin::Conf::INVALID_VALUE;
            }

            $conf->{parser}->{conf}->{script_rules}->{$name} = $re;

        }
    });

    $conf->{parser}->register_commands(\@cmds);
}

sub check_script_contains_email {
    my ($self, $pms) = @_;


    my $rule = $pms->get_current_eval_rule_name();

    my $to = $pms->get('To:addr');
    my $script_text = $self->_get_script_text($pms);
    dbg("Running $rule checking script for $to");
    return grep { /$to/ } @$script_text;
}

sub parsed_metadata {
    my ($self, $opts) = @_;

    $self->_run_script_rules($opts);

}

sub _run_script_rules {
    my ($self, $opts) = @_;
    my $pms = $opts->{permsgstatus};

    # check all script rules
    if ( exists $pms->{conf}->{script_rules} ) {
        my $script_text = $self->_get_script_text($pms);
        foreach my $name (keys %{$pms->{conf}->{script_rules}}) {
            my $re = $pms->{conf}->{script_rules}->{$name};
            dbg("running rule $name $re");
            foreach my $line (@$script_text) {
                if ( $line =~ /$re/p ) {
                    dbg(qq(ran rule $name ======> got hit ").(defined ${^MATCH} ? ${^MATCH} : '<negative match>').qq("));
                    my $score = $pms->{conf}->{scores}->{$name} || 1;
                    $pms->got_hit($name,'SCRIPT: ','ruletype' => 'rawbody', 'score' => $score);
                    last;
                }
            }
        }
    }

}

sub _get_script_text {
    my ($self, $pms) = @_;

    return $pms->{script_text} if defined $pms->{script_text};

    $pms->{script_text} = [];
    foreach my $p ($pms->{msg}->find_parts(qr/./)) {
        next unless defined $p->{html_results}->{script};
        push @{$pms->{script_text}}, @{$p->{html_results}->{script}};
    }

    return $pms->{script_text};
}

1;