use strict;
use warnings;
package Mail::SpamAssassin::Plugin::ScriptInfo;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger ();
use Mail::SpamAssassin::Util qw(compile_regexp);
use MIME::Base64;
use HTML::Parser;
use Data::Dumper;

our @ISA = qw(Mail::SpamAssassin::Plugin);
our $VERSION = 0.04;

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
sub info { Mail::SpamAssassin::Logger::info ("ScriptInfo: @_"); }

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
            my $tflags = $pms->{conf}->{tflags}->{$name} || '';
            dbg("running rule $name $re");
            if ( $tflags =~ /\bmultiple\b/ ) {
                my $hits = 0;
                my $maxhits = $1 if ($tflags =~ /\bmaxhits=(\d+)\b/);
                foreach my $line (@$script_text) {
                    while ( $line =~ /$re/g ) {
                        $hits++;
                        last if defined $maxhits && $hits >= $maxhits;
                    }
                    last if defined $maxhits && $hits >= $maxhits;
                }
                if ( $hits > 0 ) {
                    dbg(qq(ran rule $name ======> got hit ($hits)"));
                    my $score = $pms->{conf}->{scores}->{$name} || 1;
                    $pms->got_hit($name,'SCRIPT: ','ruletype' => 'rawbody', 'score' => $score, 'value' => $hits);
                }
            } else {
                foreach my $line (@$script_text) {
                    if ( $line =~ /$re/p ) {
                        dbg(qq(ran rule $name ======> got hit ").(defined ${^MATCH} ? ${^MATCH} : '<negative match>').qq("));
                        $pms->{pattern_hits}->{$name} = ${^MATCH} if defined ${^MATCH};
                        my $score = $pms->{conf}->{scores}->{$name} || 1;
                        $pms->got_hit($name,'SCRIPT: ','ruletype' => 'rawbody', 'score' => $score);
                        last;
                    }
                }
            }
        }
    }

}

sub _get_script_text {
    my ($self, $pms) = @_;

    return $pms->{script_text} if defined $pms->{script_text};

    $pms->{script_text} = [];

    # initialize the parser
    my $script_tag = 0; my $style_tag = 0;
    my $parser = HTML::Parser->new(
        api_version => 3,
        start_h => [ sub {
            my ($tagname, $attr, $attrseq) = @_;
            if (lc($tagname) eq 'script') {
                $script_tag++;
            } elsif ( lc($tagname) eq 'style' ) {
                $style_tag++;
            }
            # check for attributes that contain script
            foreach my $attrname (grep /^on/i, keys %$attr) {
                push @{$pms->{script_text}}, $attr->{$attrname};
            }
            # check for javascript: and data: URIs
            if ( defined($attr->{href}) ) {
                if ( $attr->{href} =~ /^javascript:/i ) {
                    push @{$pms->{script_text}}, substr($attr->{href}, 11);
                } elsif ( $attr->{href} =~ /^data:([^,;]*)(;base64)?,(.*)/i ) {
                    if ( $2 eq ';base64' ) {
                        push @{$pms->{script_text}}, MIME::Base64::decode_base64($3);
                    } else {
                        push @{$pms->{script_text}}, $3;
                    }
                }
            }
        }, 'tagname, attr, attrseq' ],
        text_h => [ sub {
            my ($dtext, $is_cdata) = @_;
            if ( $script_tag > 0 ) {
                push @{$pms->{script_text}}, $dtext if (defined($dtext));
            }
        }, 'dtext, is_cdata' ],
        end_h => [ sub {
            my ($tagname) = @_;
            if (lc($tagname) eq 'script') {
                $script_tag--;
            } elsif (lc($tagname) eq 'style') {
                $style_tag--;
            }
        }, 'tagname' ],
    );

    # cycle through all parts of the message and parse any text/html parts
    foreach my $p ($pms->{msg}->find_parts(qr/./)) {
        next unless $p->effective_type eq 'text/html';

        my $text = $p->decode();

        # Normalize unicode quotes, messes up attributes parsing
        # U+201C e2 80 9c LEFT DOUBLE QUOTATION MARK
        # U+201D e2 80 9d RIGHT DOUBLE QUOTATION MARK
        # Examples of input:
        # <a href=\x{E2}\x{80}\x{9D}https://foobar.com\x{E2}\x{80}\x{9D}>
        # .. results in uri "\x{E2}\x{80}\x{9D}https://foobar.com\x{E2}\x{80}\x{9D}"
        if (utf8::is_utf8($text)) {
            $text =~ s/(?:\x{201C}|\x{201D})/"/g;
        } else {
            $text =~ s/\x{E2}\x{80}(?:\x{9C}|\x{9D})/"/g;
        }

        # call the parser
        eval {
            local $SIG{__WARN__} = sub {
                my $err = $_[0];
                $err =~ s/\s+/ /gs; $err =~ s/(.*) at .*/$1/s;
                info("HTML::Parser warning: $err");
            };
            $parser->parse($text);
        };

        # bug 7437: deal gracefully with HTML::Parser misbehavior on unclosed <style> and <script> tags
        # (typically from not passing the entire message to spamc, but possibly a DoS attack)
        $parser->parse("</style>") while $style_tag > 0;
        $parser->parse("</script>") while $script_tag > 0;

        $parser->eof();

    }

    # print $_ foreach @{$pms->{script_text}}; print "\n";

    return $pms->{script_text};
}

1;