use strict;
use warnings;
package Mail::SpamAssassin::Plugin::ScriptInfo;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger ();
use Mail::SpamAssassin::Util qw(compile_regexp);
use MIME::Base64;
use HTML::Parser;
use Digest::MD5;
use Data::Dumper;

our @ISA = qw(Mail::SpamAssassin::Plugin);
our $VERSION = 0.08;

=head1 NAME

Mail::SpamAssassin::Plugin::ScriptInfo - SpamAssassin plugin to analyze scripts embedded in HTML attachments

=head1 SYNOPSIS

    loadplugin     Mail::SpamAssassin::Plugin::ScriptInfo

=head1 DESCRIPTION

This plugin analyzes scripts embedded in HTML attachments. Most of the time this will be
JavaScript, but it will match any text found inside a <script> tag as well as any text
found in certain HTML tag attributes such as <a href="javascript:..."> or 'on*' event handlers.

NOTE: This plugin does not inspect scripts in the HTML body of the message. It only inspects
scripts in HTML attachments. This is to avoid false positives and is generally safe because
most modern email clients will not execute scripts in the message body.

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

You can also use the 'multiple' flag to match multiple times in the same script. The 'maxhits' flag can be
used to limit the number of hits that will trigger a match.

    # sample rule
    script  __HEX_CONSTANT  /0x[0-9A-F]/i
    tflags  __HEX_CONSTANT  multiple maxhits=10
    meta    JS_OBFUSCATION  __HEX_CONSTANT > 9
    score   JS_OBFUSCATION  5.0

=item check_script_contains_email()

This rule checks for the presence of the recipient's email address in the
script text.  This is useful for detecting phishing attacks.

    # sample rule
    script  JS_PHISHING     eval:check_script_contains_email()
    score   JS_PHISHING     5.0

=item script_ignore_md5

This directive allows you to ignore certain HTML attachments that match a fuzzy MD5 checksum. This is useful
if you have a particular HTML attachment that is known to contain scripts that are not malicious.

    # sample rule (Cisco Secure Message)
    script_ignore_md5  10DBD19204B70CF81AB952A0F6CABEA7

To obtain the fuzzy MD5 hash of an attachment in a message, run the following command:

    cat /path/to/message | spamassassin -L -D ScriptInfo |& grep md5

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

    push (@cmds, (
        {
            setting => 'script',
            is_priv => 1,
            type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
            code => sub {
                my ($self, $key, $value, $line) = @_;

                if ($value !~ /^(\S+)\s+(.+)$/) {
                    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
                }
                my $name = $1;
                my $pattern = $2;

                if ( $pattern =~ /^eval:(.*)/ ) {
                    $conf->{parser}->add_test($name, $1, $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
                } else {
                    my ($re, $err) = compile_regexp($pattern, 1);
                    if (!$re) {
                        dbg("Error parsing rule: invalid regexp '$pattern': $err");
                        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
                    }

                    $conf->{parser}->{conf}->{script_rules}->{$name} = $re;
                }

            }
        },
        {
            setting => 'script_ignore_md5',
            is_priv => 1,
            type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRINGLIST,
            code => sub {
                my ($self, $key, $value, $line) = @_;
                $conf->{parser}->{conf}->{script_ignore_md5}->{uc($value)} = 1;
            }
        }
    ));

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
        start_document_h => [ sub {
            my ($self) = @_;
            $self->{_md5} = Digest::MD5->new;
            $self->{script_text} = [];
        }, 'self' ],
        start_h => [ sub {
            my ($self, $tagname, $attr, $attrseq) = @_;
            my $md5_text = "$tagname";

            if (lc($tagname) eq 'script') {
                $script_tag++;
            } elsif ( lc($tagname) eq 'style' ) {
                $style_tag++;
            }

            foreach my $attrname (@{$attrseq}) {
                if ( $attrname =~ /^(?:name|method|type)$/i ) {
                    $md5_text .= qq( $attrname="$attr->{$attrname}");
                } elsif ( $attrname =~ /^(?:src|href|action)$/i ) {
                    next if $tagname =~ /^(?:base|img)$/;
                    if ( $attr->{$attrname} =~ m{^(https?://[^/]+/[^?]+)}i ) {
                        # Only include URL's with a non-empty path
                        # Do not include the query string
                        $md5_text .= qq( $attrname="$1");
                    } elsif ( $attr->{$attrname} =~ /^javascript:/i ) {
                        push @{$self->{script_text}}, substr($attr->{$attrname}, 11);
                    } elsif ( $attr->{$attrname} =~ /^data:([^,;]*)(;base64)?,(.*)/i ) {
                        if ( $2 eq ';base64' ) {
                            push @{$self->{script_text}}, MIME::Base64::decode_base64($3);
                        } else {
                            push @{$self->{script_text}}, $3;
                        }
                    }
                } elsif ( $attrname =~ /^on/ ) {
                    push @{$self->{script_text}}, $attr->{$attrname};
                }
            }

            # <option> tags can screw up the fuzzy checksum, so we skip them
            unless ( $tagname eq 'option' ) {
                # print $md5_text, "\n";
                $self->{_md5}->add($md5_text);
            }
        }, 'self, tagname, attr, attrseq' ],
        text_h => [ sub {
            my ($self, $dtext, $is_cdata) = @_;
            if ( $script_tag > 0 ) {
                push @{$self->{script_text}}, $dtext if (defined($dtext));
            }
        }, 'self, dtext, is_cdata' ],
        end_h => [ sub {
            my ($self, $tagname) = @_;
            if (lc($tagname) eq 'script') {
                $script_tag--;
            } elsif (lc($tagname) eq 'style') {
                $style_tag--;
            }
        }, 'self, tagname' ],
        end_document_h => [ sub {
            my ($self) = @_;
            $self->{md5} = uc($self->{_md5}->hexdigest);
        }, 'self' ],
    );

    defined($pms->{attachments}) or
        die "Mail::SpamAssassin::Plugin::ScriptInfo requires Mail::SpamAssassin::Plugin::AttachmentDetail";

    # cycle through all parts of the message and parse any text/html attachments
    foreach my $a ( @{$pms->{attachments}} )  {
        next unless $a->{effective_type} eq 'text/html';

        my $text = $a->{part}->decode();

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

        # check md5 against the ignore list
        my $md5 = $parser->{md5};
        dbg("name=$a->{name} md5=$md5");
        if ( defined($pms->{conf}->{script_ignore_md5}->{$md5}) ) {
            dbg("Skipping due to md5 match");
        } else {
            # add the parsed text to the list of script text
            push(@{$pms->{script_text}}, @{$parser->{script_text}});
        }

    }

    # print $_ foreach @{$pms->{script_text}}; print "\n";

    return $pms->{script_text};
}

1;