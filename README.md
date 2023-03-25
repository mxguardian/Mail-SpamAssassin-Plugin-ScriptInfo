# NAME

Mail::SpamAssassin::Plugin::ScriptInfo - SpamAssassin plugin to analyze scripts embedded in HTML attachments

# SYNOPSIS

    loadplugin     Mail::SpamAssassin::Plugin::ScriptInfo

# DESCRIPTION

This plugin analyzes scripts embedded in HTML attachments. Most of the time this will be
JavaScript, but it will match any text found inside a &lt;script> tag as well as any text
found in certain HTML tag attributes such as &lt;a href="javascript:..."> or 'on\*' event handlers.

NOTE: This plugin does not inspect scripts in the HTML body of the message. It only inspects
scripts in HTML attachments. This is to avoid false positives and is generally safe because
most modern email clients will not execute scripts in the message body.

# CONFIGURATION

The following configuration options are available:

- script

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

- check\_script\_contains\_email()

    This rule checks for the presence of the recipient's email address in the
    script text.  This is useful for detecting phishing attacks.

        # sample rule
        script  JS_PHISHING     eval:check_script_contains_email()
        score   JS_PHISHING     5.0

- script\_ignore\_md5

    This directive allows you to ignore certain HTML attachments that match a fuzzy MD5 checksum. This is useful
    if you have a particular HTML attachment that is known to contain scripts that are not malicious.

        # sample rule (Cisco Secure Message)
        script_ignore_md5  10DBD19204B70CF81AB952A0F6CABEA7

    To obtain the fuzzy MD5 hash of an attachment in a message, run the following command:

        cat /path/to/message | spamassassin -L -D ScriptInfo |& grep md5

# AUTHOR

    Kent Oyer <kent@mxguardian.net>
    Copyright (C) 2023 MXGuardian, LLC

# LICENSE

This program is free software; you can redistribute it and/or modify it
under the terms of the Apache License, Version 2.0.
