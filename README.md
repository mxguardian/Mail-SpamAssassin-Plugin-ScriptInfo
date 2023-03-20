# NAME

Mail::SpamAssassin::Plugin::ScriptInfo - SpamAssassin plugin to analyze scripts embedded in HTML messages
and attachments

# SYNOPSIS

    loadplugin     Mail::SpamAssassin::Plugin::ScriptInfo

# DESCRIPTION

This plugin analyzes scripts embedded in HTML messages and attachments

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

- check\_script\_contains\_email()

    This rule checks for the presence of the recipient's email address in the
    script text.  This is useful for detecting phishing attacks.

        # sample rule
        body  JS_PHISHING     eval:check_script_contains_email()
        score JS_PHISHING     5.0

# AUTHOR

    Kent Oyer <kent@mxguardian.net>
    Copyright (C) 2023 MXGuardian, LLC

# LICENSE

This program is free software; you can redistribute it and/or modify it
under the terms of the Apache License, Version 2.0.
