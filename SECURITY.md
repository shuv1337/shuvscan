# Security policy

Shuvscan handles sensitive host evidence and invokes remote shells. Treat scanner bugs as security
bugs even when they do not directly cross a privilege boundary.

Do not include live credentials, private hostnames, or unredacted scan evidence in public reports.
Until a private reporting channel is published, open a minimal GitHub advisory containing only the
affected version and a request for maintainer contact.

The scanner does not modify targets. A probe that requires mutation, package installation, a
download, or disabling a security control will not be accepted into the built-in pack.
