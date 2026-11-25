# Security policy

DotLdap.Testing is a test library: it runs an LDAP server inside a test process, bound to 127.0.0.1, with data the
test defines. It is not meant to be exposed to a network or to hold real credentials. Still, a bug that lets
something outside the test process reach the server, read its data or crash the process that hosts it is a security
issue, and so is anything in the package that could harm the machine it runs on.

## Supported versions

Until 1.0 only the latest pre-release gets fixes.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through
[GitHub's private vulnerability reporting](https://github.com/saiganov/DotLdap/security/advisories/new)
(Security tab → Report a vulnerability). Include what you did, what happened and, if you have one, a test or a
request that shows it.

You can expect a first answer within a week. Once a fix is released, the advisory is published with credit to the
reporter unless you ask otherwise.
