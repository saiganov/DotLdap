#### 0.1.0 (preview) ####

First preview: the public API may still change before 1.0.

- `LdapTestServer`: an LDAP server inside the test process on a free port of 127.0.0.1, started from a fluent builder in milliseconds. Bind (simple; SASL PLAIN in the generic flavour), Search with every filter type, scope and attribute selection, Compare, Add, Modify, Delete, ModifyDN, Abandon, Unbind, WhoAmI, Password Modify, StartTLS and ldaps:// with a generated certificate.
- Two flavours: generic (OpenLDAP-like: `uid=...,ou=users`, `groupOfNames`, operational `memberOf`) and Active Directory (`CN=...,CN=Users`, `sAMAccountName`, `userPrincipalName`, `objectGUID`, `objectSid`, bind by UPN or `DOMAIN\user`, `data 52e`-style error texts, account states, nested-group and bitwise matching rules, `tokenGroups`, ranged retrieval, `unicodePwd`).
- Controls: simple paged results, server-side sorting, ManageDsaIT (generic), domain scope (AD).
- Test data from code (`WithUser`, `WithGroup`, `WithEntry`), LDIF and JSON; passwords in clear text or `{MD5}`, `{SHA}`, `{SSHA}` and SHA-2 hashes. Read-only users, optional schema checks, referral entries and a default referral.
- Test hooks: a request log (`Requests`, `LastAnswer`, `Last<T>()`), interceptors and fault injection (`Intercept`, `FailWith<T>`), `ProtocolErrors` and `InternalErrors`, the directory changeable while the server runs, `LdapServerFixture` for a shared server.
- A published schema, so that ADSI (`DirectoryEntry`, `DirectorySearcher`) types values as with a real domain controller.
- The library targets net8.0 and has no package dependencies.
- Tested through System.DirectoryServices.Protocols, Novell.Directory.Ldap and (on Windows) ADSI, with seeded fuzz tests on every push and a longer fuzz run every night. Differences from real servers are listed in KNOWN_DIFFERENCES.md.
