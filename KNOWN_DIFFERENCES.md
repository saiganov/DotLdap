# Known differences

DotLdap.Testing follows RFC 4511 and the documented behaviour of OpenLDAP (generic flavour) and Active Directory
(AD flavour). Where it deliberately behaves differently, or does not go as far, the difference is listed here.
Behaviour a test can rely on is pinned by the tests in `tests/DotLdap.Testing.Tests`.

## Both flavours

| Behaviour | A real server | DotLdap.Testing |
|---|---|---|
| Authentication | Simple bind, SASL (EXTERNAL, DIGEST-MD5, GSSAPI, ...), NTLM and Kerberos on AD | Simple bind; SASL PLAIN in the generic flavour. Everything else is refused with `authMethodNotSupported`, NTLM ("Sicily") included. |
| Access control | ACLs decide who reads and writes what | Every bound user reads everything and writes everything, except users marked read-only. `userPassword` is not returned unless `ExposeUserPassword` is on. |
| Schema | Every write is checked against the schema | Not checked by default. `WithSchemaChecks()` checks single-valued attributes and value syntaxes of the attributes the server knows; which attributes an object class requires or allows is never checked. Data loaded from code, LDIF or JSON is not checked at all. |
| Search time limit | Honoured | Ignored: searches run on in-memory data. |
| Approximate match `(cn~=value)` | Sound-alike or similar | Equality. |
| Sorting text (server-side sort control) | By the rules of a language (AD) or by the matching rule (OpenLDAP) | Without regard to case and otherwise by code point, the same on every machine. Names with punctuation or accented letters may sort differently. |
| Server limits | Configured per server | Unlimited unless set: `WithMaxSearchResults` (AD's MaxPageSize) and `WithMaxValuesPerAttribute` (AD's MaxValRange, 1500 by default in the AD flavour). |
| Persistence, replication | Yes | No: the data lives as long as the server object. |
| Listening address | Any interface | The IPv4 loopback, `127.0.0.1`, only. |

## Generic flavour (OpenLDAP-like)

- `memberOf` is computed from `member` and `uniqueMember` of group entries, as the memberof overlay maintains it; it
  cannot be written.
- Password Modify (RFC 3062) changes `userPassword` and stores what it is given; there is no password policy and no
  hashing of new passwords.
- A default referral URL without a DN gets the DN that was asked for. OpenLDAP behaves the same way as far as we
  know; RFC 4511 §4.1.10 makes the two forms mean the same. Not checked against a real server.

## Active Directory flavour

- Error texts carry the data codes a domain controller sends (`data 52e`, `533`, `775`, ...). The DSID numbers and the
  `v2580`/`v4563` suffixes are fixed; on a real domain controller they vary by Windows version. A user that does not
  exist gets `data 525` here; many domain controllers answer `data 52e` for that too, so code should not tell the two
  apart to the person logging in.
- A subtree search from the domain root returns only entries; a real domain controller adds continuation references
  to its application partitions (DomainDnsZones, ForestDnsZones) and Configuration. Add them with `WithReferral` to
  test code against them, as the ActiveDirectory sample does.
- Referrals stand for other domains, but come from referral entries said outright rather than from `crossRef`
  objects in the configuration partition. URLs carry an explicit scope (`??sub`, `??base`); a real domain
  controller may leave it out. A search with the domain scope control gets no references; from memory, not checked
  against a domain controller.
- The primary group (Domain Users) is reported through `primaryGroupID`, `tokenGroups` and `primaryGroupToken`. As on
  a domain controller, the generated group does not list its members in `member`, so it is not in `memberOf`.
- Passwords are set through `unicodePwd` (reset and change). There is no password policy: length, history and
  complexity are not checked. `RequireTlsForUnicodePwd` makes the server refuse `unicodePwd` over plain `ldap://`,
  as a domain controller does; it is off by default so that tests need no certificate.
- Through ADSI (`DirectoryEntry`): `Invoke("SetPassword")`, `Invoke("ChangePassword")` and `ObjectSecurity` are not
  supported, and the default `AuthenticationTypes.Secure` is refused; use `AuthenticationTypes.None`.
- There are no security descriptors, no Global Catalog port and no configuration or schema partitions beyond the
  subschema entry.

## Test-only behaviour

- `Requests`, `LastAnswer`, `Last<T>()`, `ProtocolErrors` and `InternalErrors` record what happened, for assertions.
- Interceptors (`Intercept`, `FailWith<T>`) can answer any request with any result, referrals included, before the
  server looks at it.
- Malformed input closes only the connection it came on; an exception inside the server becomes an `other` (80)
  answer instead of taking the server down.
