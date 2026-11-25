# DotLdap.Testing

An LDAP server that runs inside your .NET test process. No Docker, no config files: it starts in
milliseconds on a free port and its data is defined in code.

```csharp
using DotLdap.Testing;

using var ldap = LdapTestServer.Create()
    .WithBaseDn("dc=example,dc=com")
    .WithUser("alice", "s3cret", u => u.Email("alice@example.com").MemberOf("admins"))
    .WithUser("bob", "hunter2")
    .WithTls()                       // StartTLS + ldaps:// with a generated certificate
    .Start();

// point the code under test at ldap.Host / ldap.Port (or ldap.Url, ldap.LdapsUrl)
var sut = new MyLdapAuthenticator(ldap.Host, ldap.Port, baseDn: "dc=example,dc=com");
Assert.True(sut.Login("alice", "s3cret"));

// assert on what the code sent, change data on the fly, inject faults
Assert.Contains(ldap.Requests, r => r.Request is DotLdap.Testing.Protocol.SearchRequest);
Assert.Equal(DotLdap.Testing.Protocol.ResultCode.Success, ldap.LastAnswer!.Result!.Code);
ldap.Directory.AddUser("carol", "pw");
using (ldap.FailWith<DotLdap.Testing.Protocol.SearchRequest>(DotLdap.Testing.Protocol.ResultCode.Busy)) { /* ... */ }
```

`Requests[^1]` is not always the request the test has just made: a client closes a connection on its own
time, and its unbind (which has no answer) is recorded whenever the server gets to it. `LastAnswer` is the
last request the server answered, and `Last<BindRequest>()` the last request of one type.

Active Directory flavour (`CN=…,CN=Users`, `sAMAccountName`, `userPrincipalName`, `objectGUID`, `objectSid`,
bind by UPN or `DOMAIN\user`, `data 52e` error texts, `memberOf` with nested-group matching rule, `tokenGroups`,
ranged retrieval):

```csharp
using var ad = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com")
    .WithUser("alice", "s3cret", u => u.MemberOf("Developers"))
    .WithUser("bob", "hunter2", u => u.LockedOut())      // also Disabled(), MustChangePassword(),
    .WithGroup("Engineering", "Developers")               // AccountExpired(), PasswordExpired()
    .Start();
```

Data from a JSON file, for both flavours alike (`WithJson`, `WithJsonFile`, `server.Directory.AddJson`):

```json
{
  "users": [
    { "name": "alice", "password": "s3cret", "email": "alice@example.com", "groups": ["admins"],
      "attributes": { "title": "Engineer", "telephoneNumber": ["+1 555 0100", "+1 555 0101"] } },
    { "name": "bob", "password": "hunter2", "disabled": true }
  ],
  "groups": [ { "name": "staff", "members": ["alice", "admins"] } ],
  "entries": [
    { "dn": "ou=printers,dc=example,dc=com",
      "attributes": { "objectClass": ["top", "organizationalUnit"], "ou": "printers" } }
  ]
}
```

Users and groups are what `WithUser` and `WithGroup` make of them. A user also takes `displayName`, `firstName`,
`lastName` and the flags `disabled`, `lockedOut`, `mustChangePassword`, `accountExpired`, `passwordExpired`,
`readOnly`; `attributes` come after the named properties and may replace what they set, flags come last. The
order within the file is free: everything is created first and memberships are filled in afterwards, so a group
may be named by a user, listed under `groups`, and have members defined further down. A member or group is given
by name or by DN: a member's name must be a user or group of the directory, a member's DN is taken as it is, and
a group a user names by DN must exist (by name it is created). A membership stated twice is kept once. A value is a string, a number, a boolean or `{ "base64": "…" }`; comments and trailing commas
are allowed. A property the format does not know is an error that names its place (`$.users[1].mail`), and a
mistake in the file is found before anything is added. What only the directory can refuse, such as an entry that
exists already, is found on the way, after what came before it has been added.

Shared server for a test class (works with xUnit, NUnit and MSTest, no framework dependency):

```csharp
public class LdapFixture : LdapServerFixture
{
    protected override void Configure(LdapTestServerBuilder b) => b.WithLdifFile("testdata/users.ldif");
}
public class LoginTests(LdapFixture ldap) : IClassFixture<LdapFixture> { /* ldap.Server ... */ }
```

## What works

- Simple Bind (DN; in AD flavour also UPN and `DOMAIN\user`), anonymous bind, Unbind, Abandon
- SASL PLAIN bind in the generic flavour, announced in `supportedSASLMechanisms`; the AD flavour refuses it, as
  a domain controller does. The name is the user's `uid` or a DN, with `u:` or `dn:` in front or not. (Which
  forms a real server takes depends on how it maps SASL names to entries.) An authorization
  identity has to name the same user. TLS is not required. With Novell.Directory.Ldap:
  `connection.Bind(new SaslPlainRequest("alice", "alice-secret"))` (namespace `Novell.Directory.Ldap.Sasl`). That
  client reports every failed SASL bind as `Other` (80); what the server answered (`invalidCredentials`, or
  `authMethodNotSupported` in the AD flavour) is in `server.Requests`, where the bind reads
  `#1 Bind alice SASL PLAIN => Success` (`#1` is the connection) and the requests after it carry the DN in `BoundDn`
- Search: all scopes, all RFC 4511 filter types, attribute selection (`*`, `+`, `1.1`), typesOnly, size limit
- Simple paged results control, server-side sorting control (one key in the AD flavour, as on a domain
  controller, up to eight otherwise), server-side result limit (like AD's MaxPageSize). Text sorts without
  regard to case and otherwise by code point, the same on every machine; a real domain controller sorts by the
  rules of a language, so the order of names with punctuation or accented letters differs from it
- Add, Modify, Delete, ModifyDN (rename and subtree move) and Password Modify (not in the AD flavour,
  which uses `unicodePwd` as real AD does), with the result codes a real
  server gives (`entryAlreadyExists`, `noSuchAttribute`, `notAllowedOnNonLeaf`, `notAllowedOnRDN`, …);
  a Modify request is applied all-or-nothing
- Schema checks, off by default: with `WithSchemaChecks()` (or `server.Directory.SchemaChecks = true` in the
  middle of a test) an Add, Modify or ModifyDN is refused when it leaves a single-valued attribute with two
  values (`constraintViolation`) or writes a value its syntax does not allow, such as text for a number or something that is
  no DN for `manager` (`invalidAttributeSyntax`). Checked are the attributes the server knows, the well-known
  ones and those declared with `DefineAttribute(name, syntax, singleValued)`; an unknown attribute takes anything,
  and so does data loaded from code or LDIF. Which attributes an object class requires or allows is not checked
- Read-only users: `WithUser("reader", "pw", u => u.ReadOnly())`, `WithReadOnlyUser("cn=svc,…")` for a user
  from LDIF (after the `WithLdif` call that adds it), or `server.Directory.SetReadOnly(dn)` in the middle of a test. What such a user tries to write ends
  with `insufficientAccessRights` (50; in the AD flavour with the message of a domain controller, `problem 4003
  (INSUFF_ACCESS_RIGHTS)`), so a test can see what the application does when its account lacks the right.
  They bind, search and compare like everyone else and may change a password they know: Password Modify with the
  old password, in the AD flavour deleting the old `unicodePwd` and adding the new one
- Root DSE, Compare, WhoAmI, StartTLS, LDAPS
- AD matching rules: in-chain (`1.2.840.113556.1.4.1941`), bitwise AND/OR
- AD account states in bind errors: `data 525` (no such user), `52e` (wrong password), `533` (disabled),
  `775` (locked out), `701` (account expired), `532` (password expired), `773` (must change password)
- AD attributes filled in by the server: `objectCategory`, `sAMAccountType`, `primaryGroupID` with a
  "Domain Users" group, `name`, `whenCreated`, `pwdLastSet`, `accountExpires`. This applies to entries from
  the builder, from `WithEntry` and from LDIF alike; values the test data brings are kept, and a "Domain Users"
  group or a container listed in the data replaces the generated one
- AD lockout from imported data runs out after `DirectoryLayout.LockoutDuration` (30 minutes), as on a real
  domain controller; a lockout made with `LockedOut()` stays
- AD constructed attributes: `tokenGroups`, `primaryGroupToken`
- AD lookups: `(objectCategory=person)`, `(objectSid=S-1-5-21-…)`, search bases `<GUID=…>` and `<SID=…>`
- AD ranged retrieval: `member;range=0-1499`, then `member;range=1500-*` (limit set with `WithMaxValuesPerAttribute`)
- AD writes: passwords through `unicodePwd` (reset and change), generated `objectGUID`/`objectSid` on Add,
  group `member` links that follow renames and deletes; `RequireTlsForUnicodePwd` makes the server refuse
  `unicodePwd` over plain `ldap://`, as a real domain controller does
- Computed attributes (`memberOf`, `entryDN`, `distinguishedName`) with an extension point for more
- A published schema (`subschemaSubentry`), so that clients which need one get typed values: the well-known
  attributes of the flavour, the attributes found in the data, and attributes declared with `DefineAttribute`.
  Nothing is checked against it unless schema checks are turned on (below); see "System.DirectoryServices" below. Stored attributes the flavour's own schema
  knows as operational (`pwdAccountLockedTime`, `entryUUID`, … in the generic flavour; to the AD flavour those are
  ordinary attributes) are returned only when asked for
- Data from code (fluent), raw entries, LDIF or JSON; `userPassword` in plain text or `{MD5}`/`{SHA}`/`{SSHA}`/SHA-2 variants
- Request log and fault injection
- Referrals: a part of the tree other servers hold (`WithReferral`, or any entry of class `referral` with `ref`
  values, RFC 3296), and a default referral for names outside the directory; see "Referrals" below
- Malformed input never takes the server down: bytes that are not LDAP close that one connection and are listed
  in `ProtocolErrors`; an exception inside the server or in an interceptor becomes an `other` (80) answer and
  is kept in `InternalErrors`. Both lists are empty in a healthy test, which makes them a cheap last assertion

## System.DirectoryServices (`DirectoryEntry`, `DirectorySearcher`)

Both work against the server, in the AD flavour and in the generic one; the Windows job of the CI runs them
(`AdsiTests`). Two things to know:

**Use `AuthenticationTypes.None`.** The server speaks the simple bind only. `new DirectoryEntry(path, user, password)`
defaults to `AuthenticationTypes.Secure`, which means NTLM or Kerberos; so do `new DirectoryEntry(path)` and
`DirectoryEntry.Exists(path)`. The server refuses them with "the requested authentication method is not supported"
and says so in the extended error message. Code under test has to take the authentication type from configuration:

```csharp
using var root = new DirectoryEntry($"LDAP://{server.Host}:{server.Port}/{server.BaseDn}",
    "alice@corp.example.com", "alice-secret", AuthenticationTypes.None);
using var searcher = new DirectorySearcher(root, "(sAMAccountName=bob)") { PageSize = 500 };
```

**ADSI types values by the schema.** It reads the schema the server publishes and returns `int` for
`userAccountControl`, `DateTime` for `whenCreated`, `byte[]` for `objectSid`, and for `pwdLastSet` a `long` from
`DirectorySearcher` and a COM large integer from `DirectoryEntry`, as with a real domain controller. An attribute
it cannot find there is an error (`0x8000500C`). The server lists the well-known attributes of its flavour and
whatever the data holds: a custom attribute as a string, or as binary when a value is not text. (A name that is
not a letter followed by letters, digits and hyphens cannot be in a schema and is left out.) Declare what the
server cannot guess, a custom number or an attribute no entry has yet:

```csharp
LdapTestServer.Create().AsActiveDirectory()
    .Configure(d => d
        .DefineAttribute("badgeNumber", AttributeSyntax.Integer, singleValued: true) // as stated
        .DefineAttribute("costCenter"))                                              // just make it exist
```

ADSI caches schemas on disk under the DN of the subschema entry, for every process of the user. That is why the DN
the server publishes carries a hash of the schema (`CN=Aggregate-D601C983,CN=Schema,CN=Configuration,…`): two test
servers with different custom attributes never get each other's schema. The plain name answers as well.

Not supported through ADSI: `Invoke("SetPassword")` and `Invoke("ChangePassword")` (they need Kerberos or LDAPS
with a certificate Windows trusts; write `unicodePwd` instead, which is what they do underneath) and `ObjectSecurity` (there are no security descriptors).

## Referrals

For code that talks to more than one directory: a client that asks one server and is told to ask another.

```csharp
using var partners = LdapTestServer.Create().WithBaseDn("dc=partners,dc=net")
    .WithUser("bob", "bob-secret").AllowAnonymousSearch().Start();
using var ldap = LdapTestServer.Create()
    .WithUser("alice", "alice-secret")
    // this part of the tree is on the other server, under another name
    .WithReferral("ou=partners,dc=example,dc=com", $"ldap://{partners.Host}:{partners.Port}/ou=users,dc=partners,dc=net")
    .Start();
```

- A search whose scope reaches the referral entry gets a search result reference with its URLs in place of
  the entry and of anything below it, whatever the filter. The URLs end in `??sub`, or in `??base` for a
  search of one level. A search that is cut short by a size limit gets none; a paged search gets them with
  its last page.
- Any request that names the entry or something below it (search, compare, add, modify, delete, rename,
  Password Modify) ends with `referral` (10) and the URLs, where the name is rewritten for the other server:
  `uid=bob,ou=partners,dc=example,dc=com` becomes `ldap://…/uid=bob,ou=users,dc=partners,dc=net`. A URL
  without a DN means the same name. For a search the URLs also say the scope (`??base`, `??one`, `??sub`).
  A rename to under a referral entry, or to the name of one, ends with `affectsMultipleDSAs` (71).
- A referral entry is meant to have nothing below it. Entries that are there all the same are out of reach
  over the wire (unless the client sends ManageDsaIT), nobody can bind as one, and a name they share with a
  user of this server does not get in that user's way. But they are still data: a group down there shows in
  `memberOf`. A connection stays bound when its own entry goes behind a referral entry later.
- In `ref`, what follows a space is a label and is not sent. A blank value is left out, and an entry with nothing
  but blank values is an ordinary entry. A value that is no LDAP URL is sent as it is
  (RFC 3296 allows other kinds of URI); `WithReferral` takes LDAP URLs only, to catch typing mistakes.
- The URL can name a server that does not exist, to see what the code does with a referral it is handed, or a
  second test server, to see it followed. A client that follows usually arrives without credentials unless it
  was given some for the purpose; hence `AllowAnonymousSearch` above.
- Generic flavour: the ManageDsaIT control makes the referral entry an entry like any other, to read, change
  or delete it over the wire. `ref` is operational, so ask for it by name. From test code,
  `server.Directory` reaches the entry without ceremony.
- AD flavour: the same entries stand for other domains (a domain controller builds its references from
  `crossRef` objects; here they are said outright). A search with the domain scope control
  (`DomainScopeControl`, 1.2.840.113556.1.4.1339) gets no references. ManageDsaIT is unknown, as on a domain
  controller. The message of a `referral` answer is in the shape a domain controller uses
  (`0000202B: RefErr: DSID-…, data 0, 1 access points … ref 1: 'child.corp.example.com'`).
- `WithDefaultReferral("ldap://root.example.org")` answers requests for names outside every naming context of
  the directory with `referral` instead of `noSuchObject`. A URL without a DN gets the name that was asked for.
- A client that has not bound is told to bind before it is told where to go. Binds are not referred: a bind
  as a name behind a referral entry fails with `invalidCredentials`, whether or not an entry has that name.
- `new LdapResult(ResultCode.Referral, Referrals: [...])` from an interceptor sends a client away by hand.

## What does not exist yet

SASL other than PLAIN, NTLM, object class rules (which attributes a class requires or allows), access control beyond read-only users (every bound user reads everything, and writes everything unless marked read-only). Where the server knowingly differs from OpenLDAP or a domain controller is listed in [KNOWN_DIFFERENCES.md](KNOWN_DIFFERENCES.md).

## Samples

Each sample is a small application written the production way (the Api and ActiveDirectory samples have no DotLdap.Testing reference; the standalone server is built on it), with its test project next to it (`samples/DotLdap.Sample.*.Tests`) that points it at a test server:

| Sample | Scenario | What the tests show |
|---|---|---|
| [`Sample.Api`](samples/DotLdap.Sample.Api) | ASP.NET Core minimal API with a `/login` endpoint: bind as a service account, find the user, bind as the user, check a group (System.DirectoryServices.Protocols) | `WebApplicationFactory` with the LDAP settings pointed at the server; wrong passwords, a user outside the group, a filter-injection attempt read back from `Last<SearchRequest>()`, the order of binds from `Requests`, a directory that is down or goes down before the user bind, filter escaping, duplicate login names, a password changed while the test runs. |
| [`Sample.ActiveDirectory`](samples/DotLdap.Sample.ActiveDirectory) | Account code for Active Directory over ldaps:// (Novell.Directory.Ldap): login by UPN or `DOMAIN\user` with the reason for a refusal, nested groups, password reset | The AD flavour with TLS, trusting exactly the test server's certificate: every `data` code the sample reads (wrong password, disabled, locked out, expired, must change password, ...), filter escaping, duplicate names, continuation references skipped, the in-chain matching rule, `unicodePwd` resets with `RequireTlsForUnicodePwd` on. |
| [`Sample.Standalone`](samples/DotLdap.Sample.Standalone) | A console server on fixed ports for clients outside the process: `ldapsearch`, an LDAP browser, a service in a container | The server over TCP and ldaps:// as an outside client sees it, the AD flavour and an LDIF file from the command line. `dotnet run --project samples/DotLdap.Sample.Standalone -- --ad` prints the `ldapsearch` commands to try. |

The shortest version, from `Sample.Api`:

```csharp
using var ldap = LdapTestServer.Create()
    .WithEntry("ou=services,dc=example,dc=com", e => e.Set("objectClass", "organizationalUnit").Set("ou", "services"))
    .WithEntry("uid=svc-web,ou=services,dc=example,dc=com", e => e  // the API's service account
        .Set("objectClass", "account", "simpleSecurityObject").Set("uid", "svc-web").Set("userPassword", "svc-secret"))
    .WithUser("alice", "alice-secret", u => u.MemberOf("staff"))
    .Start();
using var api = new WebApplicationFactory<Program>().WithWebHostBuilder(host => host
    .UseSetting("Ldap:Url", ldap.Url)
    .UseSetting("Ldap:ServicePassword", "svc-secret"));
```

## How the library is tested

- `tests/DotLdap.Testing.Tests` drives the server through real clients over TCP: System.DirectoryServices.Protocols, Novell.Directory.Ldap.NETStandard and, on Windows, ADSI (`DirectoryEntry`, `DirectorySearcher`), plus a raw-socket client for what the libraries cannot send. CI runs it on Linux, Windows and macOS on every push and pull request, together with the samples' tests.
- `tests/DotLdap.Testing.Tests/Fuzzing` holds seeded fuzz tests for the frame reader, the decoder, the filter, DN and LDIF parsers and the server behind a raw socket. The run in CI is short and repeatable. Every night a run with fifty times the cases and a new seed looks further ([workflow](.github/workflows/nightly.yml)). For a longer hunt locally: `DOTLDAP_FUZZ_SCALE=50 DOTLDAP_FUZZ_SEED=12345 dotnet test --project tests/DotLdap.Testing.Tests --filter-namespace DotLdap.Testing.Tests.Fuzzing`; a failure prints the seed, the step and the input, and the case goes into `FuzzFindingsTests`.
- Each feature was reviewed in rounds, each with a hand mutation check of its tests; the pull requests list what was found.

## Performance

Time to the first green test: from the moment the OS starts a fresh process to a bind and a search that succeeded, without tearing down (median of 5 runs, image already pulled):

| | Time |
|---|---:|
| DotLdap.Testing | 0.14 s |
| OpenLDAP started by Testcontainers (`bitnamilegacy/openldap:2.6.10-debian-12-r1`) | 4.9 s |

After that, a test that builds its own server costs a few milliseconds, most of it the client connecting and disconnecting:

| Benchmark (through Novell.Directory.Ldap over TCP) | Mean | Allocated |
|---|---:|---:|
| New server, connect, bind, search, dispose | 6.1 ms | 178 KB |
| The same in the Active Directory flavour, bind by UPN | 6.3 ms | 222 KB |
| Bind | 0.18 ms | 74 KB |
| Compare | 0.51 ms | 72 KB |
| Add and delete an entry | 2.4 ms | 198 KB |
| Search one user by `uid` among 10,000 | 2.4 ms | 2.7 MB |
| Search 1,000 of 10,000 users by `memberOf` | 71 ms | 126 MB |
| Seed 100 users with `AddUser` (in process, no client) | 0.46 ms | 1.1 MB |
| Seed 10,000 users with `AddUser` | 120 ms | 105 MB |
| Seed 10,000 users from LDIF | 164 ms | 119 MB |

A search looks at every entry: there are no indexes, which is right for the few hundred entries a test usually has. A filter on `memberOf` computes the attribute for each entry it looks at, which is what makes the last search slow with 10,000 users.

Measured on 4 cores of an Intel Xeon at 2.7 GHz, Ubuntu 24.04, .NET 10.0.15, BenchmarkDotNet 0.15.8, Novell.Directory.Ldap 3.6.0 as the client (managed, so no native library is measured along with the server), Docker 29. The benchmarks are in `benchmarks/DotLdap.Testing.Benchmarks` and run by hand, not in CI:

```bash
dotnet run -c Release --project benchmarks/DotLdap.Testing.Benchmarks -- --filter '*'   # BenchmarkDotNet
dotnet run -c Release --project benchmarks/DotLdap.Testing.Benchmarks -- startup        # first green test vs OpenLDAP (needs Docker)
```

## Public API

Only what tests use is public: the server and its builder, the directory and its entries, the request records an interceptor and the request log see, and the extension point for computed attributes. The BER codec, the session, the filter evaluator and the schema catalogue are internal and may change in any release. The request records (`BindRequest`, `SearchRequest`, ..., `RecordedRequest`, `LdapRequestContext`) are made only by the server: they have `init` properties with defaults and no positional constructors or `Deconstruct`, and a `ToString()` of their own, so later releases can add a property without breaking code or changing the log text. Match them with property patterns, such as `context.Request is BindRequest { Name: "cn=svc,dc=example,dc=com" }`, and make one with an object initializer to test an interceptor on its own: `interceptor(new LdapRequestContext { Request = new BindRequest { Name = "cn=svc,dc=example,dc=com" }, IsTls = true })`. `LdapResult`, which interceptors create, keeps its constructor.

| Type | Why it is public |
|---|---|
| `LdapTestServer`, `LdapTestServerBuilder`, `LdapTestServerOptions` | The entry point: configure, start, `Url`, `Requests`, `Intercept`, `FailWith<T>`. |
| `InMemoryDirectory`, `DirectoryLayout`, `DirectoryFlavor`, `DirectorySeedExtensions`, `UserBuilder` | The data behind the server, readable and changeable while it runs. |
| `Entry`, `EntryAttribute`, `DistinguishedName`, `Rdn`, `LdifReader`, `AttributeSyntax` | Building and inspecting data. |
| `RecordedRequest`, `LdapRequestContext`, `LdapRequestInterceptor` | The request log and fault injection. |
| `DotLdap.Testing.Protocol` records (`BindRequest`, `SearchRequest`, ..., `LdapResult`, `ResultCode`, `LdapFilter`) | What a test asserts on and what an interceptor answers with. |
| `IVirtualAttributeProvider`, `VirtualAttribute`, `IDirectoryView` | Computed attributes, the extension point for server-specific behaviour. |
| `LdapServerFixture` | A shared server for a test class, with no test framework dependency. |

## Installing

The package goes to nuget.org as a pre-release until 1.0, so pass `--prerelease`:

```bash
dotnet add package DotLdap.Testing --prerelease
```

Packages are published only from `v*` tags (for example `v0.1.0-preview.1`), with symbols and Source Link; pushes to `main` build, test and pack without publishing. Publishing uses nuget.org Trusted Publishing: the repository needs a `NUGET_USER` secret (the nuget.org account name) and a trusted publishing policy for `ci.yml` on nuget.org.

## Building

```bash
dotnet build
dotnet test --project tests/DotLdap.Testing.Tests
dotnet test --project samples/DotLdap.Sample.Api.Tests    # and the other samples/*.Tests projects
```

Requires the .NET 10 SDK (see `global.json`); the library targets `net8.0`; its tests run on both `net8.0` and `net10.0` (so the .NET 8 runtime must be installed too), and the samples and benchmarks target `net10.0`. On Linux, `System.DirectoryServices.Protocols` (used by the tests and `Sample.Api`) needs the OpenLDAP client library `libldap`; the library itself has no native or package dependencies.

Warnings are errors. Every public member of the library has an XML comment (CS1591), and package versions are set in one place, `Directory.Packages.props`. Dependabot opens weekly grouped PRs for NuGet packages and GitHub Actions; it leaves System.DirectoryServices.Protocols alone, since its Linux build looks for libldap under the soname the CI step provides.

### Changing the public API

`src/DotLdap.Testing` has `PublicAPI.Shipped.txt` and `PublicAPI.Unshipped.txt`, checked by `Microsoft.CodeAnalysis.PublicApiAnalyzers`. Adding, removing or changing a public member fails the build (RS0016/RS0017) until the line is added to or removed from `PublicAPI.Unshipped.txt`; the IDE code fix, or `dotnet format analyzers src/DotLdap.Testing --diagnostics RS0016 --severity warn`, writes the line for you. When a version is released, move every line from `Unshipped` to the end of `Shipped` (keeping the `#nullable enable` header in both files) in the release commit, so `Unshipped` lists only what changed since the last release. `pack` also runs package validation; a baseline version for it is set after 1.0.0. Release notes go into `RELEASE_NOTES.md` under a `#### X.Y.Z` heading that matches `VersionPrefix` in `Directory.Build.props`; packing fails without one.

## Security

Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes, not in a public issue.

## License

[MIT](LICENSE)
