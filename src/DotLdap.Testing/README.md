# DotLdap.Testing

An LDAP server that runs inside your .NET test process: no Docker, no config files. It starts in milliseconds on a free port of 127.0.0.1, its data is defined in code, and it comes in a generic (OpenLDAP-like) and an Active Directory flavour.

```csharp
using DotLdap.Testing;

using var ldap = LdapTestServer.Create()
    .WithUser("alice", "s3cret", u => u.Email("alice@example.com").MemberOf("admins"))
    .WithTls()
    .Start();

// point the code under test at ldap.Url (ldap://127.0.0.1:port) or ldap.LdapsUrl
Assert.True(new MyAuthenticator(ldap.Url).Login("alice", "s3cret"));
// full name: System.DirectoryServices.Protocols has a ResultCode too
Assert.Equal(DotLdap.Testing.Protocol.ResultCode.Success, ldap.LastAnswer!.Result!.Code);
```

```csharp
using var ad = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com")
    .WithUser("bob", "hunter2", u => u.LockedOut())   // a bind as bob@corp.example.com fails with "data 775"
    .Start();
```

Works with System.DirectoryServices.Protocols, Novell.Directory.Ldap, ADSI (`DirectoryEntry`) and any client that speaks LDAP over TCP.

Documentation, samples and the list of differences from real servers: [https://github.com/saiganov/DotLdap](https://github.com/saiganov/DotLdap).
