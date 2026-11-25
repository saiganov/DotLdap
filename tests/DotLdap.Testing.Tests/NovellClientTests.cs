using Novell.Directory.Ldap;
using LdapConnection = Novell.Directory.Ldap.LdapConnection;
using LdapEntry = Novell.Directory.Ldap.LdapEntry;

namespace DotLdap.Testing.Tests;

/// <summary>The server driven by a fully managed client (Novell.Directory.Ldap.NETStandard), including TLS.</summary>
public class NovellClientTests : IDisposable
{
    private readonly LdapTestServer _server = LdapTestServer.Create()
        .WithUser("alice", "alice-secret", u => u.Email("alice@example.com").MemberOf("admins"))
        .WithUser("bob", "bob-secret")
        .WithTls()
        .Start();

    public void Dispose() => _server.Dispose();

    private const string AliceDn = "uid=alice,ou=users,dc=example,dc=com";

    private LdapConnectionOptions TrustingOnlyTheServerCertificate() => new LdapConnectionOptions()
        .ConfigureRemoteCertificateValidationCallback((_, certificate, _, _) =>
            certificate is not null && certificate.GetCertHashString() == _server.Certificate!.GetCertHashString());

    private static List<LdapEntry> SearchAll(LdapConnection connection, string filter, params string[] attributes)
    {
        var results = connection.Search("dc=example,dc=com", LdapConnection.ScopeSub, filter, attributes, false);
        var entries = new List<LdapEntry>();
        while (results.HasMore()) entries.Add(results.Next());
        return entries;
    }

    [Fact]
    public void Plain_bind_and_search()
    {
        using var connection = new LdapConnection();
        connection.Connect(_server.Host, _server.Port);
        connection.Bind(AliceDn, "alice-secret");
        Assert.True(connection.Bound);

        var entries = SearchAll(connection, "(|(uid=alice)(uid=bob))", "uid", "mail", "memberOf");
        Assert.Equal(2, entries.Count);
        var alice = entries.Single(e => e.Dn == AliceDn);
        Assert.Equal("alice@example.com", alice.GetAttribute("mail").StringValue);
        Assert.Equal("cn=admins,ou=groups,dc=example,dc=com", alice.GetAttribute("memberOf").StringValue);
    }

    [Fact]
    public void Wrong_password_is_rejected()
    {
        using var connection = new LdapConnection();
        connection.Connect(_server.Host, _server.Port);
        var e = Assert.Throws<LdapException>(() => connection.Bind(AliceDn, "nope"));
        Assert.Equal(LdapException.InvalidCredentials, e.ResultCode);
    }

    [Theory]
    [InlineData("alice@corp.example.com", "wrong", "data 52e")]
    [InlineData("ghost@corp.example.com", "wrong", "data 525")]
    [InlineData("bob@corp.example.com", "bob-secret", "data 533")]
    [InlineData("bob@corp.example.com", "wrong", "data 52e")] // account state is revealed only to the right password
    [InlineData("locked@corp.example.com", "locked-secret", "data 775")]
    [InlineData("locked@corp.example.com", "wrong", "data 775")] // ...except a lockout
    [InlineData("expired@corp.example.com", "expired-secret", "data 701")]
    [InlineData("stale@corp.example.com", "stale-secret", "data 532")]
    [InlineData("newbie@corp.example.com", "newbie-secret", "data 773")]
    [InlineData("both@corp.example.com", "both-secret", "data 533")] // disabled wins, in whichever order the flags were set
    [InlineData("both2@corp.example.com", "both-secret", "data 533")]
    public void Active_directory_bind_failures_carry_the_sub_code(string name, string password, string expected)
    {
        using var server = LdapTestServer.Create()
            .AsActiveDirectory()
            .WithBaseDn("DC=corp,DC=example,DC=com")
            .WithUser("alice", "alice-secret")
            .WithUser("bob", "bob-secret", u => u.Disabled())
            .WithUser("locked", "locked-secret", u => u.LockedOut())
            .WithUser("expired", "expired-secret", u => u.AccountExpired())
            .WithUser("stale", "stale-secret", u => u.PasswordExpired())
            .WithUser("newbie", "newbie-secret", u => u.MustChangePassword())
            .WithUser("both", "both-secret", u => u.Disabled().PasswordExpired())
            .WithUser("both2", "both-secret", u => u.PasswordExpired().Disabled())
            .Start();
        using var connection = new LdapConnection();
        connection.Connect(server.Host, server.Port);
        var e = Assert.Throws<LdapException>(() => connection.Bind(name, password));
        Assert.Equal(LdapException.InvalidCredentials, e.ResultCode);
        Assert.Contains(expected, e.LdapErrorMessage);
    }

    [Fact]
    public void Add_modify_rename_delete()
    {
        using var connection = new LdapConnection();
        connection.Connect(_server.Host, _server.Port);
        connection.Bind(AliceDn, "alice-secret");

        const string carol = "uid=carol,ou=users,dc=example,dc=com";
        connection.Add(new LdapEntry(carol, new LdapAttributeSet
        {
            new LdapAttribute("objectClass", new[] { "top", "person", "inetOrgPerson" }),
            new LdapAttribute("cn", "Carol"),
            new LdapAttribute("sn", "Example"),
        }));
        connection.Modify(carol, new LdapModification(LdapModification.Add, new LdapAttribute("mail", "carol@example.com")));
        connection.Modify(carol, new LdapModification(LdapModification.Replace, new LdapAttribute("sn", "Renamed")));
        Assert.Equal("carol@example.com", Assert.Single(SearchAll(connection, "(sn=Renamed)", "mail")).GetAttribute("mail").StringValue);

        connection.Rename(carol, "uid=caroline", true);
        Assert.Single(SearchAll(connection, "(uid=caroline)"));
        Assert.Empty(SearchAll(connection, "(uid=carol)"));

        connection.Delete("uid=caroline,ou=users,dc=example,dc=com");
        Assert.Empty(SearchAll(connection, "(uid=caroline)"));

        var e = Assert.Throws<LdapException>(() => connection.Delete("ou=users,dc=example,dc=com"));
        Assert.Equal(LdapException.NotAllowedOnNonleaf, e.ResultCode);
    }

    [Fact]
    public void Ldaps()
    {
        using var connection = new LdapConnection(TrustingOnlyTheServerCertificate().UseSsl());
        connection.Connect(_server.Host, _server.LdapsPort!.Value);
        connection.Bind(AliceDn, "alice-secret");
        Assert.Single(SearchAll(connection, "(uid=bob)"));
        Assert.Contains(_server.Requests, r => r.IsTls && r.Request is Protocol.SearchRequest);
    }

    [Fact]
    public void StartTls()
    {
        using var connection = new LdapConnection(TrustingOnlyTheServerCertificate());
        connection.Connect(_server.Host, _server.Port);
        connection.StartTls();
        connection.Bind(AliceDn, "alice-secret");
        Assert.Single(SearchAll(connection, "(uid=bob)"));
        var bind = _server.Requests.Single(r => r.Request is Protocol.BindRequest);
        Assert.True(bind.IsTls);
    }
}
