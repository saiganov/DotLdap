using System.DirectoryServices.Protocols;
using System.Net;
using DotLdap.Testing.Protocol;
using ResultCode = DotLdap.Testing.Protocol.ResultCode;
using SdsResultCode = System.DirectoryServices.Protocols.ResultCode;
using SdsSearchRequest = System.DirectoryServices.Protocols.SearchRequest;
using SdsSearchScope = System.DirectoryServices.Protocols.SearchScope;
using SdsLdapConnection = System.DirectoryServices.Protocols.LdapConnection;
using SdsCompareRequest = System.DirectoryServices.Protocols.CompareRequest;

namespace DotLdap.Testing.Tests;

/// <summary>The server driven by Microsoft's client, System.DirectoryServices.Protocols (libldap on Linux, wldap32 on Windows).</summary>
public class SystemDirectoryServicesTests : IClassFixture<SystemDirectoryServicesTests.Fixture>
{
    public class Fixture : LdapServerFixture
    {
        protected override void Configure(LdapTestServerBuilder builder) => builder
            .WithBaseDn("dc=example,dc=com")
            .WithUser("alice", "alice-secret", u => u.Email("alice@example.com").DisplayName("Alice Liddell").MemberOf("admins", "staff"))
            .WithUser("bob", "bob-secret", u => u.Email("bob@example.com").MemberOf("staff"))
            .WithUser("mallory", "mallory-secret", u => u.Disabled())
            .WithUser("svc-app", "svc-secret");
    }

    private const string ServiceDn = "uid=svc-app,ou=users,dc=example,dc=com";
    private readonly LdapTestServer _server;

    public SystemDirectoryServicesTests(Fixture fixture) => _server = fixture.Server;

    private SdsLdapConnection Connect(string? dn = ServiceDn, string? password = "svc-secret")
    {
        var connection = new SdsLdapConnection(new LdapDirectoryIdentifier(_server.Host, _server.Port))
        {
            AuthType = dn is null ? AuthType.Anonymous : AuthType.Basic,
            Credential = dn is null ? null : new NetworkCredential(dn, password),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.Bind();
        return connection;
    }

    private static SearchResponse Search(SdsLdapConnection connection, string baseDn, string filter, SdsSearchScope scope = SdsSearchScope.Subtree, params string[] attributes) =>
        (SearchResponse)connection.SendRequest(new SdsSearchRequest(baseDn, filter, scope, attributes));

    [Fact]
    public void Bind_with_valid_credentials_succeeds()
    {
        using var connection = Connect("uid=alice,ou=users,dc=example,dc=com", "alice-secret");
    }

    [Theory]
    [InlineData("uid=alice,ou=users,dc=example,dc=com", "wrong")]
    [InlineData("uid=nobody,ou=users,dc=example,dc=com", "whatever")]
    [InlineData("uid=mallory,ou=users,dc=example,dc=com", "mallory-secret")] // disabled account
    public void Bind_with_bad_credentials_fails_with_49(string dn, string password)
    {
        var e = Assert.Throws<LdapException>(() => Connect(dn, password));
        Assert.Equal((int)ResultCode.InvalidCredentials, e.ErrorCode);
    }

    [Fact]
    public void Dn_with_empty_password_is_not_a_successful_login()
    {
        // The classic LDAP login bypass: a server that treats "DN + empty password" as an anonymous success.
        Assert.Throws<DirectoryOperationException>(() => Connect("uid=alice,ou=users,dc=example,dc=com", ""));
        var bind = _server.Requests.Last(r => r.Request is BindRequest);
        Assert.Equal(ResultCode.UnwillingToPerform, bind.Result!.Code);
    }

    [Fact]
    public void Typical_login_flow_search_then_bind_as_user()
    {
        using var service = Connect();
        var found = Search(service, "dc=example,dc=com", "(&(objectClass=inetOrgPerson)(mail=alice@example.com))", SdsSearchScope.Subtree, "uid", "displayName", "memberOf");
        var entry = Assert.Single(found.Entries.Cast<SearchResultEntry>());
        Assert.Equal("uid=alice,ou=users,dc=example,dc=com", entry.DistinguishedName);
        Assert.Equal("Alice Liddell", entry.Attributes["displayName"][0]);
        var groups = entry.Attributes["memberOf"].GetValues(typeof(string)).Cast<string>().OrderBy(x => x).ToArray();
        Assert.Equal(["cn=admins,ou=groups,dc=example,dc=com", "cn=staff,ou=groups,dc=example,dc=com"], groups);

        using var user = Connect(entry.DistinguishedName, "alice-secret");
    }

    [Fact]
    public void Search_scopes()
    {
        using var connection = Connect();
        Assert.Single(Search(connection, "dc=example,dc=com", "(objectClass=*)", SdsSearchScope.Base).Entries);
        Assert.Equal(2, Search(connection, "dc=example,dc=com", "(objectClass=*)", SdsSearchScope.OneLevel).Entries.Count); // ou=users, ou=groups
        Assert.Equal(4, Search(connection, "ou=users,dc=example,dc=com", "(objectClass=*)", SdsSearchScope.OneLevel).Entries.Count);
    }

    [Fact]
    public void Password_and_operational_attributes_are_not_returned_by_default()
    {
        using var connection = Connect();
        var entry = (SearchResultEntry)Search(connection, "dc=example,dc=com", "(uid=alice)").Entries[0];
        Assert.False(entry.Attributes.Contains("userPassword"));
        Assert.False(entry.Attributes.Contains("memberOf"));
        Assert.True(entry.Attributes.Contains("mail"));
    }

    [Fact]
    public void Missing_base_dn_gives_noSuchObject()
    {
        using var connection = Connect();
        var e = Assert.Throws<DirectoryOperationException>(() => Search(connection, "ou=missing,dc=example,dc=com", "(objectClass=*)"));
        Assert.Equal(SdsResultCode.NoSuchObject, e.Response.ResultCode);
        Assert.Equal("dc=example,dc=com", e.Response.MatchedDN);
    }

    [Fact]
    public void Anonymous_can_read_root_dse_but_not_the_tree()
    {
        using var connection = Connect(null, null);
        var rootDse = (SearchResultEntry)Search(connection, "", "(objectClass=*)", SdsSearchScope.Base).Entries[0];
        Assert.Equal("dc=example,dc=com", rootDse.Attributes["namingContexts"][0]);
        Assert.Equal("3", rootDse.Attributes["supportedLDAPVersion"][0]);

        var e = Assert.Throws<DirectoryOperationException>(() => Search(connection, "dc=example,dc=com", "(uid=alice)"));
        Assert.Equal(SdsResultCode.InsufficientAccessRights, e.Response.ResultCode);
    }

    [Fact]
    public void Paged_search_walks_all_pages()
    {
        using var server = LdapTestServer.Create()
            .Configure(d => { for (var i = 0; i < 25; i++) d.AddUser($"user{i:00}", "pw"); })
            .WithMaxSearchResults(10)
            .Start();
        using var connection = new SdsLdapConnection(new LdapDirectoryIdentifier(server.Host, server.Port))
        {
            AuthType = AuthType.Basic,
            Credential = new NetworkCredential("uid=user00,ou=users,dc=example,dc=com", "pw"),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.Bind();

        // Without paging the server-side limit kicks in, as with MaxPageSize in Active Directory.
        var limited = Assert.Throws<DirectoryOperationException>(() => Search(connection, "dc=example,dc=com", "(uid=*)"));
        Assert.Equal(SdsResultCode.SizeLimitExceeded, limited.Response.ResultCode);
        Assert.Equal(10, ((SearchResponse)limited.Response).Entries.Count);

        var names = new List<string>();
        var pages = 0;
        var paging = new PageResultRequestControl(10);
        while (true)
        {
            var request = new SdsSearchRequest("dc=example,dc=com", "(uid=*)", SdsSearchScope.Subtree, "uid");
            request.Controls.Add(paging);
            var response = (SearchResponse)connection.SendRequest(request);
            pages++;
            names.AddRange(response.Entries.Cast<SearchResultEntry>().Select(e => (string)e.Attributes["uid"][0]));
            var cookie = response.Controls.OfType<PageResultResponseControl>().Single().Cookie;
            if (cookie.Length == 0) break;
            paging.Cookie = cookie;
        }
        Assert.Equal(3, pages);
        Assert.Equal(25, names.Distinct().Count());
    }

    [Fact]
    public void Compare()
    {
        using var connection = Connect();
        var yes = (CompareResponse)connection.SendRequest(new SdsCompareRequest("uid=alice,ou=users,dc=example,dc=com", "mail", "ALICE@example.com"));
        var no = (CompareResponse)connection.SendRequest(new SdsCompareRequest("uid=alice,ou=users,dc=example,dc=com", "mail", "bob@example.com"));
        Assert.Equal(SdsResultCode.CompareTrue, yes.ResultCode);
        Assert.Equal(SdsResultCode.CompareFalse, no.ResultCode);
    }

    [Fact]
    public void Directory_can_change_while_the_server_runs()
    {
        using var connection = Connect();
        _server.Directory.AddUser("temp", "pw");
        Assert.Single(Search(connection, "dc=example,dc=com", "(uid=temp)").Entries);
        _server.Directory.Remove("uid=temp,ou=users,dc=example,dc=com");
        Assert.Empty(Search(connection, "dc=example,dc=com", "(uid=temp)").Entries);
    }

    [Fact]
    public void Requests_are_recorded_for_assertions()
    {
        using var server = LdapTestServer.Create().WithUser("alice", "pw").Start();
        using (var connection = new SdsLdapConnection(new LdapDirectoryIdentifier(server.Host, server.Port))
               {
                   AuthType = AuthType.Basic,
                   Credential = new NetworkCredential("uid=alice,ou=users,dc=example,dc=com", "pw"),
               })
        {
            connection.SessionOptions.ProtocolVersion = 3;
            connection.Bind();
            Search(connection, "dc=example,dc=com", "(&(objectClass=person)(uid=al*))");
        }

        var bind = Assert.Single(server.Requests.Select(r => r.Request).OfType<BindRequest>());
        Assert.Equal("uid=alice,ou=users,dc=example,dc=com", bind.Name);
        var search = server.Requests.Single(r => r.Request is Protocol.SearchRequest);
        Assert.Equal("(&(objectClass=person)(uid=al*))", ((Protocol.SearchRequest)search.Request).Filter.ToString());
        Assert.Equal(ResultCode.Success, search.Result!.Code);
        Assert.Empty(server.ProtocolErrors);
    }

    [Fact]
    public void Faults_can_be_injected()
    {
        using var connection = Connect();
        using (_server.FailWith<Protocol.SearchRequest>(ResultCode.Busy, "try later"))
        {
            var e = Assert.Throws<DirectoryOperationException>(() => Search(connection, "dc=example,dc=com", "(uid=alice)"));
            Assert.Equal(SdsResultCode.Busy, e.Response.ResultCode);
            Assert.Equal("try later", e.Response.ErrorMessage);
        }
        Assert.Single(Search(connection, "dc=example,dc=com", "(uid=alice)").Entries);
    }
}

/// <summary>Active Directory flavour: the things applications written against AD rely on.</summary>
public class ActiveDirectoryFlavorTests : IDisposable
{
    private readonly LdapTestServer _server = LdapTestServer.Create()
        .AsActiveDirectory()
        .WithBaseDn("DC=corp,DC=example,DC=com")
        .WithUser("alice", "alice-secret", u => u.Email("alice@corp.example.com").MemberOf("Developers"))
        .WithUser("bob", "bob-secret", u => u.Disabled())
        .WithGroup("Engineering", "Developers")
        .Start();

    public void Dispose() => _server.Dispose();

    private SdsLdapConnection Connect(string user, string password)
    {
        var connection = new SdsLdapConnection(new LdapDirectoryIdentifier(_server.Host, _server.Port))
        {
            AuthType = AuthType.Basic,
            Credential = new NetworkCredential(user, password),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.Bind();
        return connection;
    }

    [Theory]
    [InlineData("CN=alice,CN=Users,DC=corp,DC=example,DC=com")]
    [InlineData("alice@corp.example.com")]
    [InlineData("CORP\\alice")]
    public void Bind_accepts_dn_upn_and_down_level_names(string name)
    {
        using var connection = Connect(name, "alice-secret");
    }

    [Fact]
    public void User_entries_look_like_ad_and_nested_groups_resolve_in_one_query()
    {
        using var connection = Connect("alice@corp.example.com", "alice-secret");
        var response = (SearchResponse)connection.SendRequest(new SdsSearchRequest(
            "DC=corp,DC=example,DC=com",
            "(&(objectClass=user)(sAMAccountName=alice))",
            SdsSearchScope.Subtree));
        var alice = Assert.Single(response.Entries.Cast<SearchResultEntry>());
        Assert.Equal("CN=alice,CN=Users,DC=corp,DC=example,DC=com", alice.DistinguishedName);
        Assert.Equal("alice@corp.example.com", alice.Attributes["userPrincipalName"][0]);
        Assert.Equal(16, ((byte[])alice.Attributes["objectGUID"].GetValues(typeof(byte[]))[0]).Length);
        Assert.Equal("CN=Developers,CN=Users,DC=corp,DC=example,DC=com", alice.Attributes["memberOf"][0]); // returned with "*", as in AD
        Assert.Equal(alice.DistinguishedName, alice.Attributes["distinguishedName"][0]);

        var nested = (SearchResponse)connection.SendRequest(new SdsSearchRequest(
            "DC=corp,DC=example,DC=com",
            "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Engineering,CN=Users,DC=corp,DC=example,DC=com))",
            SdsSearchScope.Subtree, "sAMAccountName"));
        Assert.Equal("alice", Assert.Single(nested.Entries.Cast<SearchResultEntry>()).Attributes["sAMAccountName"][0]);
    }

    [Fact]
    public void Search_by_binary_object_guid()
    {
        var guid = _server.Directory.Find("CN=alice,CN=Users,DC=corp,DC=example,DC=com")!.GetValues("objectGUID")[0];
        var filter = "(objectGUID=" + string.Concat(guid.Select(b => "\\" + b.ToString("x2"))) + ")";
        using var connection = Connect("alice@corp.example.com", "alice-secret");
        var response = (SearchResponse)connection.SendRequest(new SdsSearchRequest("DC=corp,DC=example,DC=com", filter, SdsSearchScope.Subtree));
        Assert.Single(response.Entries);
    }

    [Fact]
    public void Root_dse_has_default_naming_context()
    {
        using var connection = Connect("alice@corp.example.com", "alice-secret");
        var response = (SearchResponse)connection.SendRequest(new SdsSearchRequest("", "(objectClass=*)", SdsSearchScope.Base, "defaultNamingContext"));
        Assert.Equal("DC=corp,DC=example,DC=com", ((SearchResultEntry)response.Entries[0]).Attributes["defaultNamingContext"][0]);
    }
}
