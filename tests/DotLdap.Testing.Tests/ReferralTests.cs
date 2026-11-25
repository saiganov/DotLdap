using System.DirectoryServices.Protocols;
using System.Net;
using DotLdap.Testing.Protocol;
using DotLdap.Testing.Tests.Fuzzing;
using ResultCode = DotLdap.Testing.Protocol.ResultCode;
using SdsResultCode = System.DirectoryServices.Protocols.ResultCode;
using SdsSearchRequest = System.DirectoryServices.Protocols.SearchRequest;
using SdsSearchScope = System.DirectoryServices.Protocols.SearchScope;
using SdsAddRequest = System.DirectoryServices.Protocols.AddRequest;
using SdsModifyRequest = System.DirectoryServices.Protocols.ModifyRequest;
using SdsDeleteRequest = System.DirectoryServices.Protocols.DeleteRequest;
using SdsModifyDnRequest = System.DirectoryServices.Protocols.ModifyDNRequest;
using SdsCompareRequest = System.DirectoryServices.Protocols.CompareRequest;
using SdsExtendedRequest = System.DirectoryServices.Protocols.ExtendedRequest;
using LdapConnection = System.DirectoryServices.Protocols.LdapConnection;

namespace DotLdap.Testing.Tests;

/// <summary>
/// Referrals: entries that stand for a part of the tree another server holds (RFC 3296), and the default
/// referral for names outside the directory. Seen through Microsoft's client with referral chasing off, and
/// followed for real, to a second test server, by the Novell client.
/// </summary>
public class ReferralTests
{
    private const string Base = "dc=example,dc=com";
    private const string Admin = "uid=admin,ou=users,dc=example,dc=com";
    private const string Partners = "ou=partners,dc=example,dc=com";
    private const string There = "ldap://partners.example.net/ou=people,dc=partners,dc=net";
    private const string Backup = "ldap://backup.example.net:1389/ou=people,dc=partners,dc=net";

    private static LdapTestServerBuilder Generic() => LdapTestServer.Create()
        .WithUser("admin", "admin-secret")
        .WithUser("alice", "alice-secret")
        .WithReferral(Partners, There, Backup);

    private static LdapConnection Connect(LdapTestServer server, string? user = Admin, string password = "admin-secret")
    {
        var connection = new LdapConnection(new LdapDirectoryIdentifier(server.Host, server.Port))
        {
            AuthType = user is null ? AuthType.Anonymous : AuthType.Basic,
            Credential = user is null ? null : new NetworkCredential(user, password),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None; // the tests look at what the server said
        connection.Bind();
        return connection;
    }

    /// <summary>The response, whether the client returns it or throws it (which of the two depends on the platform).</summary>
    private static DirectoryResponse Send(LdapConnection connection, DirectoryRequest request)
    {
        try
        {
            return connection.SendRequest(request);
        }
        catch (DirectoryOperationException e) when (e.Response is not null)
        {
            return e.Response;
        }
    }

    private static string[] Urls(DirectoryResponse response) => response.Referral.Select(u => u.OriginalString).ToArray();

    private static (string[] Entries, string[][] References) Search(LdapConnection connection, string baseDn, SdsSearchScope scope,
        string filter = "(objectClass=*)", params DirectoryControl[] controls)
    {
        var request = new SdsSearchRequest(baseDn, filter, scope, "1.1");
        request.Controls.AddRange(controls);
        var response = (SearchResponse)Send(connection, request);
        Assert.Equal(SdsResultCode.Success, response.ResultCode);
        return (response.Entries.Cast<SearchResultEntry>().Select(e => e.DistinguishedName).ToArray(),
            response.References.Cast<SearchResultReference>().Select(r => r.Reference.Select(u => u.OriginalString).ToArray()).ToArray());
    }

    private static DirectoryControl ManageDsaIt(bool critical = true) => new(LdapEncoder.ManageDsaItOid, null, critical, true);

    // ---- search --------------------------------------------------------------------------------------------

    [Fact]
    public void A_subtree_search_gets_a_reference_in_place_of_the_referral_entry()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);

        var (entries, references) = Search(connection, Base, SdsSearchScope.Subtree);
        Assert.Equal([Base, "ou=users," + Base, Admin, "uid=alice,ou=users," + Base], entries);
        Assert.Equal([There + "??sub", Backup + "??sub"], Assert.Single(references));

        // the reference does not depend on the filter: what matches is for the other server to say
        (entries, references) = Search(connection, Base, SdsSearchScope.Subtree, "(uid=alice)");
        Assert.Equal(["uid=alice,ou=users," + Base], entries);
        Assert.Equal([There + "??sub", Backup + "??sub"], Assert.Single(references));
    }

    [Fact]
    public void A_search_of_one_level_asks_the_other_server_for_the_one_entry()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);

        var (entries, references) = Search(connection, Base, SdsSearchScope.OneLevel);
        Assert.Equal(["ou=users," + Base], entries);
        Assert.Equal([There + "??base", Backup + "??base"], Assert.Single(references));

        // one level down from somewhere else, the referral entry is out of reach
        (_, references) = Search(connection, "ou=users," + Base, SdsSearchScope.OneLevel);
        Assert.Empty(references);
    }

    [Fact]
    public void A_search_of_one_entry_above_the_referral_gets_no_reference()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);
        var (entries, references) = Search(connection, Base, SdsSearchScope.Base);
        Assert.Equal([Base], entries);
        Assert.Empty(references);
    }

    [Theory]
    [InlineData(Partners, "ou=people,dc=partners,dc=net")]
    [InlineData("cn=Acme," + Partners, "cn=Acme,ou=people,dc=partners,dc=net")]
    [InlineData("uid=j\\,r,cn=Acme Ltd," + Partners, "uid=j%5C,r,cn=Acme%20Ltd,ou=people,dc=partners,dc=net")]
    public void A_search_from_the_referral_entry_or_below_is_sent_away_with_the_name_it_has_there(string baseDn, string nameThere)
    {
        using var server = Generic().Start();
        using var connection = Connect(server);
        foreach (var scope in new[] { SdsSearchScope.Base, SdsSearchScope.OneLevel, SdsSearchScope.Subtree })
        {
            var response = (SearchResponse)Send(connection, new SdsSearchRequest(baseDn, "(objectClass=*)", scope));
            Assert.Equal(SdsResultCode.Referral, response.ResultCode);
            // the scope is said outright (RFC 3296 §5.3)
            var asked = scope switch { SdsSearchScope.Base => "??base", SdsSearchScope.OneLevel => "??one", _ => "??sub" };
            Assert.Equal(["ldap://partners.example.net/" + nameThere + asked, "ldap://backup.example.net:1389/" + nameThere + asked], Urls(response));
            Assert.Equal(Partners, response.MatchedDN);
            Assert.Empty(response.Entries);
        }
        Assert.Equal(ResultCode.Referral, server.LastAnswer!.Result!.Code);
        Assert.Equal(2, server.LastAnswer!.Result!.Referrals!.Count);
    }

    [Fact]
    public void A_url_without_a_name_means_the_same_name()
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .WithReferral(Partners, "ldap://other.example.net", "ldaps://other.example.net:636/")
            .Start();
        using var connection = Connect(server);

        var (_, references) = Search(connection, Base, SdsSearchScope.Subtree);
        Assert.Equal(["ldap://other.example.net/" + Partners + "??sub", "ldaps://other.example.net:636/" + Partners + "??sub"], Assert.Single(references));

        var response = Send(connection, new SdsCompareRequest("cn=x," + Partners, "cn", "x"));
        Assert.Equal(SdsResultCode.Referral, response.ResultCode);
        Assert.Equal(["ldap://other.example.net/cn=x," + Partners, "ldaps://other.example.net:636/cn=x," + Partners], Urls(response));
    }

    [Fact]
    public void What_lies_behind_a_referral_entry_is_not_returned_and_only_the_outermost_one_is_named()
    {
        using var server = Generic()
            .WithEntry("cn=Acme," + Partners, e => e.Set("objectClass", "organizationalRole").Set("cn", "Acme"))
            .WithReferral("ou=deeper,cn=Acme," + Partners, "ldap://deeper.example.net/ou=deeper,dc=deeper,dc=net")
            .WithReferral("ou=suppliers," + Base, "ldap://suppliers.example.net/dc=suppliers,dc=net")
            .Start();
        using var connection = Connect(server);

        var (entries, references) = Search(connection, Base, SdsSearchScope.Subtree);
        Assert.DoesNotContain(entries, dn => dn.EndsWith(Partners, StringComparison.Ordinal));
        Assert.Equal(2, references.Length);
        Assert.Contains(references, r => r.SequenceEqual([There + "??sub", Backup + "??sub"]));
        Assert.Contains(references, r => r.SequenceEqual(["ldap://suppliers.example.net/dc=suppliers,dc=net??sub"]));
    }

    [Fact]
    public void A_paged_search_gets_the_references_once_with_the_last_page()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);
        var paging = new PageResultRequestControl(2);
        var seen = new List<int>();
        var entries = 0;
        do
        {
            var request = new SdsSearchRequest(Base, "(objectClass=*)", SdsSearchScope.Subtree, "1.1");
            request.Controls.Add(paging);
            var response = (SearchResponse)connection.SendRequest(request);
            entries += response.Entries.Count;
            seen.Add(response.References.Count);
            paging.Cookie = response.Controls.OfType<PageResultResponseControl>().Single().Cookie;
        }
        while (paging.Cookie.Length > 0);
        Assert.Equal(4, entries);
        Assert.Equal([0, 1], seen);

        // a page size of 0 gives the search up: nothing comes, references included
        var abandon = new SdsSearchRequest(Base, "(objectClass=*)", SdsSearchScope.Subtree, "1.1");
        abandon.Controls.Add(new PageResultRequestControl(0));
        var nothing = (SearchResponse)connection.SendRequest(abandon);
        Assert.Empty(nothing.Entries);
        Assert.Empty(nothing.References);
    }

    [Fact]
    public void An_anonymous_client_is_told_to_bind_before_it_is_told_where_to_go()
    {
        using var server = Generic().Start();
        using var connection = Connect(server, user: null);
        var response = Send(connection, new SdsSearchRequest("cn=x," + Partners, "(objectClass=*)", SdsSearchScope.Base));
        Assert.Equal(SdsResultCode.InsufficientAccessRights, response.ResultCode);
        Assert.Empty(response.Referral);

        response = Send(connection, new SdsDeleteRequest("cn=x," + Partners));
        Assert.Equal(SdsResultCode.StrongAuthRequired, response.ResultCode);
        Assert.Empty(response.Referral);
    }

    // ---- the other operations ------------------------------------------------------------------------------

    [Fact]
    public void Every_operation_on_a_name_at_or_below_the_referral_entry_is_sent_away()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);
        var name = "cn=Acme," + Partners;
        string[] expected = ["ldap://partners.example.net/cn=Acme,ou=people,dc=partners,dc=net", "ldap://backup.example.net:1389/cn=Acme,ou=people,dc=partners,dc=net"];

        DirectoryRequest[] requests =
        [
            new SdsAddRequest(name, "organizationalRole"),
            new SdsModifyRequest(name, DirectoryAttributeOperation.Replace, "description", "x"),
            new SdsDeleteRequest(name),
            new SdsModifyDnRequest(name, Partners, "cn=Acme2"),
            new SdsCompareRequest(name, "cn", "Acme"),
        ];
        foreach (var request in requests)
        {
            var response = Send(connection, request);
            Assert.True(SdsResultCode.Referral == response.ResultCode, request.GetType().Name + ": " + response.ResultCode);
            Assert.Equal(expected, Urls(response));
        }
        // the entry itself, too: it cannot be deleted or changed by a client that does not say it means the entry
        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsDeleteRequest(Partners)).ResultCode);
        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsModifyRequest(Partners, DirectoryAttributeOperation.Replace, "description", "x")).ResultCode);
        Assert.True(server.Directory.Exists(Partners));
        Assert.Null(server.Directory.Find(Partners)!.GetString("description"));
    }

    [Fact]
    public void A_read_only_user_is_sent_away_like_anyone_else()
    {
        using var server = Generic().WithReadOnlyUser("alice").Start();
        using var connection = Connect(server, "uid=alice,ou=users," + Base, "alice-secret");
        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsDeleteRequest("cn=x," + Partners)).ResultCode);
        Assert.Equal(SdsResultCode.InsufficientAccessRights, Send(connection, new SdsDeleteRequest("uid=admin,ou=users," + Base)).ResultCode);
    }

    [Fact]
    public void A_move_to_under_a_referral_entry_affects_several_servers()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);
        var response = Send(connection, new SdsModifyDnRequest("uid=alice,ou=users," + Base, Partners, "uid=alice"));
        Assert.Equal((int)ResultCode.AffectsMultipleDsas, (int)response.ResultCode);
        Assert.True(server.Directory.Exists("uid=alice,ou=users," + Base));
    }

    // ---- ManageDsaIT ---------------------------------------------------------------------------------------

    [Fact]
    public void With_ManageDsaIT_the_referral_entry_is_an_entry_like_any_other()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);

        var (entries, references) = Search(connection, Base, SdsSearchScope.Subtree, "(objectClass=referral)", ManageDsaIt());
        Assert.Equal([Partners], entries);
        Assert.Empty(references);

        // ref is operational: asked for by name
        var request = new SdsSearchRequest(Partners, "(objectClass=*)", SdsSearchScope.Base, "ref", "ou");
        request.Controls.Add(ManageDsaIt(critical: false));
        var entry = Assert.Single(((SearchResponse)connection.SendRequest(request)).Entries.Cast<SearchResultEntry>());
        Assert.Equal([There, Backup], entry.Attributes["ref"].GetValues(typeof(string)).Cast<string>());
        Assert.Equal("partners", entry.Attributes["ou"][0]);

        // change where it points, then remove it
        var modify = new SdsModifyRequest(Partners, DirectoryAttributeOperation.Replace, "ref", "ldap://new.example.net/dc=new");
        modify.Controls.Add(ManageDsaIt());
        Assert.Equal(SdsResultCode.Success, Send(connection, modify).ResultCode);
        (_, references) = Search(connection, Base, SdsSearchScope.Subtree);
        Assert.Equal(["ldap://new.example.net/dc=new??sub"], Assert.Single(references));

        var delete = new SdsDeleteRequest(Partners);
        delete.Controls.Add(ManageDsaIt());
        Assert.Equal(SdsResultCode.Success, Send(connection, delete).ResultCode);
        (_, references) = Search(connection, Base, SdsSearchScope.Subtree);
        Assert.Empty(references);
        Assert.Equal(SdsResultCode.NoSuchObject, Send(connection, new SdsSearchRequest("cn=x," + Partners, "(objectClass=*)", SdsSearchScope.Base)).ResultCode);
    }

    [Fact]
    public void A_referral_entry_can_be_made_over_the_wire_and_from_ldif()
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .WithLdif("""
                dn: ou=fromldif,dc=example,dc=com
                objectClass: referral
                objectClass: extensibleObject
                ou: fromldif
                ref: ldap://ldif.example.net/ou=fromldif,dc=example,dc=com
                """)
            .Start();
        using var connection = Connect(server);
        var add = new SdsAddRequest("ou=wire," + Base,
            new DirectoryAttribute("objectClass", "referral", "extensibleObject"), new DirectoryAttribute("ou", "wire"),
            new DirectoryAttribute("ref", "ldap://wire.example.net/ou=wire,dc=example,dc=com"));
        Assert.Equal(SdsResultCode.Success, Send(connection, add).ResultCode);

        var (_, references) = Search(connection, Base, SdsSearchScope.Subtree);
        Assert.Equal(2, references.Length);
        Assert.Contains(references, r => r.SequenceEqual(["ldap://ldif.example.net/ou=fromldif,dc=example,dc=com??sub"]));
        Assert.Contains(references, r => r.SequenceEqual(["ldap://wire.example.net/ou=wire,dc=example,dc=com??sub"]));
    }

    [Fact]
    public void The_root_dse_names_the_control_and_bind_and_extended_operations_do_not_take_it()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);
        var rootDse = Assert.Single(((SearchResponse)connection.SendRequest(new SdsSearchRequest("", "(objectClass=*)", SdsSearchScope.Base, "supportedControl"))).Entries.Cast<SearchResultEntry>());
        Assert.Contains(LdapEncoder.ManageDsaItOid, rootDse.Attributes["supportedControl"].GetValues(typeof(string)).Cast<string>());

        var whoAmI = new SdsExtendedRequest(Protocol.ExtendedRequest.WhoAmI);
        whoAmI.Controls.Add(ManageDsaIt());
        Assert.Equal(SdsResultCode.UnavailableCriticalExtension, Send(connection, whoAmI).ResultCode);
    }

    // ---- names outside the directory -----------------------------------------------------------------------

    [Fact]
    public void A_name_outside_the_directory_is_no_such_object_unless_there_is_a_default_referral()
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret").Start();
        using var connection = Connect(server);
        var search = new SdsSearchRequest("ou=people,dc=other,dc=org", "(objectClass=*)", SdsSearchScope.Subtree);
        Assert.Equal(SdsResultCode.NoSuchObject, Send(connection, search).ResultCode);

        server.Directory.DefaultReferral = ["ldap://root.example.org", "ldap://fixed.example.org/dc=fixed"];
        var response = Send(connection, search);
        Assert.Equal(SdsResultCode.Referral, response.ResultCode);
        Assert.Equal(["ldap://root.example.org/ou=people,dc=other,dc=org??sub", "ldap://fixed.example.org/dc=fixed"], Urls(response));
        Assert.True(string.IsNullOrEmpty(response.MatchedDN));
        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsDeleteRequest("ou=people,dc=other,dc=org")).ResultCode);

        // names inside stay this server's business, found or not; so do the root DSE and the schema
        Assert.Equal(SdsResultCode.NoSuchObject, Send(connection, new SdsSearchRequest("ou=nowhere," + Base, "(objectClass=*)", SdsSearchScope.Base)).ResultCode);
        Assert.Equal(SdsResultCode.Success, Send(connection, new SdsSearchRequest("", "(objectClass=*)", SdsSearchScope.Base)).ResultCode);
        Assert.Equal(SdsResultCode.Success, Send(connection, new SdsSearchRequest(server.Directory.SubschemaDn.ToString(), "(objectClass=*)", SdsSearchScope.Base)).ResultCode);

        server.Directory.DefaultReferral = [];
        Assert.Equal(SdsResultCode.NoSuchObject, Send(connection, search).ResultCode);
    }

    [Fact]
    public void The_default_referral_comes_from_the_builder_too_and_a_bind_is_never_referred()
    {
        using var server = Generic().WithDefaultReferral("ldap://root.example.org").Start();
        using var connection = Connect(server);
        var response = Send(connection, new SdsCompareRequest("cn=x,dc=other,dc=org", "cn", "x"));
        Assert.Equal(SdsResultCode.Referral, response.ResultCode);
        Assert.Equal(["ldap://root.example.org/cn=x,dc=other,dc=org"], Urls(response));

        // a rename to somewhere outside is as much a move to another server as one to under a referral entry
        response = Send(connection, new SdsModifyDnRequest("uid=alice,ou=users," + Base, "dc=other,dc=org", "uid=alice"));
        Assert.Equal((int)ResultCode.AffectsMultipleDsas, (int)response.ResultCode);

        foreach (var name in new[] { "uid=bob," + Partners, Partners, "uid=bob,dc=other,dc=org" })
        {
            var e = Assert.Throws<LdapException>(() => Connect(server, name, "secret"));
            Assert.Equal((int)ResultCode.InvalidCredentials, e.ErrorCode);
        }
    }

    // ---- found in review -------------------------------------------------------------------------------------

    private static LdapTestServerBuilder WithBobBehindTheReferral() => Generic()
        .WithEntry("uid=bob," + Partners, e => e.Set("objectClass", "inetOrgPerson").Set("uid", "bob").Set("cn", "bob").Set("sn", "bob").Set("userPassword", "bob-secret"));

    [Fact]
    public void A_user_behind_a_referral_entry_does_not_exist_to_this_server()
    {
        using var server = WithBobBehindTheReferral().Start();
        var e = Assert.Throws<LdapException>(() => Connect(server, "uid=bob," + Partners, "bob-secret"));
        Assert.Equal((int)ResultCode.InvalidCredentials, e.ErrorCode);

        // the password cannot be set from here either, by an administrator or by someone who knows it
        using var admin = Connect(server);
        var response = Send(admin, new SdsExtendedRequest(Protocol.ExtendedRequest.PasswordModify, Fuzzing.ClientEncoder.PasswordModify("uid=bob," + Partners, null, "changed")));
        Assert.Equal(SdsResultCode.Referral, response.ResultCode);
        Assert.Equal(["ldap://partners.example.net/uid=bob,ou=people,dc=partners,dc=net", "ldap://backup.example.net:1389/uid=bob,ou=people,dc=partners,dc=net"], Urls(response));

        using var anonymous = Connect(server, user: null);
        response = Send(anonymous, new SdsExtendedRequest(Protocol.ExtendedRequest.PasswordModify, Fuzzing.ClientEncoder.PasswordModify("uid=bob," + Partners, "bob-secret", "changed")));
        Assert.Equal(SdsResultCode.NoSuchObject, response.ResultCode);
        Assert.Empty(response.Referral);
        Assert.Equal("bob-secret", server.Directory.Find("uid=bob," + Partners)!.GetString("userPassword"));
    }

    [Fact]
    public void An_active_directory_user_behind_a_referral_entry_cannot_log_in_under_any_name()
    {
        const string child = "DC=child,DC=corp,DC=example,DC=com";
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com")
            .WithUser("admin", "admin-secret")
            .WithReferral(child, "ldap://child.corp.example.com:389/" + child, "ldap://[::1]:3268/" + child)
            .WithEntry("CN=eve," + child, e => e.Set("objectClass", "user").Set("cn", "eve").Set("sAMAccountName", "eve")
                .Set("userPrincipalName", "eve@child.corp.example.com").Set("userPassword", "eve-secret"))
            .Start();
        foreach (var name in new[] { "CN=eve," + child, "eve@child.corp.example.com", "CORP\\eve" })
        {
            var e = Assert.Throws<LdapException>(() => Connect(server, name, "eve-secret"));
            Assert.Equal((int)ResultCode.InvalidCredentials, e.ErrorCode);
        }

        // access points are named by host, without the port
        using var connection = Connect(server, "admin@corp.example.com");
        var response = Send(connection, new SdsCompareRequest("CN=eve," + child, "cn", "eve"));
        Assert.Contains("2 access points", response.ErrorMessage);
        Assert.Contains("ref 1: 'child.corp.example.com'", response.ErrorMessage);
        Assert.Contains("ref 2: '[::1]'", response.ErrorMessage);
    }

    [Fact]
    public void Taking_the_name_of_a_referral_entry_affects_several_servers()
    {
        using var server = Generic().WithEntry("ou=x," + Base, e => e.Set("objectClass", "organizationalUnit").Set("ou", "x")).Start();
        using var connection = Connect(server);
        var response = Send(connection, new SdsModifyDnRequest("ou=x," + Base, null, "ou=partners"));
        Assert.Equal((int)ResultCode.AffectsMultipleDsas, (int)response.ResultCode);
        Assert.True(server.Directory.Exists("ou=x," + Base));

        // any other name that is taken is taken here
        response = Send(connection, new SdsModifyDnRequest("ou=x," + Base, null, "ou=users"));
        Assert.Equal(SdsResultCode.EntryAlreadyExists, response.ResultCode);
    }

    [Fact]
    public void A_label_after_the_url_is_for_people_and_stays_here()
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .WithLdif("""
                dn: ou=partners,dc=example,dc=com
                objectClass: referral
                objectClass: extensibleObject
                ou: partners
                ref: ldap://hostb/ou=people,dc=partners,dc=net Partner directory
                """)
            .Start();
        using var connection = Connect(server);
        var (_, references) = Search(connection, Base, SdsSearchScope.Subtree);
        Assert.Equal(["ldap://hostb/ou=people,dc=partners,dc=net??sub"], Assert.Single(references));
        var response = Send(connection, new SdsDeleteRequest("cn=x," + Partners));
        Assert.Equal(["ldap://hostb/cn=x,ou=people,dc=partners,dc=net"], Urls(response));
    }

    [Fact]
    public void A_search_that_is_cut_short_names_no_other_servers()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);
        var request = new SdsSearchRequest(Base, "(objectClass=*)", SdsSearchScope.Subtree, "1.1") { SizeLimit = 2 };
        var response = (SearchResponse)Send(connection, request);
        Assert.Equal(SdsResultCode.SizeLimitExceeded, response.ResultCode);
        Assert.Equal(2, response.Entries.Count);
        Assert.Empty(response.References);

        // with a limit that is not reached they are there
        request = new SdsSearchRequest(Base, "(objectClass=*)", SdsSearchScope.Subtree, "1.1") { SizeLimit = 4 };
        response = (SearchResponse)Send(connection, request);
        Assert.Equal(SdsResultCode.Success, response.ResultCode);
        Assert.Single(response.References.Cast<SearchResultReference>());
    }

    [Fact]
    public void A_referral_entry_at_the_top_is_no_naming_context()
    {
        using var server = Generic().WithReferral("dc=other,dc=org", "ldap://other.example.org/dc=other,dc=org").Start();
        using var connection = Connect(server);
        var rootDse = Assert.Single(((SearchResponse)connection.SendRequest(new SdsSearchRequest("", "(objectClass=*)", SdsSearchScope.Base, "namingContexts"))).Entries.Cast<SearchResultEntry>());
        Assert.Equal([Base], rootDse.Attributes["namingContexts"].GetValues(typeof(string)).Cast<string>());
        Assert.Equal(["ldap://other.example.org/cn=x,dc=other,dc=org"], Urls(Send(connection, new SdsCompareRequest("cn=x,dc=other,dc=org", "cn", "x"))));
    }

    [Fact]
    public void Results_with_the_same_urls_are_equal_and_the_request_log_shows_them()
    {
        var one = new LdapResult(ResultCode.Referral, Referrals: ["ldap://a/dc=x", "ldap://b/dc=x"]);
        Assert.Equal(one, new LdapResult(ResultCode.Referral, Referrals: ["ldap://a/dc=x", "ldap://b/dc=x"]));
        Assert.Equal(one.GetHashCode(), new LdapResult(ResultCode.Referral, Referrals: ["ldap://a/dc=x", "ldap://b/dc=x"]).GetHashCode());
        Assert.NotEqual(one, new LdapResult(ResultCode.Referral, Referrals: ["ldap://a/dc=x"]));
        Assert.NotEqual(one, new LdapResult(ResultCode.Referral));
        Assert.Equal(new LdapResult(ResultCode.Busy, "m", "dc=x"), new LdapResult(ResultCode.Busy, "m", "dc=x", []));
        Assert.Equal("LdapResult { Code = Referral, Message = , MatchedDn = , Referrals = [ldap://a/dc=x, ldap://b/dc=x] }", one.ToString());
        Assert.Equal("LdapResult { Code = Success, Message = , MatchedDn =  }", LdapResult.Success.ToString());

        using var server = Generic().Start();
        using var connection = Connect(server);
        Send(connection, new SdsDeleteRequest("cn=x," + Partners));
        Assert.Equal(
            $"#1 Delete cn=x,{Partners} => Referral [ldap://partners.example.net/cn=x,ou=people,dc=partners,dc=net, ldap://backup.example.net:1389/cn=x,ou=people,dc=partners,dc=net]",
            server.LastAnswer!.ToString());
    }

    // ---- Active Directory ----------------------------------------------------------------------------------

    [Fact]
    public void Active_directory_names_the_other_domain_and_keeps_quiet_when_asked_to_stay_in_the_domain()
    {
        const string child = "DC=child,DC=corp,DC=example,DC=com";
        const string url = "ldap://child.corp.example.com/DC=child,DC=corp,DC=example,DC=com";
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com")
            .WithUser("admin", "admin-secret")
            .WithReferral(child, url)
            .Start();
        using var connection = Connect(server, "admin@corp.example.com");

        var (entries, references) = Search(connection, "DC=corp,DC=example,DC=com", SdsSearchScope.Subtree);
        Assert.Equal([url + "??sub"], Assert.Single(references));
        Assert.DoesNotContain(child, entries);

        (entries, references) = Search(connection, "DC=corp,DC=example,DC=com", SdsSearchScope.Subtree, "(objectClass=*)", new DomainScopeControl());
        Assert.Empty(references);
        Assert.DoesNotContain(child, entries);

        var response = (SearchResponse)Send(connection, new SdsSearchRequest("CN=Users," + child, "(objectClass=*)", SdsSearchScope.Subtree));
        Assert.Equal(SdsResultCode.Referral, response.ResultCode);
        Assert.Equal(["ldap://child.corp.example.com/CN=Users,DC=child,DC=corp,DC=example,DC=com??sub"], Urls(response));
        Assert.StartsWith("0000202B: RefErr: DSID-", response.ErrorMessage);
        Assert.Contains("ref 1: 'child.corp.example.com'", response.ErrorMessage);

        // a domain controller does not know ManageDsaIT
        var request = new SdsSearchRequest("DC=corp,DC=example,DC=com", "(objectClass=*)", SdsSearchScope.Subtree);
        request.Controls.Add(ManageDsaIt());
        Assert.Equal(SdsResultCode.UnavailableCriticalExtension, Send(connection, request).ResultCode);
    }

    // ---- followed for real -----------------------------------------------------------------------------------

    [Fact]
    public void A_client_that_follows_referrals_ends_up_at_a_second_test_server()
    {
        using var partners = LdapTestServer.Create().WithBaseDn("dc=partners,dc=net")
            .WithUser("bob", "bob-secret")
            .WithUser("carol", "carol-secret")
            .AllowAnonymousSearch() // the client follows without credentials unless it is given a handler for them
            .Start();
        using var server = Generic()
            .Configure(d => d.Update(Partners, e => e.Set("ref", $"ldap://{partners.Host}:{partners.Port}/ou=users,dc=partners,dc=net")))
            .Start();

        using var connection = new Novell.Directory.Ldap.LdapConnection();
        connection.Connect(server.Host, server.Port);
        connection.Bind(Admin, "admin-secret");
        var constraints = connection.SearchConstraints;
        constraints.ReferralFollowing = true;

        // a search of the whole tree continues on the other server
        var found = new List<string>();
        var results = connection.Search(Base, Novell.Directory.Ldap.LdapConnection.ScopeSub, "(uid=*)", ["uid"], false, constraints);
        while (results.HasMore()) found.Add(results.Next().Dn);
        Assert.Equal(
            [Admin, "uid=alice,ou=users," + Base, "uid=bob,ou=users,dc=partners,dc=net", "uid=carol,ou=users,dc=partners,dc=net"],
            found.Order(StringComparer.Ordinal));

        // and a search that starts behind the referral entry is done there, under the name the entry has there
        results = connection.Search("uid=bob," + Partners, Novell.Directory.Ldap.LdapConnection.ScopeBase, "(objectClass=*)", ["uid"], false, constraints);
        Assert.True(results.HasMore());
        Assert.Equal("uid=bob,ou=users,dc=partners,dc=net", results.Next().Dn);
        Assert.False(results.HasMore()); // the search is recorded when it is done, not with its first entry

        Assert.Contains(partners.Requests, r => r.Request is Protocol.SearchRequest { BaseDn: "uid=bob,ou=users,dc=partners,dc=net" });
    }

    // ---- by hand -------------------------------------------------------------------------------------------

    [Fact]
    public void A_test_can_send_a_client_away_by_hand()
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret").Start();
        using var connection = Connect(server);
        using (server.Intercept(c => c.Request is Protocol.SearchRequest ? new LdapResult(ResultCode.Referral, Referrals: ["ldap://elsewhere.example.net/dc=x"]) : null))
        {
            var response = Send(connection, new SdsSearchRequest(Base, "(objectClass=*)", SdsSearchScope.Base));
            Assert.Equal(SdsResultCode.Referral, response.ResultCode);
            Assert.Equal(["ldap://elsewhere.example.net/dc=x"], Urls(response));
        }
    }

    [Theory]
    [InlineData("http://example.net/dc=x")]
    [InlineData("ldap://")]
    [InlineData("ldap:///dc=x")]
    [InlineData("example.net")]
    [InlineData("ldap://bad host/dc=x")]
    [InlineData("ldap://:389/dc=x")]
    [InlineData("ldap://host:port/dc=x")]
    [InlineData("ldap://[::1/dc=x")]
    [InlineData("ldap://host/dc=x a label")]
    [InlineData("ldap://host/dc=x%zz")]
    [InlineData("ldap://host/dc=x%2")]
    [InlineData("ldap://host/dc=x%2G")]
    [InlineData("ldap://host/dc=x%")]
    [InlineData("ldap://::1/dc=x")]
    [InlineData("ldap://[]/dc=x")]
    [InlineData("ldap://host:389:389/dc=x")]
    [InlineData("ldap://user@host/dc=x")]
    [InlineData("ldap://host:/dc=x")]
    public void What_is_no_ldap_url_is_refused_when_the_referral_is_set_up(string url)
    {
        var directory = new InMemoryDirectory();
        Assert.Throws<ArgumentException>(() => directory.AddReferral(Partners, url));
        Assert.Throws<ArgumentException>(() => directory.DefaultReferral = [url]);
        Assert.Throws<ArgumentException>(() => directory.AddReferral(Partners));
        Assert.False(directory.Exists(Partners));
    }

    // ---- gaps a mutation check found ---------------------------------------------------------------------------

    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    /// <summary>What the server itself put in the last answer: no client library in between.</summary>
    private static string[] Sent(LdapTestServer server) => server.LastAnswer!.Result!.Referrals?.ToArray() ?? [];

    [Fact]
    public void A_name_behind_two_referral_entries_is_sent_where_the_outer_one_says()
    {
        using var server = Generic()
            .WithEntry("cn=Acme," + Partners, e => e.Set("objectClass", "organizationalRole").Set("cn", "Acme"))
            .WithReferral("ou=deeper,cn=Acme," + Partners, "ldap://deeper.example.net/ou=deeper,dc=deeper,dc=net")
            .Start();
        using var connection = Connect(server);
        foreach (var name in new[] { "ou=deeper,cn=Acme," + Partners, "cn=x,ou=deeper,cn=Acme," + Partners })
        {
            var response = (SearchResponse)Send(connection, new SdsSearchRequest(name, "(objectClass=*)", SdsSearchScope.Base));
            Assert.Equal(SdsResultCode.Referral, response.ResultCode);
            var there = name.Replace(Partners, "ou=people,dc=partners,dc=net", StringComparison.Ordinal);
            Assert.Equal(["ldap://partners.example.net/" + there + "??base", "ldap://backup.example.net:1389/" + there + "??base"], Urls(response));
            Assert.Equal(Partners, response.MatchedDN);
        }
    }

    [Fact]
    public void Only_an_entry_of_class_referral_that_has_ref_is_a_referral_entry()
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .WithLdif("""
                dn: ou=upper,dc=example,dc=com
                objectClass: REFERRAL
                objectClass: extensibleObject
                ou: upper
                ref: ldap://upper.example.net/ou=upper,dc=example,dc=com

                dn: ou=noref,dc=example,dc=com
                objectClass: referral
                objectClass: extensibleObject
                ou: noref

                dn: ou=noclass,dc=example,dc=com
                objectClass: organizationalUnit
                objectClass: extensibleObject
                ou: noclass
                ref: ldap://noclass.example.net/ou=noclass,dc=example,dc=com
                """)
            .Start();
        using var connection = Connect(server);

        var (entries, references) = Search(connection, Base, SdsSearchScope.Subtree);
        Assert.Equal(["ldap://upper.example.net/ou=upper,dc=example,dc=com??sub"], Assert.Single(references));
        Assert.Contains("ou=noref," + Base, entries);
        Assert.Contains("ou=noclass," + Base, entries);
        Assert.DoesNotContain(entries, dn => dn.StartsWith("ou=upper,", StringComparison.OrdinalIgnoreCase));

        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsCompareRequest("cn=x,ou=upper," + Base, "cn", "x")).ResultCode);
        Assert.Equal(SdsResultCode.NoSuchObject, Send(connection, new SdsCompareRequest("cn=x,ou=noref," + Base, "cn", "x")).ResultCode);
        Assert.Equal(SdsResultCode.NoSuchObject, Send(connection, new SdsCompareRequest("cn=x,ou=noclass," + Base, "cn", "x")).ResultCode);
    }

    [Fact]
    public void A_search_of_one_level_gets_no_reference_for_a_referral_entry_further_down()
    {
        const string deep = "ldap://deep.example.net/ou=deep,dc=deep,dc=net";
        using var server = Generic().WithReferral("ou=deep,ou=users," + Base, deep).Start();
        using var connection = Connect(server);

        var (entries, references) = Search(connection, Base, SdsSearchScope.OneLevel);
        Assert.Equal(["ou=users," + Base], entries);
        Assert.Equal([There + "??base", Backup + "??base"], Assert.Single(references));

        (entries, references) = Search(connection, "ou=users," + Base, SdsSearchScope.OneLevel);
        Assert.Equal([Admin, "uid=alice,ou=users," + Base], entries);
        Assert.Equal([deep + "??base"], Assert.Single(references));

        (_, references) = Search(connection, Base, SdsSearchScope.Subtree);
        Assert.Equal(2, references.Length);
    }

    [Theory]
    [InlineData("ldap://h.example.net", "ldap://h.example.net", null)]
    [InlineData("ldap://h.example.net/", "ldap://h.example.net", null)]
    [InlineData("LDAP://H.example.net:389/dc=x", "LDAP://H.example.net:389", "dc=x")]
    [InlineData("LDAPS://h.example.net/dc=x", "LDAPS://h.example.net", "dc=x")]
    [InlineData("ldap://h.example.net??sub", "ldap://h.example.net", null)]
    [InlineData("ldap://h.example.net?cn?one?(a=b/c)", "ldap://h.example.net", null)]
    [InlineData("ldap://h.example.net/?cn", "ldap://h.example.net", null)]
    [InlineData("ldap://h.example.net/dc=x?cn,sn?sub?(cn=a)", "ldap://h.example.net", "dc=x")]
    [InlineData("ldap://h.example.net/cn=a%20b%3F,o=%C3%A9,dc=x??base", "ldap://h.example.net", "cn=a b?,o=é,dc=x")]
    public void An_ldap_url_is_split_into_the_server_and_the_name(string url, string server, string? dn)
    {
        Assert.True(LdapUrl.TrySplit(url, out var actualServer, out var actualDn));
        Assert.Equal(server, actualServer);
        Assert.Equal(dn, actualDn);
    }

    [Theory]
    [InlineData("ou=people,dc=x", null, "ldap://h/ou=people,dc=x")]
    [InlineData("cn=a b,dc=x", null, "ldap://h/cn=a%20b,dc=x")]
    [InlineData("cn=who?,dc=x", "base", "ldap://h/cn=who%3F,dc=x??base")]
    [InlineData("cn=100%,dc=x", null, "ldap://h/cn=100%25,dc=x")]
    [InlineData("cn=Zoë \"Z\" <z>#1,dc=x", null, "ldap://h/cn=Zo%C3%AB%20%22Z%22%20%3Cz%3E%231,dc=x")]
    public void A_name_is_written_into_an_ldap_url_percent_encoded_and_read_back_the_same(string dn, string? scope, string url)
    {
        Assert.Equal(url, LdapUrl.Build("ldap://h", dn, scope));
        Assert.True(LdapUrl.TrySplit(url, out var server, out var back));
        Assert.Equal("ldap://h", server);
        Assert.Equal(dn, back);
    }

    [Fact]
    public void The_server_sends_urls_percent_encoded_whatever_the_client_library_makes_of_them()
    {
        // The url of the entry has an escaped name and a scope; the name the client asks for needs escaping too.
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .WithReferral(Partners, "ldap://partners.example.net/ou=our%20people,dc=partners,dc=net??sub", "LDAP://other.example.net?cn")
            .Start();
        using var connection = Connect(server);

        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsCompareRequest("cn=Zoë Q?," + Partners, "cn", "x")).ResultCode);
        Assert.Equal(
            ["ldap://partners.example.net/cn=Zo%C3%AB%20Q%3F,ou=our%20people,dc=partners,dc=net", "LDAP://other.example.net/cn=Zo%C3%AB%20Q%3F," + Partners],
            Sent(server));

        // references are not part of the recorded result: what the client got is all there is to look at
        var (_, references) = Search(connection, Base, SdsSearchScope.OneLevel);
        // (the scheme is compared without regard to case: the client library on Linux hands "LDAP://" back as "ldap://")
        Assert.Equal(
            ["ldap://partners.example.net/ou=our%20people,dc=partners,dc=net??base", "LDAP://other.example.net/" + Partners + "??base"],
            Assert.Single(references), StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_url_whose_name_is_no_distinguished_name_is_passed_on_as_it_is()
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .WithReferral(Partners, "ldap://odd.example.net/nonsense")
            .Start();
        using var connection = Connect(server);
        var response = Send(connection, new SdsCompareRequest("cn=x," + Partners, "cn", "x"));
        Assert.Equal(SdsResultCode.Referral, response.ResultCode);
        Assert.Equal(["ldap://odd.example.net/nonsense"], Urls(response));
    }

    [Fact]
    public void The_schema_and_the_root_stay_this_servers_business_with_a_default_referral()
    {
        using var server = Generic().WithDefaultReferral("ldap://root.example.org").Start();
        using var connection = Connect(server);
        var subschema = server.Directory.SubschemaDn.ToString();
        Assert.NotEqual(SdsResultCode.Referral, Send(connection, new SdsCompareRequest(subschema, "cn", "x")).ResultCode);
        Assert.NotEqual(SdsResultCode.Referral, Send(connection, new SdsModifyRequest(subschema, DirectoryAttributeOperation.Replace, "description", "x")).ResultCode);
        Assert.NotEqual(SdsResultCode.Referral, Send(connection, new SdsDeleteRequest(subschema)).ResultCode);
    }

    [Fact]
    public void AddReferral_makes_an_entry_the_schema_allows_and_refuses_the_root()
    {
        var directory = new InMemoryDirectory { SchemaChecks = true };
        directory.Add(new Entry(Base).Set("objectClass", "top", "domain").Set("dc", "example"));
        var dn = directory.AddReferral(Partners, There, Backup);
        Assert.Equal(Partners, dn.ToString());

        var entry = directory.Find(Partners)!;
        Assert.Equal(["top", "referral", "extensibleObject"], entry.GetStrings("objectClass"));
        Assert.Equal(["partners"], entry.GetStrings("ou"));
        Assert.Equal([There, Backup], entry.GetStrings("ref"));

        Assert.Throws<ArgumentException>(() => directory.AddReferral("", There));
    }

    [Fact]
    public void The_schema_has_ref_as_an_operational_attribute_clients_may_write()
    {
        using var server = Generic().WithSchemaChecks().Start();
        using var connection = Connect(server);

        var schema = new SdsSearchRequest(server.Directory.SubschemaDn.ToString(), "(objectClass=subschema)", SdsSearchScope.Base, "attributeTypes", "objectClasses");
        var subschema = Assert.Single(((SearchResponse)connection.SendRequest(schema)).Entries.Cast<SearchResultEntry>());
        var definition = Assert.Single(subschema.Attributes["attributeTypes"].GetValues(typeof(string)).Cast<string>(), t => t.Contains("NAME 'ref'", StringComparison.Ordinal));
        Assert.Contains("USAGE", definition);
        Assert.DoesNotContain("NO-USER-MODIFICATION", definition);
        Assert.DoesNotContain("SINGLE-VALUE", definition);
        Assert.StartsWith("( 2.16.840.1.113730.3.1.34 ", definition);
        var referral = Assert.Single(subschema.Attributes["objectClasses"].GetValues(typeof(string)).Cast<string>(), c => c.Contains("NAME 'referral'", StringComparison.Ordinal));
        Assert.StartsWith("( 2.16.840.1.113730.3.2.6 ", referral); // a class the catalog does not have is published too, under a made-up number
        Assert.Contains("STRUCTURAL", referral);

        // operational: "*" does not return it
        var request = new SdsSearchRequest(Partners, "(objectClass=*)", SdsSearchScope.Base, "*");
        request.Controls.Add(ManageDsaIt());
        var entry = Assert.Single(((SearchResponse)connection.SendRequest(request)).Entries.Cast<SearchResultEntry>());
        Assert.Contains("ou", entry.Attributes.AttributeNames.Cast<string>());
        Assert.DoesNotContain("ref", entry.Attributes.AttributeNames.Cast<string>(), StringComparer.OrdinalIgnoreCase);

        // and a client may write it, more than one value, with the schema checked
        var modify = new SdsModifyRequest(Partners, DirectoryAttributeOperation.Replace, "ref", "ldap://a.example.net/dc=a", "ldap://b.example.net/dc=b");
        modify.Controls.Add(ManageDsaIt());
        Assert.Equal(SdsResultCode.Success, Send(connection, modify).ResultCode);
        Assert.Equal(["ldap://a.example.net/dc=a", "ldap://b.example.net/dc=b"], server.Directory.Find(Partners)!.GetStrings("ref"));
    }

    [Fact]
    public void A_result_with_an_empty_list_of_referrals_has_no_referral_field()
    {
        // Referral ::= SEQUENCE SIZE (1..MAX) OF uri: an empty one is not LDAP
        Assert.Equal(
            LdapEncoder.Result(1, 5, new LdapResult(ResultCode.Success)),
            LdapEncoder.Result(1, 5, new LdapResult(ResultCode.Success, Referrals: [])));
        Assert.NotEqual(
            LdapEncoder.Result(1, 5, new LdapResult(ResultCode.Referral)),
            LdapEncoder.Result(1, 5, new LdapResult(ResultCode.Referral, Referrals: ["ldap://h/dc=x"])));
    }

    [Fact]
    public void Active_directory_lists_every_server_in_the_message()
    {
        const string child = "DC=child,DC=corp,DC=example,DC=com";
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com")
            .WithUser("admin", "admin-secret")
            .WithReferral(child, "ldap://dc1.child.corp.example.com/" + child, "ldaps://dc2.child.corp.example.com:636/" + child)
            .Start();
        using var connection = Connect(server, "admin@corp.example.com");
        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsCompareRequest("CN=x," + child, "cn", "x")).ResultCode);
        Assert.Equal(
            "0000202B: RefErr: DSID-03100835, data 0, 2 access points\n\tref 1: 'dc1.child.corp.example.com'\n\tref 2: 'dc2.child.corp.example.com'\n",
            server.LastAnswer!.Result!.Message);
        Assert.Equal(child, server.LastAnswer!.Result!.MatchedDn, ignoreCase: true);
    }

    [Fact]
    public void The_generic_server_does_not_know_the_domain_scope_control()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);

        var rootDse = Assert.Single(((SearchResponse)connection.SendRequest(new SdsSearchRequest("", "(objectClass=*)", SdsSearchScope.Base, "supportedControl"))).Entries.Cast<SearchResultEntry>());
        Assert.DoesNotContain(LdapEncoder.DomainScopeOid, rootDse.Attributes["supportedControl"].GetValues(typeof(string)).Cast<string>());

        // not critical: ignored, the references come
        var (_, references) = Search(connection, Base, SdsSearchScope.Subtree, "(objectClass=*)", new DirectoryControl(LdapEncoder.DomainScopeOid, null, false, true));
        Assert.Equal([There + "??sub", Backup + "??sub"], Assert.Single(references));

        // critical: refused
        var request = new SdsSearchRequest(Base, "(objectClass=*)", SdsSearchScope.Subtree);
        request.Controls.Add(new DirectoryControl(LdapEncoder.DomainScopeOid, null, true, true));
        Assert.Equal(SdsResultCode.UnavailableCriticalExtension, Send(connection, request).ResultCode);
    }

    [Fact]
    public void Active_directory_takes_the_domain_scope_control_on_a_search_only_and_ignores_ManageDsaIT()
    {
        const string root = "DC=corp,DC=example,DC=com";
        const string child = "DC=child,DC=corp,DC=example,DC=com";
        const string url = "ldap://child.corp.example.com/DC=child,DC=corp,DC=example,DC=com";
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(root)
            .WithUser("admin", "admin-secret")
            .WithReferral(child, url)
            .Start();
        using var connection = Connect(server, "admin@corp.example.com");

        var rootDse = Assert.Single(((SearchResponse)connection.SendRequest(new SdsSearchRequest("", "(objectClass=*)", SdsSearchScope.Base, "supportedControl"))).Entries.Cast<SearchResultEntry>());
        var supported = rootDse.Attributes["supportedControl"].GetValues(typeof(string)).Cast<string>().ToArray();
        Assert.Contains(LdapEncoder.DomainScopeOid, supported);
        Assert.DoesNotContain(LdapEncoder.ManageDsaItOid, supported);

        // the control is a search control: critical on anything else, it is unknown
        var delete = new SdsDeleteRequest("CN=nobody,CN=Users," + root);
        delete.Controls.Add(new DirectoryControl(LdapEncoder.DomainScopeOid, null, true, true));
        Assert.Equal(SdsResultCode.UnavailableCriticalExtension, Send(connection, delete).ResultCode);

        // ManageDsaIT that is not critical is ignored: the search still gets the reference, the delete is still sent away
        var (entries, references) = Search(connection, root, SdsSearchScope.Subtree, "(objectClass=*)", ManageDsaIt(critical: false));
        Assert.Equal([url + "??sub"], Assert.Single(references));
        Assert.DoesNotContain(child, entries, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(root, entries, StringComparer.OrdinalIgnoreCase); // so the line above is not passing on spelling alone

        delete = new SdsDeleteRequest(child);
        delete.Controls.Add(ManageDsaIt(critical: false));
        Assert.Equal(SdsResultCode.Referral, Send(connection, delete).ResultCode);
        Assert.True(server.Directory.Exists(child));
    }

    [Fact]
    public void A_bind_does_not_take_ManageDsaIT()
    {
        // No client library puts a control on a bind, hence the bare socket.
        using var server = Generic().Start();
        using var client = new RawClient(server.Host, server.Port);
        LdapControl[] critical = [new(LdapEncoder.ManageDsaItOid, Critical: true)];

        var response = client.Exchange(ClientEncoder.Encode(1, new Protocol.BindRequest(3, Admin, "admin-secret", null), critical), Patience);
        Assert.Equal((int)ResultCode.UnavailableCriticalExtension, response!.ResultCode);
        Assert.Null(server.LastAnswer!.BoundDn);

        // the same control on the operations that take it, for comparison: same connection, now bound
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(2, new Protocol.BindRequest(3, Admin, "admin-secret", null)), Patience)!.ResultCode);
        response = client.Exchange(ClientEncoder.Encode(3, new Protocol.CompareRequest(Partners, "ou", "partners"u8.ToArray()), critical), Patience);
        Assert.Equal((int)ResultCode.CompareTrue, response!.ResultCode);
    }

    [Fact]
    public void A_read_only_user_is_sent_away_whatever_the_operation()
    {
        using var server = Generic().WithReadOnlyUser("alice").Start();
        using var connection = Connect(server, "uid=alice,ou=users," + Base, "alice-secret");
        var name = "cn=Acme," + Partners;
        DirectoryRequest[] requests =
        [
            new SdsAddRequest(name, "organizationalRole"),
            new SdsModifyRequest(name, DirectoryAttributeOperation.Replace, "description", "x"),
            new SdsDeleteRequest(name),
            new SdsModifyDnRequest(name, Partners, "cn=Acme2"),
        ];
        foreach (var request in requests)
        {
            var response = Send(connection, request);
            Assert.True(SdsResultCode.Referral == response.ResultCode, request.GetType().Name + ": " + response.ResultCode);
        }
    }

    [Fact]
    public void An_anonymous_client_is_told_to_bind_on_a_compare_too()
    {
        using var server = Generic().WithDefaultReferral("ldap://root.example.org").Start();
        using var connection = Connect(server, user: null);
        foreach (var name in new[] { "cn=x," + Partners, "cn=x,dc=other,dc=org" })
        {
            var response = Send(connection, new SdsCompareRequest(name, "cn", "x"));
            Assert.Equal(SdsResultCode.InsufficientAccessRights, response.ResultCode);
            Assert.Empty(response.Referral);
        }
    }

    [Fact]
    public void The_default_referral_is_copied_when_it_is_set()
    {
        var directory = new InMemoryDirectory();
        string[] urls = ["ldap://a.example.net"];
        directory.DefaultReferral = urls;
        urls[0] = "no url at all";
        Assert.Equal(["ldap://a.example.net"], directory.DefaultReferral);
    }

    // ---- found in the second review round ---------------------------------------------------------------------

    private static byte[] PasswordModify(string? user, string? oldPassword, string newPassword) => ClientEncoder.PasswordModify(user, oldPassword, newPassword);

    private static SdsExtendedRequest PasswordModifyRequest(string? user, string? oldPassword, string newPassword, DirectoryControl? control = null)
    {
        var request = new SdsExtendedRequest(Protocol.ExtendedRequest.PasswordModify, PasswordModify(user, oldPassword, newPassword));
        if (control is not null) request.Controls.Add(control);
        return request;
    }

    [Fact]
    public void ManageDsaIT_on_a_password_change_opens_nothing()
    {
        using var server = WithBobBehindTheReferral().Start();
        var bob = "uid=bob," + Partners;

        using var anonymous = Connect(server, user: null);
        var response = Send(anonymous, PasswordModifyRequest(bob, "bob-secret", "changed", ManageDsaIt(critical: false)));
        Assert.Equal(SdsResultCode.NoSuchObject, response.ResultCode);

        using var admin = Connect(server);
        response = Send(admin, PasswordModifyRequest(bob, null, "changed", ManageDsaIt(critical: false)));
        Assert.Equal(SdsResultCode.Referral, response.ResultCode);
        Assert.Equal("bob-secret", server.Directory.Find(bob)!.GetString("userPassword"));
    }

    [Fact]
    public void A_password_change_is_referred_by_the_name_whether_or_not_an_entry_has_it()
    {
        using var server = WithBobBehindTheReferral().WithDefaultReferral("ldap://root.example.org").WithReadOnlyUser("alice").Start();
        using var admin = Connect(server);
        foreach (var (name, url) in new[]
        {
            ("uid=bob," + Partners, "ldap://partners.example.net/uid=bob,ou=people,dc=partners,dc=net"),
            ("uid=nobody," + Partners, "ldap://partners.example.net/uid=nobody,ou=people,dc=partners,dc=net"),
            ("dn:uid=nobody," + Partners, "ldap://partners.example.net/uid=nobody,ou=people,dc=partners,dc=net"),
            ("uid=q,dc=other,dc=org", "ldap://root.example.org/uid=q,dc=other,dc=org"),
        })
        {
            var response = Send(admin, PasswordModifyRequest(name, null, "changed"));
            Assert.True(SdsResultCode.Referral == response.ResultCode, name + ": " + response.ResultCode);
            Assert.Equal(url, Urls(response)[0]);
        }
        // a name of this server that nobody has stays what it was
        Assert.Equal(SdsResultCode.NoSuchObject, Send(admin, PasswordModifyRequest("uid=nobody,ou=users," + Base, null, "changed")).ResultCode);

        // a read-only user is sent away before anyone asks what it may do; here it may do nothing without the old password
        using var alice = Connect(server, "uid=alice,ou=users," + Base, "alice-secret");
        Assert.Equal(SdsResultCode.Referral, Send(alice, PasswordModifyRequest("uid=bob," + Partners, null, "changed")).ResultCode);
        Assert.Equal(SdsResultCode.InsufficientAccessRights, Send(alice, PasswordModifyRequest(Admin, null, "changed")).ResultCode);

        // and an anonymous client learns nothing: the same answer for someone behind the referral entry and for no one
        using var anonymous = Connect(server, user: null);
        var hidden = Send(anonymous, PasswordModifyRequest("uid=bob," + Partners, "bob-secret", "changed"));
        var missing = Send(anonymous, PasswordModifyRequest("uid=nobody," + Partners, "bob-secret", "changed"));
        Assert.Equal(SdsResultCode.NoSuchObject, hidden.ResultCode);
        Assert.Equal(SdsResultCode.NoSuchObject, missing.ResultCode);
        Assert.Equal(hidden.ErrorMessage.Replace("bob", "nobody", StringComparison.Ordinal), missing.ErrorMessage);
        Assert.Equal("bob-secret", server.Directory.Find("uid=bob," + Partners)!.GetString("userPassword"));
    }

    [Fact]
    public void A_connection_whose_user_goes_behind_a_referral_entry_stays_bound_but_cannot_change_that_password_here()
    {
        const string moving = "ou=moving," + Base;
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .WithEntry(moving, e => e.Set("objectClass", "organizationalUnit").Set("ou", "moving"))
            .WithEntry("uid=carol," + moving, e => e.Set("objectClass", "inetOrgPerson").Set("uid", "carol").Set("cn", "carol").Set("sn", "carol").Set("userPassword", "carol-secret"))
            .Start();
        using var carol = Connect(server, "uid=carol," + moving, "carol-secret");

        server.Directory.Update(moving, e => e.Add("objectClass", "referral").Set("ref", "ldap://moved.example.net/ou=moved,dc=moved,dc=net"));

        var response = Send(carol, PasswordModifyRequest(null, null, "carol-new"));
        Assert.Equal(SdsResultCode.Referral, response.ResultCode);
        Assert.Equal(["ldap://moved.example.net/uid=carol,ou=moved,dc=moved,dc=net"], Urls(response));
        Assert.Equal("carol-secret", server.Directory.Find("uid=carol," + moving)!.GetString("userPassword"));

        // still bound, as a connection is whose user was deleted; a new login is another matter
        Assert.Equal(SdsResultCode.Success, Send(carol, new SdsSearchRequest(Base, "(objectClass=*)", SdsSearchScope.Base)).ResultCode);
        var e = Assert.Throws<LdapException>(() => Connect(server, "uid=carol," + moving, "carol-secret"));
        Assert.Equal((int)ResultCode.InvalidCredentials, e.ErrorCode);
    }

    [Fact]
    public void A_namesake_behind_a_referral_entry_does_not_get_in_the_way_of_a_user_here()
    {
        // generic: SASL PLAIN looks a user name up as uid
        using var server = WithBobBehindTheReferral().WithUser("bob", "local-bob").Start();
        using var client = new RawClient(server.Host, server.Port);
        foreach (var name in new[] { "u:bob", "bob" })
        {
            var plain = new Protocol.BindRequest(3, "", null, Protocol.BindRequest.Plain, System.Text.Encoding.UTF8.GetBytes($"\0{name}\0local-bob"));
            Assert.Equal(0, client.Exchange(ClientEncoder.Encode(1, plain), Patience)!.ResultCode);
            // a bind's own record has who the connection was before it; the next request has who it is now
            Assert.Equal(0, client.Exchange(ClientEncoder.Encode(2, new Protocol.ExtendedRequest(Protocol.ExtendedRequest.WhoAmI, null)), Patience)!.ResultCode);
            Assert.Equal("uid=bob,ou=users," + Base, server.LastAnswer!.BoundDn?.ToString());
        }
        // the one behind the referral entry cannot be meant, by any name
        var hidden = new Protocol.BindRequest(3, "", null, Protocol.BindRequest.Plain, System.Text.Encoding.UTF8.GetBytes($"\0dn:uid=bob,{Partners}\0bob-secret"));
        Assert.Equal((int)ResultCode.InvalidCredentials, client.Exchange(ClientEncoder.Encode(2, hidden), Patience)!.ResultCode);

        // Active Directory: two domains with the same account name
        const string child = "DC=child,DC=corp,DC=example,DC=com";
        using var domain = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com")
            .WithUser("eve", "local-eve")
            .WithReferral(child, "ldap://child.corp.example.com/" + child)
            .WithEntry("CN=eve," + child, e => e.Set("objectClass", "user").Set("cn", "eve").Set("sAMAccountName", "eve")
                .Set("userPrincipalName", "eve@child.corp.example.com").Set("userPassword", "other-eve"))
            .Start();
        foreach (var name in new[] { "CORP\\eve", "eve", "eve@corp.example.com" })
        {
            using var connection = Connect(domain, name, "local-eve");
        }
        var refused = Assert.Throws<LdapException>(() => Connect(domain, "eve", "other-eve"));
        Assert.Equal((int)ResultCode.InvalidCredentials, refused.ErrorCode);
    }

    [Fact]
    public void A_rename_that_is_wrong_for_another_reason_says_that_reason()
    {
        using var server = Generic().WithEntry("ou=x," + Base, e => e.Set("objectClass", "organizationalUnit").Set("ou", "x")).Start();
        using var connection = Connect(server);

        // a new RDN that is two: no name at all, and not a way to under the referral entry
        var there = Send(connection, new SdsModifyDnRequest("ou=x," + Base, null, "ou=z,ou=partners"));
        var here = Send(connection, new SdsModifyDnRequest("ou=x," + Base, null, "ou=z,ou=users"));
        Assert.Equal(here.ResultCode, there.ResultCode);
        Assert.NotEqual((int)ResultCode.AffectsMultipleDsas, (int)there.ResultCode);
        Assert.NotEqual(SdsResultCode.Success, there.ResultCode);
        // nor one that starts with the referral entry's name
        var starts = Send(connection, new SdsModifyDnRequest("ou=x," + Base, null, "ou=partners,ou=z"));
        Assert.Equal(here.ResultCode, starts.ResultCode);

        // an entry that is not there
        Assert.Equal(SdsResultCode.NoSuchObject, Send(connection, new SdsModifyDnRequest("ou=nope," + Base, null, "ou=partners")).ResultCode);
        Assert.Equal(SdsResultCode.NoSuchObject, Send(connection, new SdsModifyDnRequest("ou=nope," + Base, Partners, "ou=nope")).ResultCode);

        // a new RDN spelled another way is still the referral entry's name
        Assert.Equal((int)ResultCode.AffectsMultipleDsas, (int)Send(connection, new SdsModifyDnRequest("ou=x," + Base, null, "OU=Partners")).ResultCode);
        Assert.Equal((int)ResultCode.AffectsMultipleDsas, (int)Send(connection, new SdsModifyDnRequest("ou=x," + Base, Base, "ou=partners")).ResultCode);
        Assert.True(server.Directory.Exists("ou=x," + Base));
    }

    [Theory]
    [InlineData("ldap://h3/ou=p,dc=n\tPartner directory", "ldap://h3/cn=x,ou=p,dc=n??base")]
    [InlineData(" ldap://h2/ou=p,dc=n", "ldap://h2/cn=x,ou=p,dc=n??base")]
    [InlineData("ldap://h1/ou=p,dc=n  two spaces", "ldap://h1/cn=x,ou=p,dc=n??base")]
    [InlineData("ldap:///ou=p,dc=n", "ldap:///cn=x,ou=p,dc=n??base")] // no host: legal (RFC 4516), "the same server"
    [InlineData("http://example.net/partners a label", "http://example.net/partners")] // another kind of URI: as it is, less the label
    public void Ref_values_that_AddReferral_would_not_write_are_still_read_as_what_they_are(string stored, string sent)
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .WithEntry(Partners, e => e.Set("objectClass", "referral", "extensibleObject").Set("ou", "partners").Set("ref", stored))
            .Start();
        using var connection = Connect(server);
        Send(connection, new SdsSearchRequest("cn=x," + Partners, "(objectClass=*)", SdsSearchScope.Base));
        Assert.Equal(ResultCode.Referral, server.LastAnswer!.Result!.Code);
        Assert.Equal([sent], Sent(server));
    }

    [Fact]
    public void A_url_without_a_host_is_refused_with_words_that_say_so()
    {
        var directory = new InMemoryDirectory();
        Assert.Contains("names no host", Assert.Throws<ArgumentException>(() => directory.AddReferral(Partners, "ldap:///dc=x")).Message);
        Assert.Contains("is not an LDAP URL", Assert.Throws<ArgumentException>(() => directory.AddReferral(Partners, "http://example.net/")).Message);
    }


    // ---- gaps a second mutation check found --------------------------------------------------------------------

    [Fact]
    public void The_referral_entry_itself_is_no_identity_even_with_a_password_of_its_own()
    {
        using var server = Generic().Configure(d => d.Update(Partners, e => e.Set("userPassword", "partners-secret"))).Start();
        var e = Assert.Throws<LdapException>(() => Connect(server, Partners, "partners-secret"));
        Assert.Equal((int)ResultCode.InvalidCredentials, e.ErrorCode);
    }

    [Fact]
    public void Active_directory_says_no_such_user_for_one_behind_a_referral_entry_whatever_the_password()
    {
        const string child = "DC=child,DC=corp,DC=example,DC=com";
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com")
            .WithUser("admin", "admin-secret")
            .WithReferral(child, "ldap://child.corp.example.com/" + child)
            .WithEntry("CN=eve," + child, e => e.Set("objectClass", "user").Set("cn", "eve").Set("sAMAccountName", "eve")
                .Set("userPrincipalName", "eve@child.corp.example.com").Set("userPassword", "eve-secret"))
            .Start();
        foreach (var password in new[] { "eve-secret", "wrong" })
        {
            Assert.Throws<LdapException>(() => Connect(server, "CN=eve," + child, password));
            // 525 is "user not found"; 52e, "wrong password", would say that the user is known here
            Assert.Contains(", data 525,", server.LastAnswer!.Result!.Message);
        }
    }

    [Fact]
    public void An_anonymous_password_change_behind_a_referral_entry_is_answered_as_for_a_user_that_does_not_exist()
    {
        using var server = WithBobBehindTheReferral().Start();
        using var anonymous = Connect(server, user: null);
        // spelled otherwise than the entry is, so an answer made from the entry that was found would show
        foreach (var uid in new[] { "BOB", "NOBODY" })
        {
            var name = $"UID={uid},OU=Partners,DC=Example,DC=Com";
            Send(anonymous, new SdsExtendedRequest(Protocol.ExtendedRequest.PasswordModify, Fuzzing.ClientEncoder.PasswordModify(name, "bob-secret", "changed")));
            Assert.Equal(new LdapResult(ResultCode.NoSuchObject, $"No such user: {name}"), server.LastAnswer!.Result);
        }
    }

    [Fact]
    public void Taking_the_name_of_a_referral_entry_at_the_top_affects_several_servers_and_the_answer_names_it()
    {
        using var server = Generic()
            .WithEntry("o=acme", e => e.Set("objectClass", "organization").Set("o", "acme"))
            .WithReferral("o=partners", "ldap://partners.example.net/o=partners")
            .WithEntry("ou=x," + Base, e => e.Set("objectClass", "organizationalUnit").Set("ou", "x"))
            .Start();
        using var connection = Connect(server);

        // the parent of the new name is the root: there is no "," to put between the two
        var response = Send(connection, new SdsModifyDnRequest("o=acme", null, "o=partners"));
        Assert.Equal((int)ResultCode.AffectsMultipleDsas, (int)response.ResultCode);
        Assert.Equal("'o=partners' is held by another server.", server.LastAnswer!.Result!.Message);
        Assert.True(server.Directory.Exists("o=acme"));

        response = Send(connection, new SdsModifyDnRequest("ou=x," + Base, null, "ou=partners"));
        Assert.Equal((int)ResultCode.AffectsMultipleDsas, (int)response.ResultCode);
        Assert.Equal($"'{Partners}' is held by another server.", server.LastAnswer!.Result!.Message);
    }

    [Fact]
    public void A_label_is_taken_off_a_uri_that_is_no_ldap_url_too()
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .WithLdif("""
                dn: ou=partners,dc=example,dc=com
                objectClass: referral
                objectClass: extensibleObject
                ou: partners
                ref: http://partners.example.net/directory Partner directory
                ref: ldap://hostb/ou=people,dc=partners,dc=net The same over LDAP
                """)
            .Start();
        using var connection = Connect(server);
        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsCompareRequest("cn=x," + Partners, "cn", "x")).ResultCode);
        Assert.Equal(["http://partners.example.net/directory", "ldap://hostb/cn=x,ou=people,dc=partners,dc=net"], Sent(server));
    }

    [Fact]
    public void Active_directory_names_an_ipv6_host_whole_with_or_without_a_port_and_any_other_uri_as_it_is()
    {
        const string child = "DC=child,DC=corp,DC=example,DC=com";
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com")
            .WithUser("admin", "admin-secret")
            .WithReferral(child, "ldap://[fe80::1]/" + child)
            .Configure(d => d.Update(child, e => e.Set("ref", "ldap://[fe80::1]/" + child, "ldaps://[fe80::2]:636/" + child, "http://example.net/child")))
            .Start();
        using var connection = Connect(server, "admin@corp.example.com");
        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsCompareRequest("CN=x," + child, "cn", "x")).ResultCode);
        Assert.Equal(
            "0000202B: RefErr: DSID-03100835, data 0, 3 access points\n\tref 1: '[fe80::1]'\n\tref 2: '[fe80::2]'\n\tref 3: 'http://example.net/child'\n",
            server.LastAnswer!.Result!.Message);
    }

    [Theory]
    [InlineData("ldap://host/dc=x\tlabel")]
    [InlineData("ldap://host/dc=x\n")]
    [InlineData("ldap://ho\rst/dc=x")]
    [InlineData("ldap://host:65536/dc=x")]
    [InlineData("ldap://host:+389/dc=x")]
    [InlineData("ldap://host:/dc=x")]
    [InlineData("ldap://host]/dc=x")]
    [InlineData("ldap://host]:389/dc=x")]
    public void A_url_with_other_whitespace_a_port_that_is_none_or_half_a_bracket_is_no_ldap_url(string url)
    {
        Assert.False(LdapUrl.TrySplit(url, out _, out _));
        Assert.Throws<ArgumentException>(() => new InMemoryDirectory().DefaultReferral = [url]);
    }

    [Theory]
    [InlineData("ldap://h:65535/dc=x", "ldap://h:65535", "dc=x")]
    [InlineData("ldap://h:0", "ldap://h:0", null)]
    [InlineData("ldap://[::1]/dc=x", "ldap://[::1]", "dc=x")]
    [InlineData("ldaps://[fe80::1]:636?cn", "ldaps://[fe80::1]:636", null)]
    public void The_server_of_an_ldap_url_may_have_any_port_and_an_ipv6_address(string url, string server, string? dn)
    {
        Assert.True(LdapUrl.TrySplit(url, out var actualServer, out var actualDn));
        Assert.Equal(server, actualServer);
        Assert.Equal(dn, actualDn);
    }

    [Fact]
    public void Results_differ_when_any_one_member_differs_and_can_be_hashed_without_urls()
    {
        string[] urls = ["ldap://a/dc=x", "ldap://b/dc=x"];
        var one = new LdapResult(ResultCode.Referral, "m", "dc=x", urls);
        // "with" keeps the list: each of these differs in the one member alone
        Assert.NotEqual(one, one with { Code = ResultCode.Busy });
        Assert.NotEqual(one, one with { Message = "other" });
        Assert.NotEqual(one, one with { MatchedDn = "dc=y" });
        Assert.NotEqual(one, one with { Referrals = ["ldap://a/dc=x", "ldap://c/dc=x"] }); // as many, another one
        Assert.NotEqual(one, one with { Referrals = ["ldap://b/dc=x", "ldap://a/dc=x"] }); // the order is the order to try them in
        Assert.NotEqual(one, one with { Referrals = ["ldap://a/dc=x", "ldap://b/DC=X"] });
        Assert.Equal(one, one with { Referrals = [.. urls] });
        Assert.False(one.Equals(null));

        Assert.NotEqual(new LdapResult(ResultCode.Success), new LdapResult(ResultCode.Busy));
        Assert.Equal(new LdapResult(ResultCode.Success), new LdapResult(ResultCode.Success, Referrals: []));
        Assert.Equal(LdapResult.Success.GetHashCode(), new LdapResult(ResultCode.Success, Referrals: []).GetHashCode());
    }

    [Fact]
    public void A_single_url_is_printed_and_an_empty_list_is_not()
    {
        var single = new LdapResult(ResultCode.Referral, Referrals: ["ldap://a/dc=x"]);
        var none = new LdapResult(ResultCode.Success, Referrals: []);
        Assert.Equal("LdapResult { Code = Referral, Message = , MatchedDn = , Referrals = [ldap://a/dc=x] }", single.ToString());
        Assert.Equal("LdapResult { Code = Success, Message = , MatchedDn =  }", none.ToString());

        var delete = new Protocol.DeleteRequest("cn=x");
        Assert.Equal("#7 Delete cn=x => Referral [ldap://a/dc=x]", new RecordedRequest(7, null, false, delete, single).ToString());
        Assert.Equal("#7 Delete cn=x => Success", new RecordedRequest(7, null, false, delete, none).ToString());
    }

    [Fact]
    public void ManageDsaIT_is_about_referral_entries_and_leaves_the_default_referral_as_it_is()
    {
        using var server = Generic().WithDefaultReferral("ldap://root.example.org").Start();
        using var connection = Connect(server);
        var search = new SdsSearchRequest("dc=other,dc=org", "(objectClass=*)", SdsSearchScope.Base);
        search.Controls.Add(ManageDsaIt());
        var response = Send(connection, search);
        Assert.Equal(SdsResultCode.Referral, response.ResultCode);
        Assert.Equal(["ldap://root.example.org/dc=other,dc=org??base"], Urls(response));
    }

    // ---- found in the third review -----------------------------------------------------------------------------

    [Fact]
    public void A_default_referral_does_not_stop_a_suffix_from_being_renamed()
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .WithEntry("o=other", e => e.Set("objectClass", "top", "organization").Set("o", "other"))
            .WithDefaultReferral("ldap://root.example.org").Start();
        using var connection = Connect(server);

        // the new name of a suffix is outside every naming context by construction, and still this server's
        Assert.Equal(SdsResultCode.Success, Send(connection, new SdsModifyDnRequest("o=other", null, "o=another")).ResultCode);
        Assert.True(server.Directory.Exists("o=another"));
        // a move to a parent outside the directory is another matter
        Assert.Equal((int)ResultCode.AffectsMultipleDsas, (int)Send(connection, new SdsModifyDnRequest("o=another", "dc=elsewhere,dc=org", "o=another")).ResultCode);
        Assert.True(server.Directory.Exists("o=another"));
    }

    [Fact]
    public void The_base_dn_is_this_servers_own_also_while_no_entry_has_it()
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret").WithDefaultReferral("ldap://root.example.org").Start();
        using var connection = Connect(server);
        server.Directory.Clear();

        Assert.Equal(SdsResultCode.NoSuchObject, Send(connection, new SdsSearchRequest(Base, "(objectClass=*)", SdsSearchScope.Base)).ResultCode);
        Assert.Equal(SdsResultCode.NoSuchObject, Send(connection, new SdsCompareRequest("cn=x," + Base, "cn", "x")).ResultCode);
        var add = new SdsAddRequest(Base, new DirectoryAttribute("objectClass", "top", "domain"), new DirectoryAttribute("dc", "example"));
        Assert.Equal(SdsResultCode.Success, Send(connection, add).ResultCode);
        // and what is outside still is
        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsCompareRequest("dc=other,dc=org", "dc", "other")).ResultCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t ")]
    public void A_ref_value_that_says_nothing_names_no_server(string blank)
    {
        // next to a real one it is left out
        using var server = Generic().Configure(d => d.Update(Partners, e => e.Set("ref", blank, "ldap://partners.example.net/ou=people,dc=partners,dc=net"))).Start();
        using var connection = Connect(server);
        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsCompareRequest("cn=x," + Partners, "cn", "x")).ResultCode);
        Assert.Equal(["ldap://partners.example.net/cn=x,ou=people,dc=partners,dc=net"], Sent(server));

        // alone it leaves an entry that refers nowhere: an ordinary entry, as one without ref is
        server.Directory.Update(Partners, e => e.Set("ref", blank));
        Assert.Equal(SdsResultCode.NoSuchObject, Send(connection, new SdsCompareRequest("cn=x," + Partners, "cn", "x")).ResultCode);
        var search = (SearchResponse)Send(connection, new SdsSearchRequest(Base, "(objectClass=*)", SdsSearchScope.Subtree));
        Assert.Equal(SdsResultCode.Success, search.ResultCode);
        Assert.Empty(search.References.Cast<SearchResultReference>());
        Assert.Contains(search.Entries.Cast<SearchResultEntry>(), e => e.DistinguishedName.Equals(Partners, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A_move_below_itself_is_refused_as_that_also_when_a_referral_entry_is_there()
    {
        using var server = Generic()
            .WithEntry("ou=a," + Base, e => e.Set("objectClass", "top", "organizationalUnit").Set("ou", "a"))
            .WithReferral("ou=r,ou=a," + Base, "ldap://h/ou=r,dc=z")
            .Start();
        using var connection = Connect(server);
        Assert.Equal(SdsResultCode.UnwillingToPerform, Send(connection, new SdsModifyDnRequest("ou=a," + Base, "ou=r,ou=a," + Base, "ou=a")).ResultCode);
    }

    [Fact]
    public void With_ManageDsaIT_the_name_of_a_referral_entry_is_a_name_that_is_taken()
    {
        using var server = Generic().WithEntry("ou=x," + Base, e => e.Set("objectClass", "organizationalUnit").Set("ou", "x")).Start();
        using var connection = Connect(server);
        var rename = new SdsModifyDnRequest("ou=x," + Base, null, "ou=partners");
        rename.Controls.Add(ManageDsaIt());
        Assert.Equal(SdsResultCode.EntryAlreadyExists, Send(connection, rename).ResultCode);
    }

    [Fact]
    public void The_schema_says_that_ref_is_for_knowledge_of_other_servers()
    {
        using var server = Generic().Start();
        var types = server.Directory.FindSubschema(server.Directory.SubschemaDn)!.GetStrings("attributeTypes");
        Assert.Contains("( 2.16.840.1.113730.3.1.34 NAME 'ref' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE distributedOperation )", types);
    }

    // ---- gaps a third mutation check found ---------------------------------------------------------------------

    [Fact]
    public void An_anonymous_client_is_told_to_bind_on_every_write_and_never_where_to_go()
    {
        using var server = Generic().WithDefaultReferral("ldap://root.example.org").Start();
        using var connection = Connect(server, user: null);
        foreach (var name in new[] { "cn=Acme," + Partners, Partners, "cn=Acme,dc=other,dc=org" })
        {
            DirectoryRequest[] requests =
            [
                new SdsAddRequest(name, "organizationalRole"),
                new SdsModifyRequest(name, DirectoryAttributeOperation.Replace, "description", "x"),
                new SdsDeleteRequest(name),
                new SdsModifyDnRequest(name, Base, "cn=Acme2"),
            ];
            foreach (var request in requests)
            {
                var response = Send(connection, request);
                Assert.True(SdsResultCode.StrongAuthRequired == response.ResultCode, request.GetType().Name + " " + name + ": " + response.ResultCode);
                Assert.Empty(Sent(server));
            }
        }
    }

    [Fact]
    public void An_anonymous_client_that_may_search_is_sent_away_from_a_search_and_a_compare_like_a_bound_one()
    {
        using var server = Generic().WithDefaultReferral("ldap://root.example.org").AllowAnonymousSearch().Start();
        using var connection = Connect(server, user: null);

        Send(connection, new SdsSearchRequest("cn=x," + Partners, "(objectClass=*)", SdsSearchScope.OneLevel));
        Assert.Equal(ResultCode.Referral, server.LastAnswer!.Result!.Code);
        Assert.Equal(
            ["ldap://partners.example.net/cn=x,ou=people,dc=partners,dc=net??one", "ldap://backup.example.net:1389/cn=x,ou=people,dc=partners,dc=net??one"],
            Sent(server));

        Send(connection, new SdsCompareRequest("cn=x," + Partners, "cn", "x"));
        Assert.Equal(ResultCode.Referral, server.LastAnswer!.Result!.Code);
        Assert.Equal(
            ["ldap://partners.example.net/cn=x,ou=people,dc=partners,dc=net", "ldap://backup.example.net:1389/cn=x,ou=people,dc=partners,dc=net"],
            Sent(server));

        // the default referral, too
        Send(connection, new SdsSearchRequest("dc=other,dc=org", "(objectClass=*)", SdsSearchScope.Base));
        Assert.Equal(["ldap://root.example.org/dc=other,dc=org??base"], Sent(server));
        Send(connection, new SdsCompareRequest("dc=other,dc=org", "dc", "other"));
        Assert.Equal(["ldap://root.example.org/dc=other,dc=org"], Sent(server));

        // to read is not to write: for a write it is still "bind first"
        Assert.Equal(SdsResultCode.StrongAuthRequired, Send(connection, new SdsDeleteRequest("cn=x," + Partners)).ResultCode);
        Assert.Empty(Sent(server));
    }

    [Fact]
    public void With_ManageDsaIT_an_entry_is_added_below_a_referral_entry_and_the_referral_entry_is_renamed()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);

        var add = new SdsAddRequest("cn=Acme," + Partners, new DirectoryAttribute("objectClass", "organizationalRole"), new DirectoryAttribute("cn", "Acme"));
        add.Controls.Add(ManageDsaIt());
        Assert.Equal(SdsResultCode.Success, Send(connection, add).ResultCode);
        Assert.True(server.Directory.Exists("cn=Acme," + Partners));

        // the name of a referral entry is, to a client that says ManageDsaIT, a name that is taken like any other
        var taken = new SdsModifyDnRequest("ou=users," + Base, null, "ou=partners");
        taken.Controls.Add(ManageDsaIt());
        Assert.Equal(SdsResultCode.EntryAlreadyExists, Send(connection, taken).ResultCode);

        var rename = new SdsModifyDnRequest("cn=Acme," + Partners, null, "cn=Acme2");
        rename.Controls.Add(ManageDsaIt());
        Assert.Equal(SdsResultCode.Success, Send(connection, rename).ResultCode);
        Assert.True(server.Directory.Exists("cn=Acme2," + Partners));
        Assert.False(server.Directory.Exists("cn=Acme," + Partners));

        // without the control all of it is the other server's business again
        Assert.Equal(SdsResultCode.Referral, Send(connection, new SdsModifyDnRequest("cn=Acme2," + Partners, null, "cn=Acme3")).ResultCode);
        Assert.True(server.Directory.Exists("cn=Acme2," + Partners));
    }

    [Fact]
    public void A_bound_client_that_knows_the_old_password_is_sent_away_all_the_same_and_dn_colon_is_no_part_of_the_name()
    {
        using var server = WithBobBehindTheReferral().Start();
        using var admin = Connect(server);
        const string bobThere = "ldap://partners.example.net/uid=bob,ou=people,dc=partners,dc=net";

        // the old password is proof of who asks, not a way past the referral entry
        Send(admin, PasswordModifyRequest("uid=bob," + Partners, "bob-secret", "changed"));
        Assert.Equal(ResultCode.Referral, server.LastAnswer!.Result!.Code);
        Assert.Equal(bobThere, Sent(server)[0]);

        // "dn:" is written in either case
        foreach (var prefix in new[] { "dn:", "DN:" })
        {
            Send(admin, PasswordModifyRequest(prefix + "uid=bob," + Partners, null, "changed"));
            Assert.Equal(ResultCode.Referral, server.LastAnswer!.Result!.Code);
            Assert.Equal(bobThere, Sent(server)[0]);
        }
        Assert.Equal("bob-secret", server.Directory.Find("uid=bob," + Partners)!.GetString("userPassword"));

        // and it is not part of the name the answer gives back
        Send(admin, PasswordModifyRequest("dn:uid=nobody,ou=users," + Base, null, "changed"));
        Assert.Equal(new LdapResult(ResultCode.NoSuchObject, "No such user: uid=nobody,ou=users," + Base), server.LastAnswer!.Result);
    }

    [Fact]
    public void A_subtree_search_beside_the_referral_entry_gets_no_reference()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);
        var (entries, references) = Search(connection, "ou=users," + Base, SdsSearchScope.Subtree);
        Assert.Equal(["ou=users," + Base, Admin, "uid=alice,ou=users," + Base], entries);
        Assert.Empty(references);
    }

    [Fact]
    public void The_directory_hands_out_copies_of_its_referral_entries_and_the_base_of_a_search_is_not_below_itself()
    {
        var directory = new InMemoryDirectory();
        directory.Add(new Entry(Base).Set("objectClass", "top", "domain").Set("dc", "example"));
        directory.AddReferral(Partners, There);

        var above = directory.ReferralAtOrAbove("cn=x," + Partners)!;
        Assert.Equal(Partners, above.Dn.ToString());
        above.Set("ref", "ldap://changed.example.net");
        foreach (var scope in new[] { Protocol.SearchScope.SingleLevel, Protocol.SearchScope.WholeSubtree })
        {
            var below = Assert.Single(directory.ReferralsBelow(Base, scope));
            Assert.Equal(Partners, below.Dn.ToString());
            below.Set("ref", "ldap://changed.example.net");
            Assert.Empty(directory.ReferralsBelow(Partners, scope));
        }
        Assert.Empty(directory.ReferralsBelow(Base, Protocol.SearchScope.BaseObject));
        Assert.Equal([There], directory.Find(Partners)!.GetStrings("ref"));

        // the root is every server's own, with or without a default referral
        Assert.True(directory.Holds(DistinguishedName.Root));
        Assert.True(directory.Holds("cn=x," + Base));
        Assert.False(directory.Holds("dc=com"));
    }

    [Fact]
    public void A_list_of_urls_is_checked_whole_before_anything_is_changed_and_null_is_refused_by_name()
    {
        var directory = new InMemoryDirectory();
        directory.DefaultReferral = ["ldap://good.example.net"];

        // the second URL is the bad one
        Assert.Throws<ArgumentException>(() => directory.DefaultReferral = ["ldap://other.example.net", "no url at all"]);
        Assert.Equal(["ldap://good.example.net"], directory.DefaultReferral);
        Assert.Throws<ArgumentException>(() => directory.AddReferral(Partners, There, "no url at all"));
        Assert.False(directory.Exists(Partners));

        Assert.Equal("value", Assert.Throws<ArgumentNullException>(() => directory.DefaultReferral = null!).ParamName);
        Assert.Equal("url", Assert.Throws<ArgumentNullException>(() => directory.DefaultReferral = ["ldap://other.example.net", null!]).ParamName);
        Assert.Equal("url", Assert.Throws<ArgumentNullException>(() => directory.AddReferral(Partners, There, null!)).ParamName);
        Assert.Equal("urls", Assert.Throws<ArgumentNullException>(() => directory.AddReferral(Partners, (string[])null!)).ParamName);
        Assert.Equal("directory", Assert.Throws<ArgumentNullException>(() => DirectorySeedExtensions.AddReferral(null!, Partners, There)).ParamName);
        Assert.Equal(["ldap://good.example.net"], directory.DefaultReferral);
        Assert.False(directory.Exists(Partners));
    }

    [Fact]
    public void AddReferral_gives_the_entry_every_part_of_a_name_made_of_several()
    {
        var directory = new InMemoryDirectory { SchemaChecks = true };
        directory.Add(new Entry(Base).Set("objectClass", "top", "domain").Set("dc", "example"));
        var dn = directory.AddReferral("ou=partners+l=Oslo," + Base, There);
        var entry = directory.Find(dn)!;
        Assert.Equal(["partners"], entry.GetStrings("ou"));
        Assert.Equal(["Oslo"], entry.GetStrings("l"));
    }

    [Theory]
    [InlineData("ldap://host/dc=a%20b%zz")] // the second escape is the broken one
    [InlineData("ldap://host/dc=a%2Cb%2")]
    [InlineData("ldap://host/dc=x%z0")] // the first digit is none
    [InlineData("ldap://[fe80::1/dc=x")] // what follows the last colon would do for a port
    [InlineData("ldap://[fe80::1:389/dc=x")]
    [InlineData("ldap://[::1]]/dc=x")]
    [InlineData("ldap://[::1]:5]/dc=x")]
    [InlineData("ldap://[not-an-address-at-all]/dc=x")]
    [InlineData("ldap://[127.0.0.1]/dc=x")]
    public void A_url_with_a_broken_escape_after_a_good_one_or_an_address_whose_bracket_never_closes_is_no_ldap_url(string url)
    {
        Assert.False(LdapUrl.TrySplit(url, out _, out _));
        Assert.Throws<ArgumentException>(() => new InMemoryDirectory().DefaultReferral = [url]);
    }

    [Theory]
    [InlineData("cn=a-b.c_d~e,dc=x", "ldap://h/cn=a-b.c_d~e,dc=x")] // unreserved (RFC 3986 §2.3)
    [InlineData("cn=!$&'()*+;,dc=x", "ldap://h/cn=!$&'()*+;,dc=x")] // sub-delims
    [InlineData("cn=a:b@c/d,dc=x", "ldap://h/cn=a:b@c/d,dc=x")] // what else a path may have
    [InlineData("cn=[x]\\5Cy{z}|^`,dc=x", "ldap://h/cn=%5Bx%5D%5C5Cy%7Bz%7D%7C%5E%60,dc=x")] // gen-delims a path may not have, and the rest of ASCII
    public void A_name_in_an_ldap_url_keeps_what_a_url_may_carry_and_has_the_rest_percent_encoded(string dn, string url)
    {
        Assert.Equal(url, LdapUrl.Build("ldap://h", dn));
        Assert.True(LdapUrl.TrySplit(url, out _, out var back));
        Assert.Equal(dn, back);
    }

    [Theory]
    [InlineData("\tldap://h4/ou=p,dc=n", "ldap://h4/cn=x,ou=p,dc=n??base")]
    [InlineData(" \t ldap://h5/ou=p,dc=n\t label", "ldap://h5/cn=x,ou=p,dc=n??base")]
    public void A_ref_value_that_begins_with_a_tab_is_read_from_where_the_url_begins(string stored, string sent)
    {
        using var server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .WithEntry(Partners, e => e.Set("objectClass", "referral", "extensibleObject").Set("ou", "partners").Set("ref", stored))
            .Start();
        using var connection = Connect(server);
        Send(connection, new SdsSearchRequest("cn=x," + Partners, "(objectClass=*)", SdsSearchScope.Base));
        Assert.Equal(ResultCode.Referral, server.LastAnswer!.Result!.Code);
        Assert.Equal([sent], Sent(server));
    }

    [Fact]
    public void The_root_dse_lists_paging_and_sorting_next_to_the_control_for_referrals()
    {
        static string[] Supported(LdapConnection connection)
        {
            var rootDse = Assert.Single(((SearchResponse)connection.SendRequest(new SdsSearchRequest("", "(objectClass=*)", SdsSearchScope.Base, "supportedControl"))).Entries.Cast<SearchResultEntry>());
            return rootDse.Attributes["supportedControl"].GetValues(typeof(string)).Cast<string>().ToArray();
        }

        using var generic = Generic().Start();
        using var connection = Connect(generic);
        Assert.Equal([LdapEncoder.PagedResultsOid, LdapEncoder.SortRequestOid, LdapEncoder.ManageDsaItOid], Supported(connection));

        using var domain = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com").WithUser("admin", "admin-secret").Start();
        using var toDomain = Connect(domain, "admin@corp.example.com");
        Assert.Equal([LdapEncoder.PagedResultsOid, LdapEncoder.SortRequestOid, LdapEncoder.DomainScopeOid], Supported(toDomain));
    }

    [Fact]
    public void The_schema_gives_ref_the_syntax_of_a_directory_string()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);
        var schema = new SdsSearchRequest(server.Directory.SubschemaDn.ToString(), "(objectClass=subschema)", SdsSearchScope.Base, "attributeTypes");
        var subschema = Assert.Single(((SearchResponse)connection.SendRequest(schema)).Entries.Cast<SearchResultEntry>());
        var definition = Assert.Single(subschema.Attributes["attributeTypes"].GetValues(typeof(string)).Cast<string>(), t => t.Contains("NAME 'ref'", StringComparison.Ordinal));
        Assert.Contains(" SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 ", definition); // RFC 3296 §2.2
    }

    [Fact]
    public void A_result_has_its_urls_in_field_3_after_the_message_and_a_reference_is_a_list_of_urls()
    {
        static string[] Strings(System.Formats.Asn1.AsnReader reader)
        {
            var found = new List<string>();
            while (reader.HasData) found.Add(System.Text.Encoding.UTF8.GetString(reader.ReadOctetString()));
            return found.ToArray();
        }
        static System.Formats.Asn1.AsnReader Operation(byte[] bytes, int id, int tag)
        {
            var message = new System.Formats.Asn1.AsnReader(bytes, System.Formats.Asn1.AsnEncodingRules.BER).ReadSequence();
            Assert.True(message.TryReadInt32(out var actual));
            Assert.Equal(id, actual);
            var operation = message.ReadSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.Application, tag, true));
            Assert.False(message.HasData);
            return operation;
        }

        // LDAPResult ::= SEQUENCE { resultCode, matchedDN, diagnosticMessage, referral [3] Referral OPTIONAL }
        string[] urls = ["ldap://a.example.net/dc=x", "ldap://b.example.net/cn=Zo%C3%AB,dc=x??sub"];
        // (the code is the test's to choose: what an interceptor asks for is what is sent)
        foreach (var code in new[] { ResultCode.Referral, ResultCode.Busy })
        {
            var result = Operation(LdapEncoder.Result(7, 5, new LdapResult(code, "m", "dc=x", urls)), 7, 5);
            result.ReadEnumeratedBytes();
            Assert.Equal(["dc=x", "m"], [System.Text.Encoding.UTF8.GetString(result.ReadOctetString()), System.Text.Encoding.UTF8.GetString(result.ReadOctetString())]);
            var field = result.PeekTag();
            Assert.Equal(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 3, true), field);
            Assert.Equal(urls, Strings(result.ReadSequence(field)));
            Assert.False(result.HasData);
        }

        // SearchResultReference ::= [APPLICATION 19] SEQUENCE SIZE (1..MAX) OF uri URI
        Assert.Equal(urls, Strings(Operation(LdapEncoder.SearchResultReference(9, urls), 9, 19)));
    }

    [Fact]
    public async Task The_accept_loop_ends_quietly_when_its_listener_is_not_listening()
    {
        // A listener stopped between the loop's look at "are we stopping" and its call says "not listening" with
        // an InvalidOperationException. The moment cannot be hit from outside, so the loop is run on a listener
        // that never listened, which says the same.
        using var server = Generic().Start();
        var loop = typeof(LdapTestServer).GetMethod("AcceptLoopAsync", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        var notListening = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        await ((Task)loop.Invoke(server, [notListening, false])!).WaitAsync(Patience, TestContext.Current.CancellationToken);

        // and the server goes on
        using var connection = Connect(server);
    }
}
