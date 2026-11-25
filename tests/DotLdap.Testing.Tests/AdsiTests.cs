using System.DirectoryServices;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using DotLdap.Testing.Protocol;
using SearchScope = System.DirectoryServices.SearchScope;

namespace DotLdap.Testing.Tests;

/// <summary>Runs on Windows only: System.DirectoryServices is a wrapper over ADSI.</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute([CallerFilePath] string? sourceFilePath = null, [CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath, sourceLineNumber)
    {
        if (!OperatingSystem.IsWindows()) Skip = "System.DirectoryServices (ADSI) exists on Windows only.";
    }
}

/// <summary>
/// The server driven by <see cref="DirectoryEntry"/> and <see cref="DirectorySearcher"/>, the most common way a
/// .NET application talks to Active Directory. ADSI sits between them and the wire. It reads the published
/// schema to decide what type a value has, and it wants to see paging and sorting announced in the root DSE.
/// </summary>
[SupportedOSPlatform("windows")]
public class AdsiTests
{
    private const string BaseDn = "DC=corp,DC=example,DC=com";
    private const string UsersDn = "CN=Users," + BaseDn;
    private const string AliceDn = "CN=alice," + UsersDn;

    private static LdapTestServer StartActiveDirectory(Action<LdapTestServerBuilder>? more = null)
    {
        var builder = LdapTestServer.Create()
            .AsActiveDirectory()
            .WithBaseDn(BaseDn)
            .WithUser("admin", "admin-secret")
            .WithUser("alice", "alice-secret", u => u.Email("alice@corp.example.com").DisplayName("Alice Liddell").MemberOf("Developers"))
            .WithUser("bob", "bob-secret")
            .WithUser("carol", "carol-secret")
            .WithUser("dave", "dave-secret", u => u.Disabled())
            .WithGroup("Engineering", "Developers");
        more?.Invoke(builder);
        return builder.Start();
    }

    /// <summary>
    /// A simple bind, which is what the server speaks. The default of <see cref="DirectoryEntry"/> is
    /// <see cref="AuthenticationTypes.Secure"/>, which means NTLM or Kerberos.
    /// </summary>
    private static DirectoryEntry Open(LdapTestServer server, string dn, string user = "admin@corp.example.com", string password = "admin-secret") =>
        new($"LDAP://{server.Host}:{server.Port}/{dn}", user, password, AuthenticationTypes.None);

    private static void AssertHealthy(LdapTestServer server)
    {
        Assert.Empty(server.ProtocolErrors);
        Assert.Empty(server.InternalErrors);
    }

    private static T Value<T>(SearchResult result, string property) => Assert.IsType<T>(Assert.Single(result.Properties[property].Cast<object>()));

    // ---- bind ------------------------------------------------------------------------------------------------

    [WindowsFact]
    public void Binds_with_every_name_form_Active_Directory_takes()
    {
        using var server = StartActiveDirectory();

        foreach (var user in new[] { "alice@corp.example.com", AliceDn, "CORP\\alice", "alice" })
        {
            using var entry = Open(server, BaseDn, user, "alice-secret");
            Assert.NotNull(entry.NativeObject); // this is what binds
            Assert.Equal("DC=corp", entry.Name);
            Assert.Equal("domainDNS", entry.SchemaClassName);
        }
        AssertHealthy(server);
    }

    [WindowsFact]
    public void Failed_binds_carry_the_error_and_data_code_a_domain_controller_gives()
    {
        using var server = StartActiveDirectory();

        foreach (var (user, password, data) in new[]
                 {
                     ("alice@corp.example.com", "wrong", "data 52e"),
                     ("nobody@corp.example.com", "whatever", "data 525"),
                     ("dave@corp.example.com", "dave-secret", "data 533"),
                 })
        {
            using var entry = Open(server, BaseDn, user, password);
            var e = Assert.Throws<DirectoryServicesCOMException>(() => entry.NativeObject);
            Assert.Equal(unchecked((int)0x8007052E), e.HResult); // "The user name or password is incorrect."
            Assert.Contains(data, e.ExtendedErrorMessage);
        }
        AssertHealthy(server);
    }

    [WindowsFact]
    public void The_default_authentication_type_asks_for_NTLM_and_gets_a_refusal_that_says_what_to_do()
    {
        using var server = StartActiveDirectory();
        var path = $"LDAP://{server.Host}:{server.Port}/{BaseDn}";

        foreach (var open in new Func<DirectoryEntry>[]
                 {
                     () => new DirectoryEntry(path, "admin@corp.example.com", "admin-secret"), // AuthenticationTypes.Secure
                     () => new DirectoryEntry(path),                                           // ...as the current Windows user
                 })
        {
            using var entry = open();
            var e = Assert.Throws<DirectoryServicesCOMException>(() => entry.NativeObject);
            Assert.Equal(unchecked((int)0x80072027), e.HResult); // "The requested authentication method is not supported by the server."
            Assert.Contains("AuthenticationTypes.None", e.ExtendedErrorMessage);
        }
        Assert.Contains(server.Requests, r => r.Request is BindRequest { SaslMechanism: BindRequest.Sicily });
        AssertHealthy(server); // refused, but as a proper answer: no dropped connection
    }

    [WindowsFact]
    public void An_anonymous_bind_is_told_to_bind_first_as_by_a_domain_controller()
    {
        using var server = StartActiveDirectory();
        using var entry = new DirectoryEntry($"LDAP://{server.Host}:{server.Port}/{BaseDn}", null, null, AuthenticationTypes.Anonymous);

        var e = Assert.Throws<DirectoryServicesCOMException>(() => entry.NativeObject);

        Assert.Equal(unchecked((int)0x80072020), e.HResult); // "An operations error occurred."
        Assert.Contains("a successful bind must be completed", e.ExtendedErrorMessage);
        AssertHealthy(server);
    }

    [WindowsFact]
    public void The_root_DSE_reads_like_an_entry()
    {
        using var server = StartActiveDirectory();
        using var rootDse = Open(server, "RootDSE");

        Assert.Equal(BaseDn, rootDse.Properties["defaultNamingContext"].Value);
        Assert.Equal(server.Directory.SubschemaDn.ToString(), rootDse.Properties["subschemaSubentry"].Value);
        Assert.Contains(LdapEncoder.SortRequestOid, rootDse.Properties["supportedControl"].Cast<string>());
        AssertHealthy(server);
    }

    // ---- search ----------------------------------------------------------------------------------------------

    [WindowsFact]
    public void Search_results_come_typed_by_the_schema()
    {
        using var server = StartActiveDirectory(b => b
            .Configure(d => d.DefineAttribute("badgeNumber", AttributeSyntax.Integer, singleValued: true))
            .Configure(d => d.Update(AliceDn, e => e.Set("assetTag", "A-17").Set("badgeNumber", "42").SetBinary("firmwareImage", [0xFF, 0xFE, 0x00, 0x80]))));
        using var root = Open(server, BaseDn);
        using var searcher = new DirectorySearcher(root, "(&(objectCategory=person)(objectClass=user)(sAMAccountName=alice))");

        var alice = searcher.FindOne()!;

        Assert.Equal("alice", Value<string>(alice, "sAMAccountName"));
        Assert.Equal("alice@corp.example.com", Value<string>(alice, "userPrincipalName"));
        Assert.Equal("Alice Liddell", Value<string>(alice, "displayName"));
        Assert.Equal($"CN=Developers,{UsersDn}", Value<string>(alice, "memberOf"));
        Assert.Equal(512, Value<int>(alice, "userAccountControl"));
        Assert.Equal(513, Value<int>(alice, "primaryGroupID"));
        Assert.True(Value<long>(alice, "pwdLastSet") > 0);
        Assert.Equal(long.MaxValue, Value<long>(alice, "accountExpires"));
        Assert.InRange(Value<DateTime>(alice, "whenCreated"), DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1));
        Assert.Equal(16, Value<byte[]>(alice, "objectGUID").Length);
        Assert.Equal(server.Directory.Find(AliceDn)!.GetValues("objectSid")[0], Value<byte[]>(alice, "objectSid"));
        Assert.Equal(["top", "person", "organizationalPerson", "user"], alice.Properties["objectClass"].Cast<string>());
        // Attributes the server has never heard of: a string or binary, as the data says; a number when declared.
        Assert.Equal("A-17", Value<string>(alice, "assetTag"));
        Assert.Equal([0xFF, 0xFE, 0x00, 0x80], Value<byte[]>(alice, "firmwareImage"));
        Assert.Equal(42, Value<int>(alice, "badgeNumber"));
        AssertHealthy(server);
    }

    [WindowsFact]
    public void Paged_search_returns_everything_in_pages()
    {
        using var server = StartActiveDirectory();
        using var root = Open(server, BaseDn);
        using var searcher = new DirectorySearcher(root, "(&(objectCategory=person)(objectClass=user))", ["sAMAccountName"]) { PageSize = 2 };

        using var results = searcher.FindAll();
        var names = results.Cast<SearchResult>().Select(r => Value<string>(r, "sAMAccountName")).ToArray();

        Assert.Equal(["admin", "alice", "bob", "carol", "dave"], names.Order());
        Assert.Equal(3, server.Requests.Count(r => r.Request is Protocol.SearchRequest { Scope: Protocol.SearchScope.WholeSubtree }));
        AssertHealthy(server);
    }

    [WindowsFact]
    public void Sorted_search_is_sorted_by_the_server()
    {
        using var server = StartActiveDirectory();
        using var root = Open(server, BaseDn);
        using var searcher = new DirectorySearcher(root, "(&(objectCategory=person)(objectClass=user))", ["sAMAccountName"])
        {
            PageSize = 2,
            Sort = new SortOption("sAMAccountName", SortDirection.Descending),
        };

        using var results = searcher.FindAll();

        Assert.Equal(["dave", "carol", "bob", "alice", "admin"], results.Cast<SearchResult>().Select(r => Value<string>(r, "sAMAccountName")));
        AssertHealthy(server);
    }

    [WindowsFact]
    public void Scopes_size_limit_and_the_in_chain_rule()
    {
        using var server = StartActiveDirectory();
        using var root = Open(server, BaseDn);
        using var users = Open(server, UsersDn);

        using (var oneLevel = new DirectorySearcher(users, "(objectClass=*)", ["cn"], SearchScope.OneLevel))
        using (var found = oneLevel.FindAll())
            Assert.Equal(8, found.Count); // five users, two groups and the generated "Domain Users"

        using (var namesOnly = new DirectorySearcher(users, "(objectClass=*)", ["cn"], SearchScope.OneLevel) { PropertyNamesOnly = true })
        using (var found = namesOnly.FindAll())
        {
            Assert.Equal(8, found.Count);
            Assert.All(found.Cast<SearchResult>(), r => Assert.Empty(r.Properties["cn"])); // names without values
        }

        using (var limited = new DirectorySearcher(root, "(objectClass=user)", ["cn"]) { SizeLimit = 2 })
        using (var found = limited.FindAll())
            Assert.Equal(2, found.Count);

        using (var nested = new DirectorySearcher(root, $"(member:1.2.840.113556.1.4.1941:={AliceDn})", ["cn"]))
        using (var found = nested.FindAll())
            Assert.Equal(["Developers", "Engineering"], found.Cast<SearchResult>().Select(r => Value<string>(r, "cn")).Order());
        AssertHealthy(server);
    }

    // ---- DirectoryEntry --------------------------------------------------------------------------------------

    [WindowsFact]
    public void DirectoryEntry_properties_come_typed_by_the_schema()
    {
        using var server = StartActiveDirectory();
        using var alice = Open(server, AliceDn);

        Assert.Equal("CN=alice", alice.Name);
        Assert.Equal("user", alice.SchemaClassName);
        Assert.Equal("alice", alice.Properties["sAMAccountName"].Value);
        Assert.Equal("alice@corp.example.com", alice.Properties["mail"].Value);
        Assert.Equal($"CN=Developers,{UsersDn}", alice.Properties["memberOf"].Value);
        Assert.Equal(512, alice.Properties["userAccountControl"].Value);
        Assert.IsType<DateTime>(alice.Properties["whenCreated"].Value);
        Assert.Equal(new Guid(server.Directory.Find(AliceDn)!.GetValues("objectGUID")[0]), alice.Guid);
        Assert.IsType<byte[]>(alice.Properties["objectSid"].Value);
        // A COM large integer (IADsLargeInteger) in two halves, as with a real domain controller.
        var pwdLastSet = alice.Properties["pwdLastSet"].Value!;
        int Half(string name) => (int)pwdLastSet.GetType().InvokeMember(name, System.Reflection.BindingFlags.GetProperty, null, pwdLastSet, null)!;
        Assert.Equal(server.Directory.Find(AliceDn)!.GetString("pwdLastSet"), (((long)Half("HighPart") << 32) | (uint)Half("LowPart")).ToString());
        Assert.Null(alice.Properties["telephoneNumber"].Value);
        Assert.Contains("sAMAccountName", alice.Properties.PropertyNames.Cast<string>());

        // Constructed attributes have to be asked for by name.
        alice.RefreshCache(["tokenGroups"]);
        var tokenGroups = Assert.IsType<object[]>(alice.Properties["tokenGroups"].Value);
        Assert.Equal(3, tokenGroups.Length); // Developers, Engineering through it, and Domain Users
        Assert.All(tokenGroups, sid => Assert.IsType<byte[]>(sid));
        AssertHealthy(server);
    }

    [WindowsFact]
    public void Walks_from_a_search_result_to_the_entry_its_parent_and_its_siblings()
    {
        using var server = StartActiveDirectory();
        using var root = Open(server, BaseDn);
        using var searcher = new DirectorySearcher(root, "(sAMAccountName=bob)");

        using var bob = searcher.FindOne()!.GetDirectoryEntry();
        using var parent = bob.Parent;

        Assert.EndsWith($"/CN=bob,{UsersDn}", bob.Path);
        Assert.EndsWith("/" + UsersDn, parent.Path);
        Assert.Equal(
            ["CN=admin", "CN=alice", "CN=bob", "CN=carol", "CN=dave", "CN=Developers", "CN=Domain Users", "CN=Engineering"],
            parent.Children.Cast<DirectoryEntry>().Select(c => c.Name).Order(StringComparer.OrdinalIgnoreCase));
        AssertHealthy(server);
    }

    [WindowsFact]
    public void Opens_an_entry_by_its_GUID()
    {
        using var server = StartActiveDirectory();
        var guid = new Guid(server.Directory.Find(AliceDn)!.GetValues("objectGUID")[0]);

        using var entry = Open(server, $"<GUID={guid}>");

        Assert.Equal(AliceDn, entry.Properties["distinguishedName"].Value);
        AssertHealthy(server);
    }

    // ---- writes ----------------------------------------------------------------------------------------------

    [WindowsFact]
    public void CommitChanges_writes_strings_numbers_and_multi_valued_attributes()
    {
        using var server = StartActiveDirectory(b => b.Configure(d => d.DefineAttribute("badgeNumber", AttributeSyntax.Integer, singleValued: true)));
        Entry Stored() => server.Directory.Find(AliceDn)!;

        using (var alice = Open(server, AliceDn))
        {
            alice.Properties["description"].Value = "changed through ADSI";
            alice.Properties["userAccountControl"].Value = 66048;
            alice.Properties["badgeNumber"].Value = 42;           // declared, in no entry so far
            alice.Properties["extensionAttribute5"].Value = "five"; // an Exchange attribute the schema lists
            alice.Properties["otherTelephone"].Add("111");
            alice.Properties["otherTelephone"].Add("222");
            alice.CommitChanges();
        }
        Assert.Equal("changed through ADSI", Stored().GetString("description"));
        Assert.Equal("66048", Stored().GetString("userAccountControl"));
        Assert.Equal("42", Stored().GetString("badgeNumber"));
        Assert.Equal("five", Stored().GetString("extensionAttribute5"));
        Assert.Equal(["111", "222"], Stored().GetStrings("otherTelephone"));

        using (var alice = Open(server, AliceDn))
        {
            Assert.Equal(42, alice.Properties["badgeNumber"].Value);
            alice.Properties["otherTelephone"].Remove("111");
            alice.Properties["description"].Clear();
            alice.CommitChanges();
        }
        Assert.Equal(["222"], Stored().GetStrings("otherTelephone"));
        Assert.False(Stored().Has("description"));
        AssertHealthy(server);
    }

    [WindowsFact]
    public void Creates_renames_moves_and_deletes_entries()
    {
        using var server = StartActiveDirectory();
        var directory = server.Directory;

        using (var users = Open(server, UsersDn))
        using (var erin = users.Children.Add("CN=erin", "user"))
        {
            erin.Properties["sAMAccountName"].Value = "erin";
            erin.CommitChanges();
        }
        var created = directory.Find($"CN=erin,{UsersDn}")!;
        Assert.Equal("erin", created.GetString("sAMAccountName"));
        Assert.True(created.Has("objectSid")); // the server filled in what a domain controller generates

        using (var group = Open(server, $"CN=Engineering,{UsersDn}"))
        {
            group.Properties["member"].Add($"CN=erin,{UsersDn}");
            group.CommitChanges();
        }
        Assert.Contains($"CN=erin,{UsersDn}", directory.Find($"CN=Engineering,{UsersDn}")!.GetStrings("member"));

        using (var carol = Open(server, $"CN=carol,{UsersDn}"))
        using (var target = Open(server, BaseDn))
        {
            carol.Rename("CN=caroline");
            carol.CommitChanges();
            Assert.True(directory.Exists($"CN=caroline,{UsersDn}"));
            carol.MoveTo(target);
            Assert.True(directory.Exists($"CN=caroline,{BaseDn}"));
            Assert.EndsWith($"/CN=caroline,{BaseDn}", carol.Path);
        }

        using (var users = Open(server, UsersDn))
        using (var bob = users.Children.Find("CN=bob", "user"))
            users.Children.Remove(bob);
        Assert.False(directory.Exists($"CN=bob,{UsersDn}"));

        using (var dave = Open(server, $"CN=dave,{UsersDn}"))
            dave.DeleteTree();
        Assert.False(directory.Exists($"CN=dave,{UsersDn}"));
        AssertHealthy(server);
    }

    [WindowsFact]
    public void Resets_a_password_through_unicodePwd()
    {
        // Invoke("SetPassword") needs Kerberos or LDAPS with a certificate Windows trusts. Writing unicodePwd is
        // what it does underneath, and that works: the new password in quotes, as UTF-16.
        using var server = StartActiveDirectory();

        using (var alice = Open(server, AliceDn))
        {
            alice.Properties["unicodePwd"].Value = System.Text.Encoding.Unicode.GetBytes("\"N3w-Passw0rd!\"");
            alice.CommitChanges();
        }

        using (var withNew = Open(server, BaseDn, "alice@corp.example.com", "N3w-Passw0rd!"))
            Assert.NotNull(withNew.NativeObject);
        using (var withOld = Open(server, BaseDn, "alice@corp.example.com", "alice-secret"))
            Assert.Throws<DirectoryServicesCOMException>(() => withOld.NativeObject);
        AssertHealthy(server);
    }

    // ---- the schema over the life of a process ---------------------------------------------------------------

    [WindowsFact]
    public void An_attribute_that_appears_after_ADSI_has_read_the_schema_is_still_found()
    {
        using var server = StartActiveDirectory();
        using (var alice = Open(server, AliceDn))
            Assert.Equal("alice", alice.Properties["sAMAccountName"].Value); // ADSI has the schema now

        server.Directory.Update(AliceDn, e => e.Set("lateAttribute", "late"));

        using (var alice = Open(server, AliceDn))
            Assert.Equal("late", alice.Properties["lateAttribute"].Value);
        using var root = Open(server, BaseDn);
        using var searcher = new DirectorySearcher(root, "(sAMAccountName=alice)", ["lateAttribute"]);
        Assert.Equal("late", Value<string>(searcher.FindOne()!, "lateAttribute"));
        AssertHealthy(server);
    }

    [WindowsFact]
    public void Two_servers_with_the_same_base_DN_and_different_custom_attributes_do_not_mix_up_their_schemas()
    {
        // ADSI keeps schemas in a cache keyed by the DN of the subschema entry. The DN carries a hash of the content.
        using var first = StartActiveDirectory(b => b.Configure(d => d.DefineAttribute("shared", AttributeSyntax.Integer).Update(AliceDn, e => e.Set("shared", "1").Set("onlyFirst", "a"))));
        using var second = StartActiveDirectory(b => b.Configure(d => d.Update(AliceDn, e => e.Set("shared", "one").Set("onlySecond", "b"))));
        Assert.NotEqual(first.Directory.SubschemaDn, second.Directory.SubschemaDn);

        using var aliceOnFirst = Open(first, AliceDn);
        using var aliceOnSecond = Open(second, AliceDn);

        Assert.Equal(1, aliceOnFirst.Properties["shared"].Value);
        Assert.Equal("a", aliceOnFirst.Properties["onlyFirst"].Value);
        Assert.Equal("one", aliceOnSecond.Properties["shared"].Value);
        Assert.Equal("b", aliceOnSecond.Properties["onlySecond"].Value);
        AssertHealthy(first);
        AssertHealthy(second);
    }

    // ---- the generic flavour ---------------------------------------------------------------------------------

    [WindowsFact]
    public void A_disabled_generic_user_reads_cleanly()
    {
        // Its lock is stored as pwdAccountLockedTime = 000001010000Z, a date no client type can hold. The attribute
        // is operational, so reading the entry does not return it.
        using var server = LdapTestServer.Create()
            .WithUser("admin", "admin-secret")
            .WithUser("mallory", "mallory-secret", u => u.Disabled())
            .Start();
        const string admin = "uid=admin,ou=users,dc=example,dc=com";

        using var root = Open(server, "dc=example,dc=com", admin);
        using var searcher = new DirectorySearcher(root, "(uid=mallory)");
        var found = searcher.FindOne()!;
        Assert.Equal("mallory", Value<string>(found, "uid"));
        Assert.DoesNotContain("pwdaccountlockedtime", found.Properties.PropertyNames.Cast<string>().Select(n => n.ToLowerInvariant()));

        using var mallory = found.GetDirectoryEntry();
        Assert.Equal("mallory", mallory.Properties["cn"].Value);
        Assert.DoesNotContain("pwdAccountLockedTime", mallory.Properties.PropertyNames.Cast<string>(), StringComparer.OrdinalIgnoreCase);
        AssertHealthy(server);
    }

    [WindowsFact]
    public void A_generic_directory_works_through_ADSI_too()
    {
        using var server = LdapTestServer.Create()
            .WithUser("admin", "admin-secret")
            .WithUser("alice", "alice-secret", u => u.Email("alice@example.com").Attribute("uidNumber", "1001").MemberOf("staff"))
            .WithUser("bob", "bob-secret")
            .Start();
        const string admin = "uid=admin,ou=users,dc=example,dc=com";

        using (var alice = Open(server, "uid=alice,ou=users,dc=example,dc=com", admin))
        {
            Assert.Equal("inetOrgPerson", alice.SchemaClassName);
            Assert.Equal("alice@example.com", alice.Properties["mail"].Value);
            Assert.Equal(1001, alice.Properties["uidNumber"].Value);
        }

        using (var root = Open(server, "dc=example,dc=com", admin))
        using (var searcher = new DirectorySearcher(root, "(objectClass=inetOrgPerson)", ["uid", "uidNumber", "memberOf"])
               {
                   PageSize = 2, Sort = new SortOption("uid", SortDirection.Descending),
               })
        using (var results = searcher.FindAll())
        {
            var found = results.Cast<SearchResult>().ToArray();
            Assert.Equal(["bob", "alice", "admin"], found.Select(r => Value<string>(r, "uid")));
            Assert.Equal(1001, Value<int>(found[1], "uidNumber"));
            Assert.Equal("cn=staff,ou=groups,dc=example,dc=com", Value<string>(found[1], "memberOf"));
        }

        using (var bob = Open(server, "uid=bob,ou=users,dc=example,dc=com", admin))
        {
            bob.Properties["description"].Value = "written through ADSI";
            bob.Properties["uidNumber"].Value = 1002;
            bob.CommitChanges();
        }
        var stored = server.Directory.Find("uid=bob,ou=users,dc=example,dc=com")!;
        Assert.Equal("written through ADSI", stored.GetString("description"));
        Assert.Equal("1002", stored.GetString("uidNumber"));
        AssertHealthy(server);
    }
}
