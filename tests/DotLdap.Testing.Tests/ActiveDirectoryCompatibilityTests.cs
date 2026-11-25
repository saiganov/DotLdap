using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;

namespace DotLdap.Testing.Tests;

/// <summary>The Active Directory behaviours that applications written against AD commonly depend on.</summary>
public class ActiveDirectoryCompatibilityTests : IDisposable
{
    private const string BaseDn = "DC=corp,DC=example,DC=com";
    private const string AliceDn = "CN=alice,CN=Users," + BaseDn;

    private readonly LdapTestServer _server = LdapTestServer.Create()
        .AsActiveDirectory()
        .WithBaseDn(BaseDn)
        .WithUser("admin", "admin-secret")
        .WithUser("alice", "alice-secret", u => u.MemberOf("Developers"))
        .WithUser("newbie", "newbie-secret", u => u.MustChangePassword())
        .WithGroup("Engineering", "Developers")
        .WithGroup("Unrelated")
        .Start();

    public void Dispose() => _server.Dispose();

    private LdapConnection Connect(string user = "admin@corp.example.com", string password = "admin-secret", LdapTestServer? server = null)
    {
        server ??= _server;
        var connection = new LdapConnection(new LdapDirectoryIdentifier(server.Host, server.Port))
        {
            AuthType = AuthType.Basic,
            Credential = new NetworkCredential(user, password),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.Bind();
        return connection;
    }

    private static List<SearchResultEntry> Search(LdapConnection connection, string baseDn, string filter, SearchScope scope, params string[] attributes) =>
        ((SearchResponse)connection.SendRequest(new SearchRequest(baseDn, filter, scope, attributes))).Entries.Cast<SearchResultEntry>().ToList();

    private byte[] SidOf(string dn) => _server.Directory.Find(dn)!.GetValues("objectSid")[0];

    [Fact]
    public void TokenGroups_lists_nested_groups_and_the_primary_group()
    {
        using var connection = Connect();
        var alice = Assert.Single(Search(connection, AliceDn, "(objectClass=*)", SearchScope.Base, "tokenGroups"));
        var sids = alice.Attributes["tokenGroups"].GetValues(typeof(byte[])).Cast<byte[]>().Select(Convert.ToHexString).OrderBy(x => x).ToArray();

        var expected = new[] { "CN=Developers", "CN=Engineering", "CN=Domain Users" }
            .Select(rdn => Convert.ToHexString(SidOf($"{rdn},CN=Users,{BaseDn}"))).OrderBy(x => x).ToArray();
        Assert.Equal(expected, sids);
    }

    [Fact]
    public void TokenGroups_is_returned_only_on_request()
    {
        using var connection = Connect();
        var alice = Assert.Single(Search(connection, AliceDn, "(objectClass=*)", SearchScope.Base));
        Assert.False(alice.Attributes.Contains("tokenGroups"));
        Assert.True(alice.Attributes.Contains("memberOf"));
    }

    [Fact]
    public void Primary_group_is_domain_users_and_is_not_in_memberOf()
    {
        using var connection = Connect();
        var domainUsers = Assert.Single(Search(connection, BaseDn, "(&(objectClass=group)(cn=Domain Users))", SearchScope.Subtree, "primaryGroupToken"));
        Assert.Equal("513", domainUsers.Attributes["primaryGroupToken"][0]);

        var users = Search(connection, BaseDn, "(&(objectClass=user)(primaryGroupID=513))", SearchScope.Subtree, "sAMAccountName", "memberOf");
        Assert.Equal(3, users.Count);
        var alice = users.Single(u => (string)u.Attributes["sAMAccountName"][0] == "alice");
        Assert.Equal($"CN=Developers,CN=Users,{BaseDn}", Assert.Single(alice.Attributes["memberOf"].GetValues(typeof(string))));
    }

    [Theory]
    [InlineData("(&(objectCategory=person)(objectClass=user))", 3)]
    [InlineData("(objectCategory=CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com)", 3)]
    [InlineData("(objectCategory=cn=person, CN=Schema, CN=Configuration, DC=corp, DC=example, DC=com)", 3)] // compared as a DN
    [InlineData("(sAMAccountType=805306368)", 3)]
    [InlineData("(objectCategory=user)", 3)] // a class name stands for that class's category: user means Person
    [InlineData("(objectCategory=container)", 1)] // CN=Users
    [InlineData("(objectCategory=domainDNS)", 1)]
    [InlineData("(objectCategory=group)", 4)] // Developers, Engineering, Unrelated, Domain Users
    [InlineData("(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", 3)]
    public void Common_ad_filters(string filter, int expected)
    {
        using var connection = Connect();
        Assert.Equal(expected, Search(connection, BaseDn, filter, SearchScope.Subtree, "cn").Count);
    }

    [Fact]
    public void Objects_are_found_by_sid_and_guid()
    {
        using var connection = Connect();
        var sid = ActiveDirectory.SidToString(SidOf(AliceDn));
        Assert.StartsWith("S-1-5-21-", sid);
        Assert.Equal(AliceDn, Assert.Single(Search(connection, BaseDn, $"(objectSid={sid})", SearchScope.Subtree, "cn")).DistinguishedName);
        Assert.Equal(AliceDn, Assert.Single(Search(connection, BaseDn, $"(objectSid={sid.ToLowerInvariant()})", SearchScope.Subtree, "cn")).DistinguishedName);
        Assert.Equal(AliceDn, Assert.Single(Search(connection, $"<SID={sid}>", "(objectClass=*)", SearchScope.Base, "cn")).DistinguishedName);

        var guid = new Guid(_server.Directory.Find(AliceDn)!.GetValues("objectGUID")[0]);
        Assert.Equal(AliceDn, Assert.Single(Search(connection, $"<GUID={guid}>", "(objectClass=*)", SearchScope.Base, "cn")).DistinguishedName);
        Assert.Equal(AliceDn, Assert.Single(Search(connection, $"<GUID={Convert.ToHexString(guid.ToByteArray())}>", "(objectClass=*)", SearchScope.Base, "cn")).DistinguishedName);

        var missing = Assert.Throws<DirectoryOperationException>(() => Search(connection, $"<GUID={Guid.NewGuid()}>", "(objectClass=*)", SearchScope.Base));
        Assert.Equal(ResultCode.NoSuchObject, missing.Response.ResultCode);
        // not a GUID or SID at all: that is a syntax error, not a missing object
        foreach (var malformed in new[] { "<nope", "<GUID=zz>", "<SID=12>", "<OID=1.2.3>" })
        {
            var e = Assert.Throws<DirectoryOperationException>(() => Search(connection, malformed, "(objectClass=*)", SearchScope.Base));
            Assert.Equal(ResultCode.InvalidDNSyntax, e.Response.ResultCode);
        }
    }

    [Fact]
    public void Large_attributes_are_read_with_ranged_retrieval()
    {
        using var server = LdapTestServer.Create()
            .AsActiveDirectory()
            .WithBaseDn(BaseDn)
            .Configure(d => { for (var i = 0; i < 25; i++) d.AddUser($"user{i:00}", "pw", u => u.MemberOf("Everyone")); })
            .WithMaxValuesPerAttribute(10)
            .Start();
        using var connection = Connect("user00@corp.example.com", "pw", server);
        var group = $"CN=Everyone,CN=Users,{BaseDn}";

        // Asked for plainly, the attribute comes back under a ranged name with the first slice only.
        var first = Assert.Single(Search(connection, group, "(objectClass=*)", SearchScope.Base, "member"));
        var name = Assert.Single(first.Attributes.AttributeNames.Cast<string>());
        Assert.Equal("member;range=0-9", name, ignoreCase: true);

        var members = new List<string>(first.Attributes[name].GetValues(typeof(string)).Cast<string>());
        var requests = 1;
        while (!name.EndsWith("-*"))
        {
            var entry = Assert.Single(Search(connection, group, "(objectClass=*)", SearchScope.Base, $"member;range={members.Count}-*"));
            name = Assert.Single(entry.Attributes.AttributeNames.Cast<string>());
            members.AddRange(entry.Attributes[name].GetValues(typeof(string)).Cast<string>());
            requests++;
        }
        Assert.Equal(3, requests);
        Assert.Equal("member;range=20-*", name, ignoreCase: true);
        Assert.Equal(25, members.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Must_change_password_ends_after_a_reset()
    {
        Assert.Throws<LdapException>(() => Connect("newbie@corp.example.com", "newbie-secret"));

        using var admin = Connect();
        var reset = new DirectoryAttributeModification { Name = "unicodePwd", Operation = DirectoryAttributeOperation.Replace };
        reset.Add(Encoding.Unicode.GetBytes("\"Fr3sh-Passw0rd\""));
        admin.SendRequest(new ModifyRequest($"CN=newbie,CN=Users,{BaseDn}", reset));

        using var newbie = Connect("newbie@corp.example.com", "Fr3sh-Passw0rd");
    }

    [Fact]
    public void Account_state_helpers_need_the_matching_flavour()
    {
        var e = Assert.Throws<InvalidOperationException>(() => LdapTestServer.Create().WithUser("x", "pw", u => u.MustChangePassword()).Start());
        Assert.Contains("AsActiveDirectory", e.Message);

        using var generic = LdapTestServer.Create().WithUser("locked", "pw", u => u.LockedOut()).WithUser("ok", "pw").Start();
        Assert.Throws<LdapException>(() => Connect("uid=locked,ou=users,dc=example,dc=com", "pw", generic));
        using var ok = Connect("uid=ok,ou=users,dc=example,dc=com", "pw", generic);
    }

    [Fact]
    public void Account_flags_combine()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .WithUser("bob", "pw", u => u.Disabled().PasswordExpired())
            .Start();
        Assert.Equal((512 | 0x2 | 0x800000).ToString(), server.Directory.Find($"CN=bob,CN=Users,{BaseDn}")!.GetString("userAccountControl"));
    }

    [Fact]
    public void Name_follows_a_rename()
    {
        using var connection = Connect();
        connection.SendRequest(new ModifyDNRequest(AliceDn, $"CN=Users,{BaseDn}", "CN=Alice Liddell"));
        Assert.Single(Search(connection, BaseDn, "(name=Alice Liddell)", SearchScope.Subtree, "cn"));
        Assert.Empty(Search(connection, BaseDn, "(name=alice)", SearchScope.Subtree, "cn"));
    }

    [Fact]
    public void ObjectCategory_follows_a_renamed_base_dn()
    {
        _server.Directory.Move(BaseDn, "DC=lab,DC=example,DC=com");
        var alice = _server.Directory.Find("CN=alice,CN=Users,DC=lab,DC=example,DC=com")!;
        Assert.Equal("CN=Person,CN=Schema,CN=Configuration,DC=lab,DC=example,DC=com", alice.GetString("objectCategory"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Domain_users_can_be_seeded_by_name(bool groupFirst)
    {
        var builder = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn);
        builder = groupFirst
            ? builder.WithGroup("Domain Users").WithUser("alice", "pw")
            : builder.WithUser("alice", "pw").WithGroup("Domain Users", "admin");
        using var server = builder.WithUser("admin", "admin-secret").Start();
        using var connection = Connect(server: server);

        // one group of that name, and it is the primary group whichever came first
        var group = Assert.Single(Search(connection, BaseDn, "(sAMAccountName=Domain Users)", SearchScope.Subtree, "primaryGroupToken"));
        Assert.Equal("513", group.Attributes["primaryGroupToken"][0]);
    }

    [Fact]
    public void Entries_from_ldif_get_the_attributes_ad_generates()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .WithUser("admin", "admin-secret")
            .WithLdif($"""
                dn: CN=Carol,OU=Staff,{BaseDn}
                objectClass: top
                objectClass: person
                objectClass: user
                cn: Carol
                sAMAccountName: carol
                userPassword: carol-secret
                """)
            .Start();
        using var connection = Connect(server: server);

        var carol = Assert.Single(Search(connection, BaseDn, "(&(objectCategory=person)(sAMAccountName=carol))", SearchScope.Subtree,
            "objectSid", "primaryGroupID", "tokenGroups", "name"));
        Assert.Equal("513", carol.Attributes["primaryGroupID"][0]);
        Assert.Equal("Carol", carol.Attributes["name"][0]);
        var domainUsers = server.Directory.Find($"CN=Domain Users,CN=Users,{BaseDn}")!.GetValues("objectSid")[0];
        Assert.Equal(domainUsers, (byte[])Assert.Single(carol.Attributes["tokenGroups"].GetValues(typeof(byte[]))));
        Assert.Single(Search(connection, BaseDn, "(objectCategory=organizationalUnit)", SearchScope.Subtree, "ou"));
        using var asCarol = Connect("CORP\\carol", "carol-secret", server);
    }

    [Fact]
    public void Disabled_and_locked_markers_are_honoured_in_either_flavour()
    {
        using var generic = LdapTestServer.Create()
            .WithUser("off", "pw", u => u.Attribute("userAccountControl", "514"))
            .Start();
        Assert.Throws<LdapException>(() => Connect("uid=off,ou=users,dc=example,dc=com", "pw", generic));

        _server.Directory.Update(AliceDn, e => e.Set("pwdAccountLockedTime", "000001010000Z"));
        Assert.Throws<LdapException>(() => Connect("alice@corp.example.com", "alice-secret"));
    }

    [Fact]
    public void Reset_with_must_change_keeps_the_flag_in_either_order()
    {
        DirectoryAttributeModification Password()
        {
            var change = new DirectoryAttributeModification { Name = "unicodePwd", Operation = DirectoryAttributeOperation.Replace };
            change.Add(Encoding.Unicode.GetBytes("\"Fr3sh-Passw0rd\""));
            return change;
        }
        DirectoryAttributeModification MustChange()
        {
            var change = new DirectoryAttributeModification { Name = "pwdLastSet", Operation = DirectoryAttributeOperation.Replace };
            change.Add("0");
            return change;
        }

        using var admin = Connect();
        admin.SendRequest(new ModifyRequest(AliceDn, MustChange(), Password()));
        Assert.Equal("0", _server.Directory.Find(AliceDn)!.GetString("pwdLastSet"));
        admin.SendRequest(new ModifyRequest(AliceDn, Password()));
        Assert.NotEqual("0", _server.Directory.Find(AliceDn)!.GetString("pwdLastSet"));
        admin.SendRequest(new ModifyRequest(AliceDn, Password(), MustChange()));
        Assert.Equal("0", _server.Directory.Find(AliceDn)!.GetString("pwdLastSet"));
    }

    [Fact]
    public void Range_with_a_huge_limit_does_not_overflow()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .Configure(d => { for (var i = 0; i < 10; i++) d.AddUser($"user{i}", "pw", u => u.MemberOf("Everyone")); })
            .WithMaxValuesPerAttribute(int.MaxValue)
            .Start();
        using var connection = Connect("user0@corp.example.com", "pw", server);
        var entry = Assert.Single(Search(connection, $"CN=Everyone,CN=Users,{BaseDn}", "(objectClass=*)", SearchScope.Base, "member;range=2-*"));
        var name = Assert.Single(entry.Attributes.AttributeNames.Cast<string>());
        Assert.Equal("member;range=2-*", name, ignoreCase: true);
        Assert.Equal(8, entry.Attributes[name].Count);
    }

    [Fact]
    public void Anonymous_client_cannot_probe_for_sids()
    {
        using var anonymous = new LdapConnection(new LdapDirectoryIdentifier(_server.Host, _server.Port)) { AuthType = AuthType.Anonymous };
        anonymous.SessionOptions.ProtocolVersion = 3;
        anonymous.Bind();
        foreach (var sid in new[] { ActiveDirectory.SidToString(SidOf(AliceDn)), "S-1-5-21-1-2-3-9999" })
        {
            var e = Assert.Throws<DirectoryOperationException>(() => Search(anonymous, $"<SID={sid}>", "(objectClass=*)", SearchScope.Base));
            Assert.Equal(ResultCode.OperationsError, e.Response.ResultCode);
        }
    }

    [Fact]
    public void Operational_attributes_are_computed_only_when_asked_for()
    {
        var computed = 0;
        _server.Directory.AddVirtualAttribute(new VirtualAttribute("expensive", isOperational: true, (_, _) =>
        {
            Interlocked.Increment(ref computed);
            return ["x"];
        }));
        using var connection = Connect();
        Search(connection, BaseDn, "(objectClass=user)", SearchScope.Subtree, "cn");
        Search(connection, BaseDn, "(objectClass=user)", SearchScope.Subtree);
        Assert.Equal(0, computed);
        Assert.Equal("x", Assert.Single(Search(connection, AliceDn, "(objectClass=*)", SearchScope.Base, "expensive")).Attributes["expensive"][0]);
        Assert.Equal(1, computed);
    }

    [Theory]
    [InlineData("CN=Users", true)]   // an AD export: accounts first, then the group, where the generated one sits
    [InlineData("CN=Users", false)]
    [InlineData("OU=Groups", true)]  // ...or in another container
    [InlineData("OU=Groups", false)]
    public void Test_data_may_bring_its_own_domain_users(string container, bool userFirst)
    {
        var user = $"""
            dn: CN=Administrator,CN=Users,{BaseDn}
            objectClass: user
            cn: Administrator
            sAMAccountName: Administrator
            userPassword: admin-secret
            userPrincipalName: admin@corp.example.com

            """;
        var group = $"""
            dn: CN=Domain Users,{container},{BaseDn}
            objectClass: group
            cn: Domain Users
            description: from the test data

            """;
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .WithLdif(userFirst ? user + "\n" + group : group + "\n" + user)
            .Start();
        using var connection = Connect(server: server);

        var found = Assert.Single(Search(connection, BaseDn, "(&(objectClass=group)(cn=Domain Users))", SearchScope.Subtree, "primaryGroupToken", "description"));
        Assert.Equal($"CN=Domain Users,{container},{BaseDn}", found.DistinguishedName);
        Assert.Equal("513", found.Attributes["primaryGroupToken"][0]);
        Assert.Equal("from the test data", found.Attributes["description"][0]);
    }

    [Fact]
    public void A_new_password_ends_password_expired_and_must_change()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .WithUser("admin", "admin-secret")
            .WithUser("stale", "old", u => u.PasswordExpired())
            .WithUser("newbie", "old", u => u.MustChangePassword())
            .Start();
        Assert.Throws<LdapException>(() => Connect("stale@corp.example.com", "old", server));
        using var admin = Connect(server: server);

        var reset = new DirectoryAttributeModification { Name = "unicodePwd", Operation = DirectoryAttributeOperation.Replace };
        reset.Add(Encoding.Unicode.GetBytes("\"Fr3sh-Passw0rd\""));
        admin.SendRequest(new ModifyRequest($"CN=stale,CN=Users,{BaseDn}", reset));
        using var stale = Connect("stale@corp.example.com", "Fr3sh-Passw0rd", server);

        // the same through userPassword, which this server also accepts in the AD flavour
        admin.SendRequest(new ModifyRequest($"CN=newbie,CN=Users,{BaseDn}", DirectoryAttributeOperation.Replace, "userPassword", "Fr3sh"));
        using var newbie = Connect("newbie@corp.example.com", "Fr3sh", server);
    }

    [Fact]
    public void Contacts_are_in_the_person_category()
    {
        _server.Directory.Add($"CN=Vendor,CN=Users,{BaseDn}", e => e.Set("objectClass", "top", "person", "organizationalPerson", "contact").Set("cn", "Vendor"));
        using var connection = Connect();
        Assert.Single(Search(connection, BaseDn, "(&(objectCategory=person)(objectClass=contact))", SearchScope.Subtree, "cn"));
        Assert.Equal(4, Search(connection, BaseDn, "(objectCategory=contact)", SearchScope.Subtree, "cn").Count); // 3 users and the contact: one category
    }

    [Fact]
    public void Primary_group_is_looked_up_in_the_accounts_own_domain()
    {
        // a group from another domain that happens to share its RID with a group generated here
        var localRid = ActiveDirectory.Rid(SidOf($"CN=Developers,CN=Users,{BaseDn}"))!.Value;
        var foreignGroup = ActiveDirectory.ParseSid($"S-1-5-21-7-8-9-{localRid}")!;
        _server.Directory.Add($"CN=Their Group,CN=Users,{BaseDn}", e => e.Set("objectClass", "top", "group").SetBinary("objectSid", foreignGroup));
        _server.Directory.Add($"CN=Guest,CN=Users,{BaseDn}", e => e
            .Set("objectClass", "top", "person", "user")
            .Set("primaryGroupID", localRid.ToString())
            .SetBinary("objectSid", ActiveDirectory.ParseSid("S-1-5-21-7-8-9-5000")!));

        using var connection = Connect();
        var guest = Assert.Single(Search(connection, $"CN=Guest,CN=Users,{BaseDn}", "(objectClass=*)", SearchScope.Base, "tokenGroups"));
        Assert.Equal(foreignGroup, (byte[])Assert.Single(guest.Attributes["tokenGroups"].GetValues(typeof(byte[]))));
    }

    [Fact]
    public void A_range_the_server_cannot_read_is_not_echoed()
    {
        using var connection = Connect();
        var group = Assert.Single(Search(connection, $"CN=Developers,CN=Users,{BaseDn}", "(objectClass=*)", SearchScope.Base, "member;range=5-2"));
        Assert.Equal("member", Assert.Single(group.Attributes.AttributeNames.Cast<string>()), ignoreCase: true);
    }

    [Fact]
    public void Generated_timestamps_do_not_depend_on_the_culture()
    {
        var before = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("th-TH"); // Buddhist calendar: year 2569
            using var server = LdapTestServer.Create().WithUser("locked", "pw", u => u.LockedOut()).Start();
            var value = server.Directory.Find("uid=locked,ou=users,dc=example,dc=com")!.GetString("pwdAccountLockedTime")!;
            Assert.StartsWith(DateTime.UtcNow.Year.ToString(System.Globalization.CultureInfo.InvariantCulture), value);
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = before;
        }
    }

    [Fact]
    public void Sid_stored_as_text_is_still_found_by_that_text()
    {
        _server.Directory.Add($"CN=Legacy,CN=Users,{BaseDn}", e => e.Set("objectClass", "top", "user").Set("objectSid", "S-1-5-21-1-2-3-1104"));
        using var connection = Connect();
        Assert.Single(Search(connection, BaseDn, "(objectSid=S-1-5-21-1-2-3-1104)", SearchScope.Subtree, "cn"));
        Assert.Single(Search(connection, "<SID=S-1-5-21-1-2-3-1104>", "(objectClass=*)", SearchScope.Base, "cn"));
    }

    [Fact]
    public void PwdLastSet_minus_one_means_now()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .WithUser("admin", "admin-secret")
            .WithUser("stale", "old", u => u.PasswordExpired())
            .Start();
        using var admin = Connect(server: server);
        var reset = new DirectoryAttributeModification { Name = "unicodePwd", Operation = DirectoryAttributeOperation.Replace };
        reset.Add(Encoding.Unicode.GetBytes("\"Fr3sh-Passw0rd\""));
        var now = new DirectoryAttributeModification { Name = "pwdLastSet", Operation = DirectoryAttributeOperation.Replace };
        now.Add("-1");
        admin.SendRequest(new ModifyRequest($"CN=stale,CN=Users,{BaseDn}", reset, now));

        using var stale = Connect("stale@corp.example.com", "Fr3sh-Passw0rd", server);
        var pwdLastSet = long.Parse(server.Directory.Find($"CN=stale,CN=Users,{BaseDn}")!.GetString("pwdLastSet")!);
        Assert.InRange(DateTime.FromFileTimeUtc(pwdLastSet), DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddMinutes(5));
    }

    [Fact]
    public void Removing_the_password_is_not_setting_one()
    {
        var newbie = $"CN=newbie,CN=Users,{BaseDn}";
        var remove = new Protocol.Modification(Protocol.ModificationType.Replace, new Protocol.PartialAttribute("userPassword", []));
        Assert.Equal(Protocol.ResultCode.Success, _server.Directory.ApplyModify(newbie, [remove]).Code);
        Assert.Equal("0", _server.Directory.Find(newbie)!.GetString("pwdLastSet"));
    }

    [Fact]
    public void An_old_lockoutTime_does_not_lock_the_account()
    {
        // as in an export from a real domain: the lockout of 2016 ran out long ago, the timestamp stayed
        _server.Directory.Update(AliceDn, e => e.Set("lockoutTime", "131000000000000000"));
        using (Connect("alice@corp.example.com", "alice-secret"))
        {
        }

        // the same for a lockout a test back-dates to "just over half an hour ago", however long the server has been up
        var expired = DateTime.UtcNow.AddMinutes(-31).ToFileTimeUtc().ToString(System.Globalization.CultureInfo.InvariantCulture);
        _server.Directory.Update(AliceDn, e => e.Set("lockoutTime", expired));
        using (Connect("alice@corp.example.com", "alice-secret"))
        {
        }

        _server.Directory.Layout.LockoutDuration = TimeSpan.Zero; // "until an administrator unlocks"
        Assert.Throws<LdapException>(() => Connect("alice@corp.example.com", "alice-secret"));
    }

    [Fact]
    public void A_lockout_that_begins_during_the_test_does_not_run_out()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .WithUser("bob", "hunter2", u => u.LockedOut())
            .Start();
        server.Directory.Layout.LockoutDuration = TimeSpan.FromTicks(1); // long over by the time of the bind
        Assert.Throws<LdapException>(() => Connect("bob@corp.example.com", "hunter2", server));
    }

    [Fact]
    public void Generated_domain_users_survives_a_failed_add_and_a_rename()
    {
        var directory = _server.Directory;
        var generated = $"CN=Domain Users,CN=Users,{BaseDn}";
        Assert.Throws<InvalidOperationException>(() => directory.Add($"CN=Developers,CN=Users,{BaseDn}",
            e => e.Set("objectClass", "top", "group").Set("sAMAccountName", "Domain Users")));
        Assert.True(directory.Exists(generated));

        // renamed, it is still the holder of RID 513, and no second one appears with the next account
        directory.Move(generated, $"CN=Everyone,CN=Users,{BaseDn}");
        directory.AddUser("zed", "pw");
        using var connection = Connect();
        var holder = Assert.Single(Search(connection, BaseDn, "(primaryGroupToken=513)", SearchScope.Subtree, "cn"));
        Assert.Equal($"CN=Everyone,CN=Users,{BaseDn}", holder.DistinguishedName);
        Assert.False(directory.Exists(generated));
    }

    [Fact]
    public void Generated_domain_users_leaves_no_trace_when_the_test_data_brings_its_own()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .WithLdif($"""
                dn: CN=Administrator,OU=People,{BaseDn}
                objectClass: user
                cn: Administrator
                userPassword: admin-secret

                dn: CN=Domain Users,OU=Groups,{BaseDn}
                objectClass: group
                cn: Domain Users
                """)
            .Start();
        Assert.False(server.Directory.Exists($"CN=Users,{BaseDn}")); // the container made for the generated group is gone too
        Assert.Equal(5, server.Directory.Count); // base, two OUs, the user, the group
    }

    [Fact]
    public void Domain_users_is_not_generated_into_a_missing_container()
    {
        var directory = new InMemoryDirectory(new DirectoryLayout { Flavor = DirectoryFlavor.ActiveDirectory, BaseDn = BaseDn }) { AutoCreateParents = false };
        directory.Add(BaseDn, e => e.Set("objectClass", "top", "domainDNS"));
        directory.Add($"OU=People,{BaseDn}", e => e.Set("objectClass", "top", "organizationalUnit"));
        directory.Add($"CN=Zed,OU=People,{BaseDn}", e => e.Set("objectClass", "top", "user"));
        Assert.Equal([BaseDn], directory.NamingContexts.Select(dn => dn.ToString()));
    }

    [Fact]
    public void Several_ranges_of_one_attribute_in_one_search()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .Configure(d => { for (var i = 0; i < 25; i++) d.AddUser($"user{i:00}", "pw", u => u.MemberOf("Everyone")); })
            .Start();
        using var connection = Connect("user00@corp.example.com", "pw", server);
        var entry = Assert.Single(Search(connection, $"CN=Everyone,CN=Users,{BaseDn}", "(objectClass=*)", SearchScope.Base, "member;range=0-4", "member;range=5-9"));
        Assert.Equal(["member;range=0-4", "member;range=5-9"], entry.Attributes.AttributeNames.Cast<string>().Select(n => n.ToLowerInvariant()).Order());
    }

    [Fact]
    public void Test_data_may_list_a_container_after_what_is_in_it()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .WithLdif($"""
                dn: OU=Staff,{BaseDn}
                objectClass: organizationalUnit
                ou: Staff

                dn: CN=Carol,OU=Staff,{BaseDn}
                objectClass: user
                cn: Carol

                dn: CN=Users,{BaseDn}
                objectClass: container
                cn: Users
                description: the one from the test data

                dn: CN=Domain Admins,CN=Users,{BaseDn}
                objectClass: group
                cn: Domain Admins
                """)
            .Start();
        // Carol made "Domain Users" and its container appear; the explicit container then took the container's place
        Assert.Equal("the one from the test data", server.Directory.Find($"CN=Users,{BaseDn}")!.GetString("description"));
        Assert.True(server.Directory.Exists($"CN=Domain Users,CN=Users,{BaseDn}"));
        Assert.Throws<InvalidOperationException>(() => server.Directory.Add($"CN=Users,{BaseDn}", e => e.Set("objectClass", "container")));
    }

    [Fact]
    public void An_attribute_asked_for_twice_comes_back_once()
    {
        using var connection = Connect();
        var alice = Assert.Single(Search(connection, AliceDn, "(objectClass=*)", SearchScope.Base, "cn", "cn;x-a", "CN"));
        Assert.Equal("cn", Assert.Single(alice.Attributes.AttributeNames.Cast<string>()), ignoreCase: true);
    }

    [Fact]
    public void A_second_tree_next_to_the_base_dn_is_left_alone()
    {
        var directory = new InMemoryDirectory(new DirectoryLayout { Flavor = DirectoryFlavor.ActiveDirectory }); // base DN dc=example,dc=com
        directory.AddLdif("""
            dn: DC=corp,DC=local
            objectClass: domainDNS

            dn: OU=Staff,DC=corp,DC=local
            objectClass: organizationalUnit

            dn: CN=Carol,OU=Staff,DC=corp,DC=local
            objectClass: user
            """);
        Assert.Equal(["DC=corp,DC=local"], directory.NamingContexts.Select(dn => dn.ToString()));
        Assert.Equal("CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=local", directory.Find("CN=Carol,OU=Staff,DC=corp,DC=local")!.GetString("objectCategory"));
    }

    [Fact]
    public void Many_accounts_are_added_quickly_even_when_domain_users_cannot_be_generated()
    {
        var directory = new InMemoryDirectory(new DirectoryLayout { Flavor = DirectoryFlavor.ActiveDirectory, BaseDn = BaseDn }) { AutoCreateParents = false };
        directory.Add(BaseDn, e => e.Set("objectClass", "top", "domainDNS"));
        directory.Add($"OU=People,{BaseDn}", e => e.Set("objectClass", "top", "organizationalUnit"));
        var watch = System.Diagnostics.Stopwatch.StartNew();
        // A scan of the directory per account would take minutes here; without it this is well under a second,
        // which leaves the budget wide enough for a busy build machine.
        for (var i = 0; i < 30000; i++) directory.Add($"CN=user{i},OU=People,{BaseDn}", e => e.Set("objectClass", "top", "user"));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(30), $"took {watch.Elapsed}");
    }

    private static string Base64Sid(string sid) => Convert.ToBase64String(ActiveDirectory.ParseSid(sid)!);

    [Fact]
    public void Domain_users_of_a_second_tree_does_not_replace_this_domains()
    {
        var generated = $"CN=Domain Users,CN=Users,{BaseDn}";
        _server.Directory.AddLdif("""
            dn: DC=other,DC=local
            objectClass: domainDNS

            dn: CN=Users,DC=other,DC=local
            objectClass: container

            dn: CN=Domain Users,CN=Users,DC=other,DC=local
            objectClass: group
            """);
        Assert.Equal(513u, ActiveDirectory.Rid(SidOf(generated)));
        Assert.NotEqual(513u, ActiveDirectory.Rid(SidOf("CN=Domain Users,CN=Users,DC=other,DC=local")));
    }

    [Fact]
    public void Primary_group_is_found_across_domain_sids()
    {
        // an account from a real domain, whose export did not include the group: 513 means the generated one
        using var imported = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .WithUser("admin", "admin-secret")
            .WithLdif($"""
                dn: CN=Carol,CN=Users,{BaseDn}
                objectClass: user
                objectSid:: {Base64Sid("S-1-5-21-7-8-9-1601")}
                primaryGroupID: 513
                """)
            .Start();
        using (var connection = Connect(server: imported))
        {
            var carol = Assert.Single(Search(connection, $"CN=Carol,CN=Users,{BaseDn}", "(objectClass=*)", SearchScope.Base, "tokenGroups"));
            var domainUsers = imported.Directory.Find($"CN=Domain Users,CN=Users,{BaseDn}")!.GetValues("objectSid")[0];
            Assert.Equal(domainUsers, (byte[])Assert.Single(carol.Attributes["tokenGroups"].GetValues(typeof(byte[]))));
        }

        // the group from a real domain, under its local name, next to builder users
        using var localized = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .WithLdif($"""
                dn: CN=Domänen-Benutzer,CN=Users,{BaseDn}
                objectClass: group
                objectSid:: {Base64Sid("S-1-5-21-7-8-9-513")}

                dn: CN=Dieter,CN=Users,{BaseDn}
                objectClass: user
                objectSid:: {Base64Sid("S-1-5-21-7-8-9-1602")}
                primaryGroupID: 513
                """)
            .WithUser("admin", "admin-secret")
            .Start();
        Assert.False(localized.Directory.Exists($"CN=Domain Users,CN=Users,{BaseDn}")); // no second primary group was made up
        using (var connection = Connect(server: localized))
        {
            var admin = Assert.Single(Search(connection, $"CN=admin,CN=Users,{BaseDn}", "(objectClass=*)", SearchScope.Base, "tokenGroups"));
            Assert.Equal(ActiveDirectory.ParseSid("S-1-5-21-7-8-9-513"), (byte[])Assert.Single(admin.Attributes["tokenGroups"].GetValues(typeof(byte[]))));
        }
    }

    [Fact]
    public void A_generated_group_the_test_changed_is_not_silently_replaced()
    {
        var directory = new InMemoryDirectory(new DirectoryLayout { Flavor = DirectoryFlavor.ActiveDirectory, BaseDn = BaseDn });
        directory.AddUser("alice", "pw", u => u.MemberOf("Domain Users")); // adding members is fine...
        directory.AddGroup("Domain Users", "alice");
        Assert.Equal([$"CN=alice,CN=Users,{BaseDn}"], directory.Find($"CN=Domain Users,CN=Users,{BaseDn}")!.GetStrings("member"));

        var other = new InMemoryDirectory(new DirectoryLayout { Flavor = DirectoryFlavor.ActiveDirectory, BaseDn = BaseDn });
        other.AddUser("alice", "pw");
        other.Update($"CN=Domain Users,CN=Users,{BaseDn}", e => e.Set("description", "mine")); // ...but this makes it the test's own
        Assert.Throws<InvalidOperationException>(() => other.AddGroup("Domain Users", "alice"));
        Assert.Equal("mine", other.Find($"CN=Domain Users,CN=Users,{BaseDn}")!.GetString("description"));
    }

    [Fact]
    public void Test_data_may_list_the_base_entry_itself()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(BaseDn)
            .WithUser("admin", "admin-secret")
            .WithLdif($"""
                dn: {BaseDn}
                objectClass: domainDNS
                description: from the export
                """)
            .Start();
        Assert.Equal("from the export", server.Directory.Find(BaseDn)!.GetString("description"));
        Assert.True(server.Directory.Exists($"CN=admin,CN=Users,{BaseDn}"));
    }

    [Fact]
    public void Filter_short_forms_are_not_values()
    {
        // (objectCategory=person) is a way to write a filter; the attribute does not hold "person"
        using var connection = Connect();
        var compare = (CompareResponse)connection.SendRequest(new CompareRequest(AliceDn, "objectCategory", "person"));
        Assert.Equal(ResultCode.CompareFalse, compare.ResultCode);
        var e = Assert.Throws<DirectoryOperationException>(() =>
            connection.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Delete, "objectCategory", "person")));
        Assert.Equal(ResultCode.NoSuchAttribute, e.Response.ResultCode);
    }
}
