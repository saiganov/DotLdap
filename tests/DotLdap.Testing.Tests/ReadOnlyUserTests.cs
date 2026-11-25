using System.DirectoryServices.Protocols;
using System.Formats.Asn1;
using System.Net;
using System.Text;

namespace DotLdap.Testing.Tests;

/// <summary>Users marked read-only: every write ends with insufficientAccessRights, reading goes on as before.</summary>
public class ReadOnlyUserTests
{
    private const string Users = "ou=users,dc=example,dc=com";
    private const string AliceDn = "uid=alice," + Users;
    private const string ReaderDn = "uid=reader," + Users;
    private const string AdminDn = "uid=admin," + Users;
    private const string PasswordModifyOid = "1.3.6.1.4.1.4203.1.11.1";
    private const ResultCode Refused = ResultCode.InsufficientAccessRights;

    private static LdapTestServerBuilder Generic() => LdapTestServer.Create()
        .WithUser("admin", "admin-secret")
        .WithUser("alice", "alice-secret", u => u.Email("alice@example.com"))
        .WithUser("reader", "reader-secret", u => u.ReadOnly());

    private static LdapTestServerBuilder Ad() => LdapTestServer.Create()
        .AsActiveDirectory()
        .WithBaseDn("DC=corp,DC=example,DC=com")
        .WithUser("admin", "admin-secret")
        .WithUser("alice", "alice-secret")
        .WithUser("reader", "reader-secret", u => u.ReadOnly());

    private static LdapConnection Connect(LdapTestServer server, string? user, string? password)
    {
        var connection = new LdapConnection(new LdapDirectoryIdentifier(server.Host, server.Port))
        {
            AuthType = user is null ? AuthType.Anonymous : AuthType.Basic,
            Credential = user is null ? null : new NetworkCredential(user, password),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.Bind();
        return connection;
    }

    private static ResultCode Fails(LdapConnection connection, DirectoryRequest request) =>
        Assert.Throws<DirectoryOperationException>(() => connection.SendRequest(request)).Response.ResultCode;

    private static ModifyRequest SetMail(string dn, string mail) =>
        new(dn, DirectoryAttributeOperation.Replace, "mail", mail);

    private static AddRequest NewUnit(string dn) => new(dn, new DirectoryAttribute("objectClass", "top", "organizationalUnit"));

    private static DirectoryAttributeModification UnicodePwd(DirectoryAttributeOperation operation, string password)
    {
        var modification = new DirectoryAttributeModification { Name = "unicodePwd", Operation = operation };
        modification.Add(Encoding.Unicode.GetBytes('"' + password + '"'));
        return modification;
    }

    private static ExtendedRequest PasswordModify(string? user, string? oldPassword, string newPassword)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            if (user is not null) writer.WriteOctetString(Encoding.UTF8.GetBytes(user), new Asn1Tag(TagClass.ContextSpecific, 0));
            if (oldPassword is not null) writer.WriteOctetString(Encoding.UTF8.GetBytes(oldPassword), new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteOctetString(Encoding.UTF8.GetBytes(newPassword), new Asn1Tag(TagClass.ContextSpecific, 2));
        }
        return new ExtendedRequest(PasswordModifyOid, writer.Encode());
    }

    [Fact]
    public void Every_write_of_a_read_only_user_is_refused_and_changes_nothing()
    {
        using var server = Generic().Start();
        using var reader = Connect(server, ReaderDn, "reader-secret");
        var before = server.Directory.Count;

        Assert.Equal(Refused, Fails(reader, NewUnit("ou=new,dc=example,dc=com")));
        Assert.Equal(Refused, Fails(reader, SetMail(AliceDn, "changed@example.com")));
        Assert.Equal(Refused, Fails(reader, SetMail(ReaderDn, "own@example.com"))); // not their own entry either
        Assert.Equal(Refused, Fails(reader, new DeleteRequest(AliceDn)));
        Assert.Equal(Refused, Fails(reader, new ModifyDNRequest(AliceDn, Users, "uid=alicia")));

        Assert.Equal(before, server.Directory.Count);
        Assert.False(server.Directory.Exists("ou=new,dc=example,dc=com"));
        Assert.Equal("alice@example.com", server.Directory.Find(AliceDn)!.GetString("mail"));
        Assert.False(server.Directory.Find(ReaderDn)!.Has("mail"));

        // The answer says why, and comes before the server looks at what the request names.
        Assert.Equal(Refused, Fails(reader, new DeleteRequest("uid=ghost," + Users)));
        Assert.Equal(Refused, Fails(reader, new DeleteRequest("not a dn")));
        var refusals = server.Requests.Where(r => r.Result?.Code == Protocol.ResultCode.InsufficientAccessRights).ToList();
        Assert.Equal(7, refusals.Count);
        Assert.All(refusals, r => Assert.Equal($"Insufficient access: {ReaderDn} is a read-only user.", r.Result!.Message));
    }

    [Fact]
    public void A_read_only_user_reads_like_everyone_else()
    {
        using var server = Generic().Start();
        using var reader = Connect(server, ReaderDn, "reader-secret");

        var found = (SearchResponse)reader.SendRequest(new SearchRequest(Users, "(uid=alice)", SearchScope.Subtree, "mail"));
        Assert.Equal("alice@example.com", found.Entries[0].Attributes["mail"][0]);
        var compared = (CompareResponse)reader.SendRequest(new CompareRequest(AliceDn, "mail", "alice@example.com"));
        Assert.Equal(ResultCode.CompareTrue, compared.ResultCode);
        var who = (ExtendedResponse)reader.SendRequest(new ExtendedRequest("1.3.6.1.4.1.4203.1.11.3"));
        Assert.Equal("dn:" + ReaderDn, Encoding.UTF8.GetString(who.ResponseValue));
    }

    [Fact]
    public void Other_users_and_anonymous_clients_are_treated_as_before()
    {
        using var server = Generic().Start();
        using (var alice = Connect(server, AliceDn, "alice-secret"))
            alice.SendRequest(SetMail(AdminDn, "admin@example.com")); // no other access control: any other user writes anything
        Assert.Equal("admin@example.com", server.Directory.Find(AdminDn)!.GetString("mail"));

        using var anonymous = Connect(server, null, null);
        Assert.Equal(ResultCode.StrongAuthRequired, Fails(anonymous, SetMail(AliceDn, "x@example.com")));
    }

    [Fact]
    public void The_connection_is_judged_by_who_is_bound_on_it_now()
    {
        using var server = Generic().Start();
        using var connection = Connect(server, ReaderDn, "reader-secret");
        Assert.Equal(Refused, Fails(connection, SetMail(AliceDn, "one@example.com")));

        connection.Bind(new NetworkCredential(AdminDn, "admin-secret"));
        connection.SendRequest(SetMail(AliceDn, "two@example.com"));

        connection.Bind(new NetworkCredential(ReaderDn, "reader-secret"));
        Assert.Equal(Refused, Fails(connection, SetMail(AliceDn, "three@example.com")));
        Assert.Equal("two@example.com", server.Directory.Find(AliceDn)!.GetString("mail"));
    }

    [Fact]
    public void The_mark_can_be_set_and_lifted_while_a_connection_is_open()
    {
        using var server = Generic().Start();
        using var alice = Connect(server, AliceDn, "alice-secret");
        alice.SendRequest(SetMail(AliceDn, "one@example.com"));

        server.Directory.SetReadOnly(AliceDn);
        Assert.True(server.Directory.IsReadOnly("UID=Alice, " + Users)); // a DN, however it is spelled
        Assert.Equal(Refused, Fails(alice, SetMail(AliceDn, "two@example.com")));

        server.Directory.SetReadOnly(AliceDn, readOnly: false);
        Assert.False(server.Directory.IsReadOnly(AliceDn));
        alice.SendRequest(SetMail(AliceDn, "three@example.com"));
        Assert.Equal("three@example.com", server.Directory.Find(AliceDn)!.GetString("mail"));
    }

    [Fact]
    public void The_mark_follows_a_renamed_user_and_goes_away_with_a_deleted_one()
    {
        using var server = Generic()
            .WithEntry("ou=archive,dc=example,dc=com", e => e.Set("objectClass", "top", "organizationalUnit"))
            .Start();
        using var admin = Connect(server, AdminDn, "admin-secret");

        admin.SendRequest(new ModifyDNRequest(ReaderDn, Users, "uid=viewer"));
        const string viewerDn = "uid=viewer," + Users;
        Assert.True(server.Directory.IsReadOnly(viewerDn));
        Assert.False(server.Directory.IsReadOnly(ReaderDn));
        using (var viewer = Connect(server, viewerDn, "reader-secret"))
            Assert.Equal(Refused, Fails(viewer, SetMail(AliceDn, "x@example.com")));

        // moved together with the container above it
        admin.SendRequest(new ModifyDNRequest(Users, "ou=archive,dc=example,dc=com", "ou=users"));
        const string movedDn = "uid=viewer,ou=users,ou=archive,dc=example,dc=com";
        Assert.True(server.Directory.IsReadOnly(movedDn));
        Assert.False(server.Directory.IsReadOnly(viewerDn));

        // a new entry under the name of a deleted read-only user starts without the mark
        admin.SendRequest(new DeleteRequest(movedDn));
        Assert.False(server.Directory.IsReadOnly(movedDn));
        admin.SendRequest(new AddRequest(movedDn,
            new DirectoryAttribute("objectClass", "top", "person", "inetOrgPerson"),
            new DirectoryAttribute("cn", "viewer"), new DirectoryAttribute("sn", "viewer"),
            new DirectoryAttribute("userPassword", "new-secret")));
        using var recreated = Connect(server, movedDn, "new-secret");
        recreated.SendRequest(SetMail(movedDn, "viewer@example.com"));

        // the same through the seeding API
        server.Directory.SetReadOnly(movedDn);
        server.Directory.Move(movedDn, "uid=viewer,dc=example,dc=com");
        Assert.True(server.Directory.IsReadOnly("uid=viewer,dc=example,dc=com"));
        Assert.True(server.Directory.Remove("uid=viewer,dc=example,dc=com"));
        Assert.False(server.Directory.IsReadOnly("uid=viewer,dc=example,dc=com"));
    }

    [Fact]
    public void An_open_connection_stays_read_only_when_its_user_is_renamed_or_deleted()
    {
        using var server = Generic().WithUser("viewer", "viewer-secret", u => u.ReadOnly()).Start();
        using var admin = Connect(server, AdminDn, "admin-secret");
        using var reader = Connect(server, ReaderDn, "reader-secret"); // no write yet: the server must remember from the bind
        using var viewer = Connect(server, "uid=viewer," + Users, "viewer-secret");
        using var alice = Connect(server, AliceDn, "alice-secret");

        admin.SendRequest(new ModifyDNRequest(ReaderDn, Users, "uid=renamed"));
        admin.SendRequest(new DeleteRequest("uid=viewer," + Users));
        Assert.Equal(Refused, Fails(reader, SetMail(AdminDn, "x@example.com")));
        Assert.Equal(Refused, Fails(viewer, SetMail(AdminDn, "x@example.com")));

        // the mark lifted from the renamed entry does not reach a connection that knows it by the old name...
        server.Directory.SetReadOnly("uid=renamed," + Users, readOnly: false);
        Assert.Equal(Refused, Fails(reader, SetMail(AdminDn, "x@example.com")));
        // ...but an entry that takes the old name is what the connection is judged by from then on
        server.Directory.AddUser("viewer", "other-secret");
        viewer.SendRequest(SetMail(AdminDn, "viewer-was-here@example.com"));
        server.Directory.SetReadOnly("uid=viewer," + Users);
        Assert.Equal(Refused, Fails(viewer, SetMail(AdminDn, "x@example.com")));

        // a user who may write keeps that right when their entry goes away, as before
        admin.SendRequest(new DeleteRequest(AliceDn));
        alice.SendRequest(SetMail(AdminDn, "alice-was-here@example.com"));
        Assert.Equal("alice-was-here@example.com", server.Directory.Find(AdminDn)!.GetString("mail"));

        // and a new bind starts from what the user is now
        reader.Bind(new NetworkCredential("uid=renamed," + Users, "reader-secret"));
        reader.SendRequest(SetMail(AdminDn, "renamed-was-here@example.com"));
        reader.Bind(new NetworkCredential(AdminDn, "admin-secret"));
        reader.SendRequest(SetMail(AdminDn, "admin@example.com"));
    }

    [Fact]
    public void A_mark_on_the_generated_domain_users_group_goes_away_with_it()
    {
        using var server = Ad().Start();
        const string generated = "CN=Domain Users," + AdUsers;
        server.Directory.SetReadOnly(generated);

        // test data that brings its own "Domain Users" replaces the generated one
        server.Directory.Add("CN=Domain Users,OU=Groups,DC=corp,DC=example,DC=com", e => e
            .Set("objectClass", "top", "group").Set("sAMAccountName", "Domain Users"));
        Assert.False(server.Directory.Exists(generated));
        Assert.False(server.Directory.IsReadOnly(generated));
    }

    [Fact]
    public void Clearing_the_directory_clears_the_marks()
    {
        using var server = Generic().Start();
        server.Directory.Clear();
        server.Directory.AddUser("reader", "reader-secret");
        Assert.False(server.Directory.IsReadOnly(ReaderDn));
    }

    [Fact]
    public void Users_from_ldif_are_marked_by_dn_or_by_name()
    {
        const string ldif = """
            dn: cn=svc-report,ou=services,dc=example,dc=com
            objectClass: person
            cn: svc-report
            sn: svc-report
            userPassword: report-secret

            dn: uid=bob,ou=users,dc=example,dc=com
            objectClass: inetOrgPerson
            uid: bob
            cn: bob
            sn: bob
            userPassword: bob-secret
            """;
        using var server = Generic().WithLdif(ldif)
            .WithReadOnlyUser("CN=svc-report,OU=services,DC=example,DC=com")
            .WithReadOnlyUser("bob")
            .Start();

        using var service = Connect(server, "cn=svc-report,ou=services,dc=example,dc=com", "report-secret");
        Assert.Equal(Refused, Fails(service, SetMail(AliceDn, "x@example.com")));
        using var bob = Connect(server, "uid=bob," + Users, "bob-secret");
        Assert.Equal(Refused, Fails(bob, SetMail(AliceDn, "x@example.com")));
    }

    [Fact]
    public void Marking_a_user_that_does_not_exist_is_an_error()
    {
        var error = Assert.Throws<InvalidOperationException>(() => Generic().WithReadOnlyUser("nobody").Start());
        Assert.Contains("uid=nobody," + Users, error.Message);
        Assert.Contains("Call it after", error.Message); // the usual cause: called before the data that adds the user

        using var server = Generic().Start();
        Assert.Throws<InvalidOperationException>(() => server.Directory.SetReadOnly("uid=ghost," + Users));
        Assert.Throws<InvalidOperationException>(() => server.Directory.SetReadOnly("uid=ghost," + Users, readOnly: false));
    }

    [Fact]
    public void A_read_only_user_changes_a_password_only_with_the_old_one()
    {
        using var server = Generic().Start();
        using var reader = Connect(server, ReaderDn, "reader-secret");

        // resets, of their own password or of someone else's, are writes
        Assert.Equal(Refused, Fails(reader, PasswordModify(null, null, "new-secret")));
        Assert.Equal(Refused, Fails(reader, PasswordModify(AliceDn, null, "new-secret")));
        Assert.Equal(Refused, Fails(reader, PasswordModify("uid=ghost," + Users, null, "new-secret")));
        using (Connect(server, AliceDn, "alice-secret"))
        {
        }

        // knowing the old password is enough, as it is for a client that has not bound at all
        Assert.Equal((ResultCode)49, Fails(reader, PasswordModify(null, "wrong", "new-secret")));
        reader.SendRequest(PasswordModify(null, "reader-secret", "new-secret"));
        using (Connect(server, ReaderDn, "new-secret"))
        {
        }
        Assert.True(server.Directory.IsReadOnly(ReaderDn));
        Assert.Equal(Refused, Fails(reader, SetMail(AliceDn, "x@example.com")));
    }

    [Fact]
    public void Sasl_plain_logs_a_read_only_user_in_as_read_only()
    {
        using var server = Generic().Start();
        using var novell = new Novell.Directory.Ldap.LdapConnection();
        novell.Connect(server.Host, server.Port);
        novell.Bind(new Novell.Directory.Ldap.Sasl.SaslPlainRequest("reader", "reader-secret"));

        var error = Assert.Throws<Novell.Directory.Ldap.LdapException>(() => novell.Delete(AliceDn));
        Assert.Equal(Novell.Directory.Ldap.LdapException.InsufficientAccessRights, error.ResultCode);
        Assert.True(server.Directory.Exists(AliceDn));
    }

    // ---- Active Directory flavour ----------------------------------------------------------------------------

    private const string AdUsers = "CN=Users,DC=corp,DC=example,DC=com";
    private const string AdAlice = "CN=alice," + AdUsers;
    private const string AdReader = "CN=reader," + AdUsers;

    [Theory]
    [InlineData("reader@corp.example.com")]
    [InlineData("CORP\\reader")]
    [InlineData(AdReader)]
    public void Active_directory_refuses_with_its_own_message(string login)
    {
        using var server = Ad().Start();
        using var reader = Connect(server, login, "reader-secret");

        Assert.Equal(Refused, Fails(reader, NewUnit("OU=new,DC=corp,DC=example,DC=com")));
        Assert.Equal(Refused, Fails(reader, SetMail(AdAlice, "x@example.com")));
        Assert.Equal(Refused, Fails(reader, new DeleteRequest(AdAlice)));
        Assert.Equal(Refused, Fails(reader, new ModifyDNRequest(AdAlice, AdUsers, "CN=alicia")));
        Assert.True(server.Directory.Exists(AdAlice));
        Assert.False(server.Directory.Find(AdAlice)!.Has("mail"));

        var refusals = server.Requests.Where(r => r.Result?.Code == Protocol.ResultCode.InsufficientAccessRights).ToList();
        Assert.Equal(4, refusals.Count);
        Assert.All(refusals, r => Assert.Equal("00002098: SecErr: DSID-03150F94, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0", r.Result!.Message));

        using var anonymous = Connect(server, null, null);
        Assert.Equal(ResultCode.OperationsError, Fails(anonymous, SetMail(AdAlice, "x@example.com")));
    }

    [Fact]
    public void Active_directory_lets_a_read_only_user_change_a_password_but_not_reset_one()
    {
        using var server = Ad().Start();
        using var reader = Connect(server, AdReader, "reader-secret");

        // a reset names no old password
        Assert.Equal(Refused, Fails(reader, new ModifyRequest(AdReader, UnicodePwd(DirectoryAttributeOperation.Replace, "New-secret1"))));
        Assert.Equal(Refused, Fails(reader, new ModifyRequest(AdAlice, UnicodePwd(DirectoryAttributeOperation.Replace, "New-secret1"))));
        // a change that brings another change along is an ordinary write
        Assert.Equal(Refused, Fails(reader, new ModifyRequest(AdReader,
            UnicodePwd(DirectoryAttributeOperation.Delete, "reader-secret"),
            UnicodePwd(DirectoryAttributeOperation.Add, "New-secret1"),
            new DirectoryAttributeModification { Name = "description", Operation = DirectoryAttributeOperation.Replace })));
        // and so is the same pair in the wrong order, or half of it
        Assert.Equal(Refused, Fails(reader, new ModifyRequest(AdReader,
            UnicodePwd(DirectoryAttributeOperation.Add, "New-secret1"),
            UnicodePwd(DirectoryAttributeOperation.Delete, "reader-secret"))));
        Assert.Equal(Refused, Fails(reader, new ModifyRequest(AdReader, UnicodePwd(DirectoryAttributeOperation.Delete, "reader-secret"))));
        Assert.Equal(Refused, Fails(reader, new ModifyRequest(AdReader,
            UnicodePwd(DirectoryAttributeOperation.Delete, "reader-secret"),
            new DirectoryAttributeModification { Name = "description", Operation = DirectoryAttributeOperation.Add })));
        using (Connect(server, AdReader, "reader-secret"))
        {
        }

        // the wrong old password fails the way it does for everyone
        Assert.Equal(ResultCode.ConstraintViolation, Fails(reader, new ModifyRequest(AdReader,
            UnicodePwd(DirectoryAttributeOperation.Delete, "wrong"),
            UnicodePwd(DirectoryAttributeOperation.Add, "New-secret1"))));

        reader.SendRequest(new ModifyRequest(AdReader,
            UnicodePwd(DirectoryAttributeOperation.Delete, "reader-secret"),
            UnicodePwd(DirectoryAttributeOperation.Add, "New-secret1")));
        using (Connect(server, AdReader, "New-secret1"))
        {
        }
        // someone else's password too, when they know it: Active Directory gives that right to everyone
        reader.SendRequest(new ModifyRequest(AdAlice,
            UnicodePwd(DirectoryAttributeOperation.Delete, "alice-secret"),
            UnicodePwd(DirectoryAttributeOperation.Add, "New-secret2")));
        using (Connect(server, AdAlice, "New-secret2"))
        {
        }
    }

    [Fact]
    public void A_generic_directory_has_no_password_change_through_unicodePwd()
    {
        using var server = Generic().Start();
        using var reader = Connect(server, ReaderDn, "reader-secret");
        Assert.Equal(Refused, Fails(reader, new ModifyRequest(ReaderDn,
            UnicodePwd(DirectoryAttributeOperation.Delete, "reader-secret"),
            UnicodePwd(DirectoryAttributeOperation.Add, "New-secret1"))));
        Assert.False(server.Directory.Find(ReaderDn)!.Has("unicodePwd"));
    }

    [Fact]
    public void A_password_change_still_needs_tls_when_the_server_asks_for_it()
    {
        using var server = Ad().WithOptions(o => o.RequireTlsForUnicodePwd = true).Start();
        using var reader = Connect(server, AdReader, "reader-secret");
        Assert.Equal(ResultCode.UnwillingToPerform, Fails(reader, new ModifyRequest(AdReader,
            UnicodePwd(DirectoryAttributeOperation.Delete, "reader-secret"),
            UnicodePwd(DirectoryAttributeOperation.Add, "New-secret1"))));
        using (Connect(server, AdReader, "reader-secret"))
        {
        }
    }

    // ---- Corner cases of the rules above -------------------------------------------------------------------

    private static DirectoryAttributeModification Change(string name, DirectoryAttributeOperation operation, string value)
    {
        var modification = new DirectoryAttributeModification { Name = name, Operation = operation };
        modification.Add(value);
        return modification;
    }

    private static DirectoryAttributeModification Pwd(string name, DirectoryAttributeOperation operation, string password)
    {
        var modification = new DirectoryAttributeModification { Name = name, Operation = operation };
        modification.Add(Encoding.Unicode.GetBytes('"' + password + '"'));
        return modification;
    }

    [Fact]
    public void Active_directory_refuses_a_password_change_that_follows_another_change()
    {
        using var server = Ad().Start();
        using var reader = Connect(server, AdReader, "reader-secret");
        Assert.Equal(Refused, Fails(reader, new ModifyRequest(AdReader,
            Change("description", DirectoryAttributeOperation.Replace, "sneaked in"),
            UnicodePwd(DirectoryAttributeOperation.Delete, "reader-secret"),
            UnicodePwd(DirectoryAttributeOperation.Add, "New-secret1"))));
        Assert.False(server.Directory.Find(AdReader)!.Has("description"));
        using (Connect(server, AdReader, "reader-secret"))
        {
        }
    }

    [Fact]
    public void Active_directory_refuses_a_new_unicodePwd_that_comes_with_the_delete_of_something_else()
    {
        using var server = Ad().Start();
        using (var admin = Connect(server, "CN=admin," + AdUsers, "admin-secret"))
            admin.SendRequest(new ModifyRequest(AdReader, Change("description", DirectoryAttributeOperation.Add, "old")));
        using var reader = Connect(server, AdReader, "reader-secret");
        Assert.Equal(Refused, Fails(reader, new ModifyRequest(AdReader,
            Change("description", DirectoryAttributeOperation.Delete, "old"),
            UnicodePwd(DirectoryAttributeOperation.Add, "New-secret1"))));
        Assert.Equal("old", server.Directory.Find(AdReader)!.GetString("description"));
        using (Connect(server, AdReader, "reader-secret"))
        {
        }
    }

    [Theory]
    [InlineData("UNICODEPWD")]
    [InlineData("unicodePwd;binary")]
    public void Active_directory_knows_a_password_change_however_the_attribute_is_spelled(string name)
    {
        using var server = Ad().Start();
        using var reader = Connect(server, AdReader, "reader-secret");
        reader.SendRequest(new ModifyRequest(AdReader,
            Pwd(name, DirectoryAttributeOperation.Delete, "reader-secret"),
            Pwd(name, DirectoryAttributeOperation.Add, "New-secret1")));
        using (Connect(server, AdReader, "New-secret1"))
        {
        }
    }

    [Fact]
    public void Active_directory_takes_no_password_change_from_an_anonymous_client()
    {
        using var server = Ad().Start();
        using var anonymous = Connect(server, null, null);
        Assert.Equal(ResultCode.OperationsError, Fails(anonymous, new ModifyRequest(AdAlice,
            UnicodePwd(DirectoryAttributeOperation.Delete, "alice-secret"),
            UnicodePwd(DirectoryAttributeOperation.Add, "New-secret1"))));
        using (Connect(server, AdAlice, "alice-secret"))
        {
        }
    }

    [Fact]
    public void A_read_only_user_changes_someone_elses_password_when_they_know_the_old_one()
    {
        using var server = Generic().Start();
        using var reader = Connect(server, ReaderDn, "reader-secret");
        Assert.Equal((ResultCode)49, Fails(reader, PasswordModify(AliceDn, "wrong", "new-secret")));
        reader.SendRequest(PasswordModify(AliceDn, "alice-secret", "new-secret"));
        using (Connect(server, AliceDn, "new-secret"))
        {
        }
    }

    [Fact]
    public void The_mark_follows_a_rename_whatever_the_case_of_the_new_name()
    {
        using var server = Generic().Start();
        using var admin = Connect(server, AdminDn, "admin-secret");
        admin.SendRequest(new ModifyDNRequest(ReaderDn, Users, "UID=Viewer"));
        Assert.True(server.Directory.IsReadOnly("uid=viewer," + Users));
        using var viewer = Connect(server, "uid=viewer," + Users, "reader-secret");
        Assert.Equal(Refused, Fails(viewer, SetMail(AliceDn, "x@example.com")));
    }

    [Fact]
    public void The_mark_follows_a_renamed_user_in_active_directory()
    {
        using var server = Ad().Start();
        using var admin = Connect(server, "CN=admin," + AdUsers, "admin-secret");
        admin.SendRequest(new ModifyDNRequest(AdReader, AdUsers, "CN=viewer"));
        Assert.True(server.Directory.IsReadOnly("CN=viewer," + AdUsers));
        Assert.False(server.Directory.IsReadOnly(AdReader));
    }

    [Fact]
    public void A_move_onto_a_name_inside_the_moved_subtree_keeps_each_mark_with_its_entry()
    {
        var directory = new InMemoryDirectory { AutoCreateParents = false };
        directory.Add("dc=example,dc=com", e => e.Set("objectClass", "top", "domain"));
        const string top = "uid=r,dc=example,dc=com", middle = "uid=r," + top, bottom = "uid=r," + middle;
        directory.Add(bottom, e => e.Set("objectClass", "top", "person").Set("cn", "r").Set("sn", "r"));
        directory.Add(middle, e => e.Set("objectClass", "top", "person").Set("cn", "r").Set("sn", "r"));
        Assert.False(directory.Exists(top));
        directory.SetReadOnly(bottom);

        directory.Move(middle, top); // bottom becomes middle, middle becomes top
        Assert.True(directory.IsReadOnly(middle));
        Assert.False(directory.IsReadOnly(top));
    }

    [Fact]
    public void A_dn_of_a_single_rdn_is_a_dn()
    {
        using var server = LdapTestServer.Create().WithBaseDn("o=acme")
            .WithEntry("o=acme", e => e.Set("objectClass", "top", "organization").Set("userPassword", "acme-secret"))
            .WithReadOnlyUser("o=acme").Start();
        Assert.True(server.Directory.IsReadOnly("o=acme"));
    }

    [Fact]
    public void A_request_for_a_generated_password_is_answered_as_for_everyone()
    {
        using var server = Generic().Start();
        using var reader = Connect(server, ReaderDn, "reader-secret");
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
        }
        Assert.Equal(ResultCode.UnwillingToPerform, Fails(reader, new ExtendedRequest(PasswordModifyOid, writer.Encode())));
    }
}
