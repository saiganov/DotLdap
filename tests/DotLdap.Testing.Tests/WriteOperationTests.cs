using System.DirectoryServices.Protocols;
using System.Formats.Asn1;
using System.Net;
using System.Text;

namespace DotLdap.Testing.Tests;

/// <summary>Add, Modify, Delete, ModifyDN and Password Modify over the wire, driven by System.DirectoryServices.Protocols.</summary>
public class WriteOperationTests : IDisposable
{
    private const string Users = "ou=users,dc=example,dc=com";
    private const string AliceDn = "uid=alice," + Users;
    private const string AdminDn = "uid=admin," + Users;

    private readonly LdapTestServer _server = LdapTestServer.Create()
        .WithUser("admin", "admin-secret")
        .WithUser("alice", "alice-secret", u => u.Email("alice@example.com").MemberOf("staff"))
        .WithEntry("ou=archive,dc=example,dc=com", e => e.Set("objectClass", "top", "organizationalUnit").Set("ou", "archive"))
        .Start();

    public void Dispose() => _server.Dispose();

    private LdapConnection Connect(string? dn = AdminDn, string? password = "admin-secret")
    {
        var connection = new LdapConnection(new LdapDirectoryIdentifier(_server.Host, _server.Port))
        {
            AuthType = dn is null ? AuthType.Anonymous : AuthType.Basic,
            Credential = dn is null ? null : new NetworkCredential(dn, password),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.Bind();
        return connection;
    }

    private static ResultCode Fails(LdapConnection connection, DirectoryRequest request) =>
        Assert.Throws<DirectoryOperationException>(() => connection.SendRequest(request)).Response.ResultCode;

    private static AddRequest NewUser(string dn, string password = "carol-secret") => new(dn,
        new DirectoryAttribute("objectClass", "top", "person", "inetOrgPerson"),
        new DirectoryAttribute("cn", "Carol"),
        new DirectoryAttribute("sn", "Example"),
        new DirectoryAttribute("userPassword", password));

    [Fact]
    public void Added_user_can_bind_and_is_found()
    {
        using var admin = Connect();
        admin.SendRequest(NewUser("uid=carol," + Users));

        using var carol = Connect("uid=carol," + Users, "carol-secret");
        var found = _server.Directory.Find("uid=carol," + Users)!;
        Assert.Equal("carol", found.GetString("uid")); // the RDN value is added for the client
        Assert.Contains(_server.Requests, r => r.Request is Protocol.AddRequest { Dn: "uid=carol," + Users });
    }

    [Fact]
    public void Add_is_refused_with_the_code_a_real_server_gives()
    {
        using var admin = Connect();
        Assert.Equal(ResultCode.EntryAlreadyExists, Fails(admin, NewUser(AliceDn)));
        Assert.Equal(ResultCode.NoSuchObject, Fails(admin, NewUser("uid=carol,ou=missing,dc=example,dc=com")));
        Assert.Equal(ResultCode.ObjectClassViolation, Fails(admin, new AddRequest("uid=dave," + Users, new DirectoryAttribute("cn", "Dave"))));

        using var anonymous = Connect(null, null);
        Assert.Equal(ResultCode.StrongAuthRequired, Fails(anonymous, NewUser("uid=carol," + Users))); // as OpenLDAP
        Assert.False(_server.Directory.Exists("uid=carol," + Users));
    }

    [Fact]
    public void Entry_with_a_forgotten_suffix_does_not_become_a_naming_context()
    {
        using var admin = Connect();
        Assert.Equal(ResultCode.NoSuchObject, Fails(admin, NewUser("uid=carol")));
        Assert.Equal(ResultCode.NoSuchObject, Fails(admin, new ModifyDNRequest(AliceDn, "", "uid=alice")));
        Assert.Equal(["dc=example,dc=com"], _server.Directory.NamingContexts.Select(dn => dn.ToString()));
    }

    [Fact]
    public void Entry_seeded_without_its_rdn_value_can_still_be_modified()
    {
        _server.Directory.Add("cn=app,dc=example,dc=com", e => e.Set("objectClass", "top", "device"));
        using var admin = Connect();
        admin.SendRequest(new ModifyRequest("cn=app,dc=example,dc=com", DirectoryAttributeOperation.Replace, "description", "x"));
        Assert.Equal("x", _server.Directory.Find("cn=app,dc=example,dc=com")!.GetString("description"));
    }

    [Fact]
    public void Entry_seeded_without_its_rdn_value_can_gain_other_values_of_the_naming_attribute()
    {
        _server.Directory.Add("cn=app,dc=example,dc=com", e => e.Set("objectClass", "top", "device"));
        using var admin = Connect();
        admin.SendRequest(new ModifyRequest("cn=app,dc=example,dc=com", DirectoryAttributeOperation.Add, "cn", "application"));
        Assert.Equal(["application"], _server.Directory.Find("cn=app,dc=example,dc=com")!.GetStrings("cn"));
    }

    [Fact]
    public void Add_refuses_computed_attributes_and_duplicate_values()
    {
        using var admin = Connect();
        var withMemberOf = NewUser("uid=carol," + Users);
        withMemberOf.Attributes.Add(new DirectoryAttribute("memberOf", "cn=staff,ou=groups,dc=example,dc=com"));
        Assert.Equal(ResultCode.UnwillingToPerform, Fails(admin, withMemberOf));

        var twice = NewUser("uid=carol," + Users);
        twice.Attributes.Add(new DirectoryAttribute("mail", "carol@example.com", "CAROL@example.com"));
        Assert.Equal(ResultCode.AttributeOrValueExists, Fails(admin, twice));
        Assert.False(_server.Directory.Exists("uid=carol," + Users));
    }

    [Fact]
    public void Replace_refuses_duplicate_values()
    {
        using var admin = Connect();
        Assert.Equal(ResultCode.AttributeOrValueExists,
            Fails(admin, new ModifyRequest(AliceDn, DirectoryAttributeOperation.Replace, "telephoneNumber", "111", "111")));
        Assert.False(_server.Directory.Find(AliceDn)!.Has("telephoneNumber"));
    }

    [Fact]
    public void Modify_keeps_the_stored_attribute_name()
    {
        using var admin = Connect();
        admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Replace, "MAIL", "alice@new.example.com"));
        var mail = Assert.Single(_server.Directory.Find(AliceDn)!.Attributes, a => a.Name.Equals("mail", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("mail", mail.Name);
    }

    [Fact]
    public void Increment()
    {
        // RFC 4525. System.DirectoryServices.Protocols cannot send it, so this one goes to the directory directly.
        static Protocol.Modification By(string attribute, string amount) => new(Protocol.ModificationType.Increment,
            new Protocol.PartialAttribute(attribute, [Encoding.UTF8.GetBytes(amount)]));

        _server.Directory.Update(AliceDn, e => e.Set("loginCount", "41"));
        Assert.Equal(Protocol.ResultCode.Success, _server.Directory.ApplyModify(AliceDn, [By("loginCount", "1")]).Code);
        Assert.Equal("42", _server.Directory.Find(AliceDn)!.GetString("loginCount"));
        Assert.Equal(Protocol.ResultCode.NoSuchAttribute, _server.Directory.ApplyModify(AliceDn, [By("badPwdCount", "1")]).Code);
        Assert.Equal(Protocol.ResultCode.ConstraintViolation, _server.Directory.ApplyModify(AliceDn, [By("mail", "1")]).Code);
    }

    [Fact]
    public void Modify_adds_replaces_and_deletes_values()
    {
        using var admin = Connect();
        admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Add, "telephoneNumber", "111", "222"));
        admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Replace, "mail", "alice@new.example.com"));
        admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Delete, "telephoneNumber", "111"));

        var alice = _server.Directory.Find(AliceDn)!;
        Assert.Equal(["222"], alice.GetStrings("telephoneNumber"));
        Assert.Equal(["alice@new.example.com"], alice.GetStrings("mail"));

        admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Delete, "telephoneNumber"));
        Assert.False(_server.Directory.Find(AliceDn)!.Has("telephoneNumber"));
    }

    [Fact]
    public void Modify_errors()
    {
        using var admin = Connect();
        Assert.Equal(ResultCode.NoSuchObject, Fails(admin, new ModifyRequest("uid=ghost," + Users, DirectoryAttributeOperation.Replace, "mail", "x")));
        Assert.Equal(ResultCode.NoSuchAttribute, Fails(admin, new ModifyRequest(AliceDn, DirectoryAttributeOperation.Delete, "description")));
        Assert.Equal(ResultCode.AttributeOrValueExists, Fails(admin, new ModifyRequest(AliceDn, DirectoryAttributeOperation.Add, "mail", "ALICE@example.com")));
        Assert.Equal(ResultCode.NotAllowedOnRdn, Fails(admin, new ModifyRequest(AliceDn, DirectoryAttributeOperation.Replace, "uid", "alicia")));
        Assert.Equal(ResultCode.UnwillingToPerform, Fails(admin, new ModifyRequest(AliceDn, DirectoryAttributeOperation.Replace, "memberOf", "cn=x")));
    }

    [Fact]
    public void Modify_is_all_or_nothing()
    {
        using var admin = Connect();
        var good = new DirectoryAttributeModification { Name = "description", Operation = DirectoryAttributeOperation.Add };
        good.Add("applied first");
        var bad = new DirectoryAttributeModification { Name = "roomNumber", Operation = DirectoryAttributeOperation.Delete };

        Assert.Equal(ResultCode.NoSuchAttribute, Fails(admin, new ModifyRequest(AliceDn, good, bad)));
        Assert.False(_server.Directory.Find(AliceDn)!.Has("description"));
    }

    [Fact]
    public void Group_membership_changes_show_up_in_memberOf()
    {
        using var admin = Connect();
        const string staff = "cn=staff,ou=groups,dc=example,dc=com";
        admin.SendRequest(new ModifyRequest(staff, DirectoryAttributeOperation.Add, "member", AdminDn));

        var response = (SearchResponse)admin.SendRequest(new SearchRequest("dc=example,dc=com", $"(memberOf={staff})", SearchScope.Subtree, "uid"));
        Assert.Equal(2, response.Entries.Count);

        admin.SendRequest(new ModifyRequest(staff, DirectoryAttributeOperation.Delete, "member", AliceDn));
        response = (SearchResponse)admin.SendRequest(new SearchRequest("dc=example,dc=com", $"(memberOf={staff})", SearchScope.Subtree, "uid"));
        Assert.Equal("admin", ((SearchResultEntry)response.Entries[0]).Attributes["uid"][0]);
    }

    [Fact]
    public void Delete_removes_leaves_only()
    {
        using var admin = Connect();
        Assert.Equal(ResultCode.NotAllowedOnNonLeaf, Fails(admin, new DeleteRequest(Users)));
        Assert.Equal(ResultCode.NoSuchObject, Fails(admin, new DeleteRequest("uid=ghost," + Users)));

        admin.SendRequest(new DeleteRequest(AliceDn));
        Assert.False(_server.Directory.Exists(AliceDn));
        Assert.Throws<LdapException>(() => Connect(AliceDn, "alice-secret"));
    }

    [Fact]
    public void ModifyDn_renames_an_entry()
    {
        using var admin = Connect();
        admin.SendRequest(new ModifyDNRequest(AliceDn, Users, "uid=alicia"));

        Assert.False(_server.Directory.Exists(AliceDn));
        var renamed = _server.Directory.Find("uid=alicia," + Users)!;
        Assert.Equal(["alicia"], renamed.GetStrings("uid")); // old RDN value removed, new one added
        Assert.Equal("alice@example.com", renamed.GetString("mail"));
        using var alicia = Connect("uid=alicia," + Users, "alice-secret");
    }

    [Fact]
    public void ModifyDn_moves_a_subtree()
    {
        using var admin = Connect();
        admin.SendRequest(new ModifyDNRequest(Users, "ou=archive,dc=example,dc=com", "ou=people"));

        Assert.True(_server.Directory.Exists("uid=alice,ou=people,ou=archive,dc=example,dc=com"));
        Assert.False(_server.Directory.Exists(AliceDn));
        Assert.Equal(ResultCode.EntryAlreadyExists,
            Fails(admin, new ModifyDNRequest("ou=groups,dc=example,dc=com", "dc=example,dc=com", "ou=archive")));
        Assert.Equal(ResultCode.NoSuchObject,
            Fails(admin, new ModifyDNRequest("ou=groups,dc=example,dc=com", "ou=nowhere,dc=example,dc=com", "ou=groups")));
    }

    [Fact]
    public void ModifyDn_does_not_overwrite_an_entry_below_the_target()
    {
        // an entry seeded without its parent sits exactly where alice would land; ou=people itself is free
        _server.Directory.AutoCreateParents = false;
        _server.Directory.Add("uid=alice,ou=people,dc=example,dc=com", e => e.Set("objectClass", "top", "account"));
        using var admin = Connect();
        Assert.False(_server.Directory.Exists("ou=people,dc=example,dc=com"));
        Assert.Equal(ResultCode.EntryAlreadyExists, Fails(admin, new ModifyDNRequest(Users, "dc=example,dc=com", "ou=people")));
        Assert.True(_server.Directory.Exists(AliceDn));
        Assert.Equal(["account", "top"], _server.Directory.Find("uid=alice,ou=people,dc=example,dc=com")!.GetStrings("objectClass").Order());
    }

    [Fact]
    public void Move_renames_a_suffix_entry_in_place()
    {
        _server.Directory.Move("dc=example,dc=com", "dc=sample,dc=com");
        Assert.True(_server.Directory.Exists("uid=alice,ou=users,dc=sample,dc=com"));
        Assert.False(_server.Directory.Exists(AliceDn));
        Assert.Equal(["dc=sample,dc=com"], _server.Directory.NamingContexts.Select(dn => dn.ToString()));
        // users added afterwards follow the new base DN
        Assert.Equal("uid=bob,ou=users,dc=sample,dc=com", _server.Directory.AddUser("bob", "bob-secret").ToString());
    }

    [Fact]
    public void Client_cannot_rename_the_base_dn()
    {
        using var admin = Connect();
        Assert.Equal(ResultCode.UnwillingToPerform, Fails(admin, new ModifyDNRequest("dc=example,dc=com", null, "dc=sample")));
        Assert.True(_server.Directory.Exists(AliceDn));
    }

    [Fact]
    public void ModifyDn_keeps_the_spelling_the_directory_has()
    {
        using var admin = Connect();
        admin.SendRequest(new ModifyDNRequest("UID=ALICE,OU=USERS,DC=EXAMPLE,DC=COM", "OU=ARCHIVE,DC=EXAMPLE,DC=COM", "uid=alicia"));

        var renamed = _server.Directory.Find("uid=alicia,ou=archive,dc=example,dc=com")!;
        Assert.Equal("uid=alicia,ou=archive,dc=example,dc=com", renamed.Dn.ToString());
        // the new RDN typed as "UID=..." still lands in the attribute the entry calls "uid"
        admin.SendRequest(new ModifyDNRequest("uid=alicia,ou=archive,dc=example,dc=com", "ou=archive,dc=example,dc=com", "UID=alice"));
        renamed = _server.Directory.Find("uid=alice,ou=archive,dc=example,dc=com")!;
        Assert.Equal("uid", Assert.Single(renamed.Attributes, a => a.Name.Equals("uid", StringComparison.OrdinalIgnoreCase)).Name);
    }

    [Fact]
    public void Delete_refuses_an_entry_with_anything_below_it()
    {
        _server.Directory.AutoCreateParents = false;
        _server.Directory.Add("uid=x,ou=gone,ou=archive,dc=example,dc=com", e => e.Set("objectClass", "top", "account"));
        using var admin = Connect();
        Assert.Equal(ResultCode.NotAllowedOnNonLeaf, Fails(admin, new DeleteRequest("ou=archive,dc=example,dc=com")));
    }

    [Fact]
    public void Entry_seeded_without_objectClass_can_still_be_modified()
    {
        _server.Directory.Add("cn=bare,dc=example,dc=com", e => e.Set("cn", "bare"));
        using var admin = Connect();
        admin.SendRequest(new ModifyRequest("cn=bare,dc=example,dc=com", DirectoryAttributeOperation.Replace, "description", "x"));
        Assert.Equal("x", _server.Directory.Find("cn=bare,dc=example,dc=com")!.GetString("description"));
        Assert.Equal(ResultCode.ObjectClassViolation, Fails(admin, new ModifyRequest(AliceDn, DirectoryAttributeOperation.Delete, "objectClass")));
    }

    [Fact]
    public void Attribute_options_are_dropped()
    {
        using var admin = Connect();
        admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Add, "description;lang-en", "engineer"));
        var withOption = NewUser("uid=carol," + Users);
        withOption.Attributes.Add(new DirectoryAttribute("title;lang-en", "manager"));
        admin.SendRequest(withOption);

        var found = (SearchResponse)admin.SendRequest(new SearchRequest("dc=example,dc=com", "(|(description=engineer)(title=manager))", SearchScope.Subtree));
        Assert.Equal(2, found.Entries.Count);
        Assert.Equal("engineer", _server.Directory.Find(AliceDn)!.GetString("description"));
    }

    [Fact]
    public void Same_value_under_two_options_is_not_a_duplicate()
    {
        using var admin = Connect();
        var carol = NewUser("uid=carol," + Users);
        carol.Attributes.Add(new DirectoryAttribute("description;lang-en", "Hello"));
        carol.Attributes.Add(new DirectoryAttribute("description;lang-de", "Hello"));
        admin.SendRequest(carol);
        Assert.Equal(["Hello"], _server.Directory.Find("uid=carol," + Users)!.GetStrings("description"));

        admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Add, "description;lang-en", "Hi"));
        admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Add, "description;lang-de", "Hi"));
        Assert.Equal(["Hi"], _server.Directory.Find(AliceDn)!.GetStrings("description"));
        Assert.Equal(ResultCode.AttributeOrValueExists, Fails(admin, new ModifyRequest(AliceDn, DirectoryAttributeOperation.Add, "description", "hi")));
    }

    [Fact]
    public void Attribute_asked_for_with_an_option_comes_back_under_that_name()
    {
        _server.Directory.AddLdif("""
            dn: cn=cert,dc=example,dc=com
            objectClass: device
            cn: cert
            userCertificate;binary:: AQID
            """);
        using var admin = Connect();
        var response = (SearchResponse)admin.SendRequest(
            new SearchRequest("cn=cert,dc=example,dc=com", "(objectClass=*)", SearchScope.Base, "userCertificate;binary"));
        var attribute = ((SearchResultEntry)response.Entries[0]).Attributes["userCertificate;binary"];
        Assert.Equal(new byte[] { 1, 2, 3 }, (byte[])attribute.GetValues(typeof(byte[]))[0]);
    }

    [Fact]
    public void Add_with_an_attribute_without_values_is_a_protocol_error()
    {
        // System.DirectoryServices.Protocols does not send an attribute without values, so the request is built by hand.
        static byte[] Message(int id, Asn1Tag operation, Action<AsnWriter> body)
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);
            using (writer.PushSequence())
            {
                writer.WriteInteger(id);
                using (writer.PushSequence(operation)) body(writer);
            }
            return writer.Encode();
        }

        static int ResultCodeOf(System.Net.Sockets.NetworkStream stream)
        {
            var buffer = new byte[1024];
            var length = 0;
            int consumed;
            while (!AsnDecoder.TryReadEncodedValue(buffer.AsSpan(0, length), AsnEncodingRules.BER, out _, out _, out _, out consumed))
            {
                var read = stream.Read(buffer, length, buffer.Length - length);
                Assert.True(read > 0, "the server closed the connection");
                length += read;
            }
            var message = new AsnReader(buffer.AsMemory(0, consumed), AsnEncodingRules.BER).ReadSequence();
            message.ReadInteger();
            return (int)message.ReadSequence(message.PeekTag()).ReadEnumeratedValue<Protocol.ResultCode>();
        }

        using var client = new System.Net.Sockets.TcpClient(_server.Host, _server.Port);
        var stream = client.GetStream();
        stream.Write(Message(1, new Asn1Tag(TagClass.Application, 0, isConstructed: true), w =>
        {
            w.WriteInteger(3);
            w.WriteOctetString(Encoding.UTF8.GetBytes(AdminDn));
            w.WriteOctetString("admin-secret"u8, new Asn1Tag(TagClass.ContextSpecific, 0));
        }));
        Assert.Equal(0, ResultCodeOf(stream));

        stream.Write(Message(2, new Asn1Tag(TagClass.Application, 8, isConstructed: true), w =>
        {
            w.WriteOctetString("cn=x,dc=example,dc=com"u8);
            using (w.PushSequence())
            {
                using (w.PushSequence())
                {
                    w.WriteOctetString("objectClass"u8);
                    using (w.PushSetOf()) w.WriteOctetString("device"u8);
                }
                using (w.PushSequence())
                {
                    w.WriteOctetString("description"u8);
                    using (w.PushSetOf())
                    {
                    }
                }
            }
        }));
        Assert.Equal((int)Protocol.ResultCode.ProtocolError, ResultCodeOf(stream));
        Assert.False(_server.Directory.Exists("cn=x,dc=example,dc=com"));
    }

    [Fact]
    public void Large_group_is_written_quickly()
    {
        var members = Enumerable.Range(0, 5000).Select(i => $"uid=user{i},{Users}").ToArray();
        using var admin = Connect();
        var watch = System.Diagnostics.Stopwatch.StartNew();
        admin.SendRequest(new AddRequest("cn=everyone,ou=groups,dc=example,dc=com",
            new DirectoryAttribute("objectClass", "top", "groupOfNames"), new DirectoryAttribute("member", members)));
        admin.SendRequest(new ModifyRequest("cn=everyone,ou=groups,dc=example,dc=com", DirectoryAttributeOperation.Delete, "member", members[1..]));
        admin.SendRequest(new ModifyRequest("cn=everyone,ou=groups,dc=example,dc=com", DirectoryAttributeOperation.Add, "member", members[1..]));

        Assert.Equal(5000, _server.Directory.Find("cn=everyone,ou=groups,dc=example,dc=com")!.GetValues("member").Count);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(20), $"took {watch.Elapsed}"); // pair-wise comparison took minutes
    }

    [Fact]
    public void Binary_values_are_compared_byte_for_byte()
    {
        // neither value is valid UTF-8; decoded as text they would look the same
        byte[] first = [0xFF, 0x01], second = [0xFE, 0x01];
        var photos = new DirectoryAttributeModification { Name = "photo", Operation = DirectoryAttributeOperation.Replace };
        photos.Add(first);
        photos.Add(second);
        var removeSecond = new DirectoryAttributeModification { Name = "photo", Operation = DirectoryAttributeOperation.Delete };
        removeSecond.Add(second);

        using var admin = Connect();
        admin.SendRequest(new ModifyRequest(AliceDn, photos));
        admin.SendRequest(new ModifyRequest(AliceDn, removeSecond));
        Assert.Equal([first], _server.Directory.Find(AliceDn)!.GetValues("photo"));
    }

    [Fact]
    public void Hash_schemes()
    {
        var md5 = "{MD5}" + Convert.ToBase64String(System.Security.Cryptography.MD5.HashData(Encoding.UTF8.GetBytes("erin-secret")));
        _server.Directory.AddUser("erin", md5);
        using var erin = Connect("uid=erin," + Users, "erin-secret");

        // a hash this library cannot check lets nobody in, least of all with the hash text as the password
        foreach (var (user, stored) in new[] { ("frank", "{CRYPT}$6$salt$hash"), ("gina", "{SSHA-256}abcdef"), ("hank", "{PKCS5S2}abcdef") })
        {
            _server.Directory.AddUser(user, stored);
            Assert.Throws<LdapException>(() => Connect($"uid={user}," + Users, stored));
        }
    }

    [Fact]
    public void Password_in_braces_that_is_not_a_hash_scheme_is_clear_text()
    {
        using var admin = Connect();
        admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Replace, "userPassword", "{2024}Secret"));
        using var alice = Connect(AliceDn, "{2024}Secret");
        Assert.Throws<LdapException>(() => Connect(AliceDn, "alice-secret"));
    }

    [Fact]
    public void User_seeded_with_a_ready_made_hash_binds_with_the_real_password()
    {
        var salt = new byte[] { 1, 2, 3, 4 };
        var digest = System.Security.Cryptography.SHA1.HashData([.. Encoding.UTF8.GetBytes("dave-secret"), .. salt]);
        var hash = "{SSHA}" + Convert.ToBase64String([.. digest, .. salt]);
        _server.Directory.AddUser("dave", hash);

        using var dave = Connect("uid=dave," + Users, "dave-secret");
        Assert.Throws<LdapException>(() => Connect("uid=dave," + Users, hash));
        Assert.Equal(hash, _server.Directory.Find("uid=dave," + Users)!.GetString("userPassword"));
    }

    [Fact]
    public void Password_changed_by_modify_takes_effect()
    {
        using var admin = Connect();
        admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Replace, "userPassword", "new-secret"));

        using var alice = Connect(AliceDn, "new-secret");
        Assert.Throws<LdapException>(() => Connect(AliceDn, "alice-secret"));
    }

    [Fact]
    public void Password_modify_extended_operation()
    {
        static byte[] Value(string? user, string? oldPassword, string newPassword)
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);
            using (writer.PushSequence())
            {
                if (user is not null) writer.WriteOctetString(Encoding.UTF8.GetBytes(user), new Asn1Tag(TagClass.ContextSpecific, 0));
                if (oldPassword is not null) writer.WriteOctetString(Encoding.UTF8.GetBytes(oldPassword), new Asn1Tag(TagClass.ContextSpecific, 1));
                writer.WriteOctetString(Encoding.UTF8.GetBytes(newPassword), new Asn1Tag(TagClass.ContextSpecific, 2));
            }
            return writer.Encode();
        }

        const string oid = "1.3.6.1.4.1.4203.1.11.1";
        using (var alice = Connect(AliceDn, "alice-secret"))
        {
            // a user changes their own password and must know the old one
            Assert.Equal((ResultCode)49, Fails(alice, new ExtendedRequest(oid, Value(null, "wrong", "second"))));
            alice.SendRequest(new ExtendedRequest(oid, Value(null, "alice-secret", "second")));
        }
        using (Connect(AliceDn, "second"))
        {
        }

        using var admin = Connect();
        admin.SendRequest(new ExtendedRequest(oid, Value(AliceDn, null, "third"))); // administrative reset
        using var again = Connect(AliceDn, "third");
        Assert.Throws<LdapException>(() => Connect(AliceDn, "second"));

        // a password that looks like a hash marker is still just a password
        admin.SendRequest(new ExtendedRequest(oid, Value(AliceDn, null, "{2024}Secret")));
        using var braces = Connect(AliceDn, "{2024}Secret");

        // an anonymous client gets the same answer for a user that exists and one that does not
        using (var anonymous = Connect(null, null))
        {
            Assert.Equal(ResultCode.StrongAuthRequired, Fails(anonymous, new ExtendedRequest(oid, Value(AliceDn, null, "x"))));
            Assert.Equal(ResultCode.StrongAuthRequired, Fails(anonymous, new ExtendedRequest(oid, Value("uid=ghost," + Users, null, "x"))));
        }

        // an empty password could never be used to bind
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, new ExtendedRequest(oid, Value(AliceDn, null, ""))));

        // a malformed value gets an answer and is recorded, the connection survives
        Assert.Equal(ResultCode.ProtocolError, Fails(admin, new ExtendedRequest(oid, [0x04, 0x01, 0x00])));
        // Not Requests[^1]: the unbind of a connection closed above is recorded whenever the server gets to it,
        // which can be after this request.
        Assert.Equal(Protocol.ResultCode.ProtocolError, _server.Last<Protocol.ExtendedRequest>()!.Result!.Code);
        admin.SendRequest(new ExtendedRequest(oid, Value(AliceDn, null, "fourth")));
    }
}

/// <summary>Write behaviour that is specific to the Active Directory flavour.</summary>
public class ActiveDirectoryWriteTests : IDisposable
{
    private const string BaseDn = "DC=corp,DC=example,DC=com";
    private const string AliceDn = "CN=alice,CN=Users," + BaseDn;
    private const string Developers = "CN=Developers,CN=Users," + BaseDn;

    private readonly LdapTestServer _server = LdapTestServer.Create()
        .AsActiveDirectory()
        .WithBaseDn(BaseDn)
        .WithUser("admin", "admin-secret")
        .WithUser("alice", "alice-secret", u => u.MemberOf("Developers"))
        .Start();

    public void Dispose() => _server.Dispose();

    private LdapConnection Connect(string user = "admin@corp.example.com", string password = "admin-secret")
    {
        var connection = new LdapConnection(new LdapDirectoryIdentifier(_server.Host, _server.Port))
        {
            AuthType = AuthType.Basic,
            Credential = new NetworkCredential(user, password),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.Bind();
        return connection;
    }

    private static DirectoryAttributeModification UnicodePwd(DirectoryAttributeOperation operation, string password)
    {
        var modification = new DirectoryAttributeModification { Name = "unicodePwd", Operation = operation };
        modification.Add(Encoding.Unicode.GetBytes('"' + password + '"'));
        return modification;
    }

    [Fact]
    public void Administrator_resets_a_password_through_unicodePwd()
    {
        using var admin = Connect();
        admin.SendRequest(new ModifyRequest(AliceDn, UnicodePwd(DirectoryAttributeOperation.Replace, "N3w-Passw0rd")));

        using var alice = Connect("alice@corp.example.com", "N3w-Passw0rd");
        Assert.Throws<LdapException>(() => Connect("alice@corp.example.com", "alice-secret"));
        Assert.False(_server.Directory.Find(AliceDn)!.Has("unicodePwd"));
    }

    [Fact]
    public void User_changes_own_password_by_deleting_the_old_and_adding_the_new()
    {
        using var alice = Connect("alice@corp.example.com", "alice-secret");
        var wrong = Assert.Throws<DirectoryOperationException>(() => alice.SendRequest(new ModifyRequest(AliceDn,
            UnicodePwd(DirectoryAttributeOperation.Delete, "not-the-old-one"), UnicodePwd(DirectoryAttributeOperation.Add, "N3w-Passw0rd"))));
        Assert.Equal(ResultCode.ConstraintViolation, wrong.Response.ResultCode);

        alice.SendRequest(new ModifyRequest(AliceDn,
            UnicodePwd(DirectoryAttributeOperation.Delete, "alice-secret"), UnicodePwd(DirectoryAttributeOperation.Add, "N3w-Passw0rd")));
        using var again = Connect("alice@corp.example.com", "N3w-Passw0rd");
    }

    [Fact]
    public void Half_of_a_password_change_is_refused()
    {
        using var alice = Connect("alice@corp.example.com", "alice-secret");
        ResultCode Fails(DirectoryAttributeModification change) =>
            Assert.Throws<DirectoryOperationException>(() => alice.SendRequest(new ModifyRequest(AliceDn, change))).Response.ResultCode;

        Assert.Equal(ResultCode.UnwillingToPerform, Fails(UnicodePwd(DirectoryAttributeOperation.Delete, "alice-secret")));
        Assert.Equal(ResultCode.UnwillingToPerform, Fails(UnicodePwd(DirectoryAttributeOperation.Add, "N3w-Passw0rd")));
        Assert.Equal(ResultCode.UnwillingToPerform, Fails(UnicodePwd(DirectoryAttributeOperation.Replace, "")));
        using var unchanged = Connect("alice@corp.example.com", "alice-secret");
    }

    [Fact]
    public void Password_reset_works_with_the_binary_option()
    {
        using var admin = Connect();
        var reset = UnicodePwd(DirectoryAttributeOperation.Replace, "N3w-Passw0rd");
        reset.Name = "unicodePwd;binary";
        admin.SendRequest(new ModifyRequest(AliceDn, reset));

        using var alice = Connect("alice@corp.example.com", "N3w-Passw0rd");
        Assert.DoesNotContain(_server.Directory.Find(AliceDn)!.Attributes, a => a.Name.StartsWith("unicodePwd", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Password_must_be_a_quoted_utf16_string()
    {
        using var admin = Connect();
        var e = Assert.Throws<DirectoryOperationException>(() =>
            admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Replace, "unicodePwd", "plain text")));
        Assert.Equal(ResultCode.UnwillingToPerform, e.Response.ResultCode);
    }

    [Fact]
    public void Added_user_gets_guid_and_sid_and_can_log_on()
    {
        using var admin = Connect();
        var request = new AddRequest("CN=Carol Example,CN=Users," + BaseDn,
            new DirectoryAttribute("objectClass", "top", "person", "organizationalPerson", "user"),
            new DirectoryAttribute("sAMAccountName", "carol"),
            new DirectoryAttribute("userPrincipalName", "carol@corp.example.com"),
            new DirectoryAttribute("userAccountControl", "512"));
        request.Attributes.Add(new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes("\"C4rol-Secret\"")));
        admin.SendRequest(request);

        var carol = _server.Directory.Find("CN=Carol Example,CN=Users," + BaseDn)!;
        Assert.Equal(16, carol.GetValues("objectGUID")[0].Length);
        Assert.True(carol.Has("objectSid"));
        Assert.Equal("Carol Example", carol.GetString("cn"));
        using var session = Connect("CORP\\carol", "C4rol-Secret");
    }

    [Fact]
    public void Group_membership_errors_use_the_codes_ad_uses()
    {
        using var admin = Connect();
        ResultCode Fails(DirectoryRequest request) =>
            Assert.Throws<DirectoryOperationException>(() => admin.SendRequest(request)).Response.ResultCode;

        // idempotent "add to group" code catches exactly these two
        Assert.Equal(ResultCode.EntryAlreadyExists, Fails(new ModifyRequest(Developers, DirectoryAttributeOperation.Add, "member", AliceDn)));
        Assert.Equal(ResultCode.UnwillingToPerform,
            Fails(new ModifyRequest(Developers, DirectoryAttributeOperation.Delete, "member", "CN=admin,CN=Users," + BaseDn)));
    }

    [Fact]
    public void Removing_a_member_from_a_group_without_members_is_refused_as_ad_does()
    {
        _server.Directory.Add("CN=Empty,CN=Users," + BaseDn, e => e.Set("objectClass", "top", "group").Set("cn", "Empty"));
        using var admin = Connect();
        var e = Assert.Throws<DirectoryOperationException>(() =>
            admin.SendRequest(new ModifyRequest("CN=Empty,CN=Users," + BaseDn, DirectoryAttributeOperation.Delete, "member", AliceDn)));
        Assert.Equal(ResultCode.UnwillingToPerform, e.Response.ResultCode);
    }

    [Fact]
    public void Stored_distinguishedName_follows_a_rename()
    {
        // exports from a real AD carry distinguishedName as an ordinary attribute
        _server.Directory.AddLdif($"""
            dn: CN=svc,CN=Users,{BaseDn}
            objectClass: user
            cn: svc
            distinguishedName: CN=svc,CN=Users,{BaseDn}
            """);
        using var admin = Connect();
        admin.SendRequest(new ModifyDNRequest($"CN=svc,CN=Users,{BaseDn}", $"CN=Users,{BaseDn}", "CN=service"));

        var response = (SearchResponse)admin.SendRequest(
            new SearchRequest(BaseDn, $"(distinguishedName=CN=service,CN=Users,{BaseDn})", SearchScope.Subtree, "distinguishedName"));
        var found = Assert.IsType<SearchResultEntry>(Assert.Single(response.Entries.Cast<object>()));
        Assert.Equal($"CN=service,CN=Users,{BaseDn}", found.Attributes["distinguishedName"][0]);
    }

    [Fact]
    public void UnicodePwd_can_be_limited_to_encrypted_connections()
    {
        using var strict = LdapTestServer.Create()
            .AsActiveDirectory()
            .WithBaseDn(BaseDn)
            .WithUser("admin", "admin-secret")
            .WithUser("alice", "alice-secret")
            .WithOptions(o => o.RequireTlsForUnicodePwd = true)
            .Start();
        using var admin = new LdapConnection(new LdapDirectoryIdentifier(strict.Host, strict.Port))
        {
            AuthType = AuthType.Basic,
            Credential = new NetworkCredential("admin@corp.example.com", "admin-secret"),
        };
        admin.SessionOptions.ProtocolVersion = 3;
        admin.Bind();

        var e = Assert.Throws<DirectoryOperationException>(() =>
            admin.SendRequest(new ModifyRequest(AliceDn, UnicodePwd(DirectoryAttributeOperation.Replace, "N3w-Passw0rd"))));
        Assert.Equal(ResultCode.UnwillingToPerform, e.Response.ResultCode);
        admin.SendRequest(new ModifyRequest(AliceDn, DirectoryAttributeOperation.Replace, "description", "still fine"));
    }

    [Fact]
    public void Password_modify_extended_operation_is_not_offered()
    {
        using var admin = Connect();
        var rootDse = (SearchResponse)admin.SendRequest(new SearchRequest("", "(objectClass=*)", SearchScope.Base, "supportedExtension"));
        var extensions = ((SearchResultEntry)rootDse.Entries[0]).Attributes["supportedExtension"].GetValues(typeof(string));
        Assert.DoesNotContain("1.3.6.1.4.1.4203.1.11.1", extensions);
        Assert.Equal(ResultCode.ProtocolError,
            Assert.Throws<DirectoryOperationException>(() => admin.SendRequest(new ExtendedRequest("1.3.6.1.4.1.4203.1.11.1"))).Response.ResultCode);
    }

    [Fact]
    public void Group_links_follow_renames_and_deletes()
    {
        using var admin = Connect();
        admin.SendRequest(new ModifyDNRequest(AliceDn, "CN=Users," + BaseDn, "CN=Alice Liddell"));
        var renamed = "CN=Alice Liddell,CN=Users," + BaseDn;
        Assert.Equal([renamed], _server.Directory.Find(Developers)!.GetStrings("member"));

        var response = (SearchResponse)admin.SendRequest(new SearchRequest(BaseDn, "(sAMAccountName=alice)", SearchScope.Subtree, "memberOf"));
        Assert.Equal(Developers, ((SearchResultEntry)response.Entries[0]).Attributes["memberOf"][0]);

        admin.SendRequest(new DeleteRequest(renamed));
        Assert.Empty(_server.Directory.Find(Developers)!.GetStrings("member"));
    }
}
