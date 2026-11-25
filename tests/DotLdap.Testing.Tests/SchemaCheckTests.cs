using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;

namespace DotLdap.Testing.Tests;

/// <summary>The strict mode: writes that break the published schema are refused. Off unless a test turns it on.</summary>
public class SchemaCheckTests
{
    private const string Users = "ou=users,dc=example,dc=com";
    private const string AliceDn = "uid=alice," + Users;
    private const string AdUsers = "CN=Users,DC=corp,DC=example,DC=com";
    private const string AdAlice = "CN=alice," + AdUsers;

    private static LdapTestServerBuilder Generic() => LdapTestServer.Create()
        .WithUser("admin", "admin-secret")
        .WithUser("alice", "alice-secret", u => u.Attribute("uidNumber", "1000"))
        .WithGroup("staff", "alice");

    private static LdapTestServerBuilder Ad() => LdapTestServer.Create()
        .AsActiveDirectory()
        .WithBaseDn("DC=corp,DC=example,DC=com")
        .WithUser("admin", "admin-secret")
        .WithUser("alice", "alice-secret", u => u.Email("alice@corp.example.com"));

    private static LdapConnection Connect(LdapTestServer server)
    {
        var ad = server.Directory.Layout.IsActiveDirectory;
        var connection = new LdapConnection(new LdapDirectoryIdentifier(server.Host, server.Port))
        {
            AuthType = AuthType.Basic,
            Credential = new NetworkCredential(ad ? "admin@corp.example.com" : "uid=admin," + Users, "admin-secret"),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.Bind();
        return connection;
    }

    private static ResultCode Fails(LdapConnection connection, DirectoryRequest request) =>
        Assert.Throws<DirectoryOperationException>(() => connection.SendRequest(request)).Response.ResultCode;

    private static ModifyRequest Change(string dn, DirectoryAttributeOperation operation, string name, params string[] values) =>
        new(dn, operation, name, values);

    // Not Requests[^1]: the unbind of a connection closed earlier has no result and is recorded whenever the server gets to it.
    private static string LastMessage(LdapTestServer server) => server.LastAnswer!.Result!.Message;

    [Fact]
    public void Without_the_option_nothing_is_checked()
    {
        using var server = Generic().Start();
        Assert.False(server.Directory.SchemaChecks);
        using var admin = Connect(server);
        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Replace, "uidNumber", "not a number", "2"));
        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Replace, "manager", "nobody in particular"));
        Assert.Equal(["not a number", "2"], server.Directory.Find(AliceDn)!.GetStrings("uidNumber"));
    }

    [Fact]
    public void A_single_valued_attribute_takes_one_value()
    {
        using var server = Generic().WithSchemaChecks().Start();
        using var admin = Connect(server);

        // a second value next to the first, two at once, two by replace
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, Change(AliceDn, DirectoryAttributeOperation.Add, "uidNumber", "1001")));
        Assert.Equal("uidNumber: attribute cannot have multiple values", LastMessage(server));
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, Change(AliceDn, DirectoryAttributeOperation.Replace, "UIDNUMBER", "1", "2")));
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, Change(AliceDn, DirectoryAttributeOperation.Add, "displayName", "A", "B")));
        Assert.Equal(["1000"], server.Directory.Find(AliceDn)!.GetStrings("uidNumber"));
        Assert.False(server.Directory.Find(AliceDn)!.Has("displayName"));

        // one value is fine, however it gets there
        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Replace, "uidNumber", "1001"));
        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Add, "displayName", "Alice"));
        // "add the new one, delete the old one" in one request leaves one value: judged by the outcome
        var swap = new ModifyRequest(AliceDn,
            new DirectoryAttributeModification { Name = "uidNumber", Operation = DirectoryAttributeOperation.Add },
            new DirectoryAttributeModification { Name = "uidNumber", Operation = DirectoryAttributeOperation.Delete });
        swap.Modifications[0].Add("1002");
        swap.Modifications[1].Add("1001");
        admin.SendRequest(swap);
        Assert.Equal(["1002"], server.Directory.Find(AliceDn)!.GetStrings("uidNumber"));

        // an attribute that may have several still takes several
        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Add, "mail", "a@example.com", "b@example.com"));
    }

    [Theory]
    [InlineData("uidNumber", "12a")]
    [InlineData("uidNumber", "")]
    [InlineData("uidNumber", "007")]
    [InlineData("uidNumber", "+7")]
    [InlineData("uidNumber", " 7")]
    [InlineData("uidNumber", "7\n")]
    [InlineData("uidNumber", "\u0661\u0662")] // digits, but not the ten a number is written with
    [InlineData("pwdAccountLockedTime", "20240101120000Z\n")]
    [InlineData("manager", "nobody in particular")]
    [InlineData("member", "uid=alice,,dc=example")]
    [InlineData("mail", "älice@example.com")] // IA5: ASCII only
    [InlineData("cn", "")]
    [InlineData("pwdAccountLockedTime", "yesterday")]
    [InlineData("pwdAccountLockedTime", "20241301000000Z")] // month 13
    [InlineData("pwdAccountLockedTime", "20240101")]
    [InlineData("pwdAccountLockedTime", "20240101120000")] // no time zone
    [InlineData("internationalISDNNumber", "12-34")]
    [InlineData("serialNumber", "a_b")]
    [InlineData("objectClass", "no such thing!")]
    [InlineData("objectClass", "2.5.6.6\n")]
    public void A_value_must_fit_the_syntax_of_its_attribute(string attribute, string value)
    {
        using var server = Generic().WithSchemaChecks().Start();
        using var admin = Connect(server);
        var target = attribute == "member" ? "cn=staff,ou=groups,dc=example,dc=com" : AliceDn;
        var before = server.Directory.Find(target)!.GetStrings(attribute);

        var replace = new ModifyRequest(target, new DirectoryAttributeModification { Name = attribute, Operation = DirectoryAttributeOperation.Replace });
        replace.Modifications[0].Add(Encoding.UTF8.GetBytes(value));
        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, replace));
        Assert.EndsWith(": value #0 invalid per syntax", LastMessage(server));
        Assert.StartsWith(attribute, LastMessage(server), StringComparison.OrdinalIgnoreCase);

        var add = new ModifyRequest(target, new DirectoryAttributeModification { Name = attribute, Operation = DirectoryAttributeOperation.Add });
        add.Modifications[0].Add(Encoding.UTF8.GetBytes(value));
        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, add));
        Assert.Equal(before, server.Directory.Find(target)!.GetStrings(attribute));
    }

    [Theory]
    [InlineData("uidNumber", "0")]
    [InlineData("uidNumber", "-12")]
    [InlineData("uidNumber", "123456789012345678901234567890")] // no size limit outside Active Directory
    [InlineData("manager", "uid=admin,ou=users,dc=example,dc=com")]
    [InlineData("manager", "")] // the empty DN is a DN
    [InlineData("mail", "alice+tag@example.com")]
    [InlineData("pwdAccountLockedTime", "20240229120000Z")]
    [InlineData("pwdAccountLockedTime", "2024022912Z")]
    [InlineData("pwdAccountLockedTime", "20240229120000.123+0100")]
    [InlineData("internationalISDNNumber", "12 34")]
    [InlineData("serialNumber", "AB-12 (c)")]
    [InlineData("description", "äöü €")]
    [InlineData("jpegPhoto", "\u0001\u0002")]
    public void A_value_that_fits_is_taken(string attribute, string value)
    {
        using var server = Generic().WithSchemaChecks().Start();
        using var admin = Connect(server);
        var replace = new ModifyRequest(AliceDn, new DirectoryAttributeModification { Name = attribute, Operation = DirectoryAttributeOperation.Replace });
        replace.Modifications[0].Add(Encoding.UTF8.GetBytes(value));
        admin.SendRequest(replace);
        Assert.Equal(value, server.Directory.Find(AliceDn)!.GetString(attribute));
    }

    [Fact]
    public void Binary_attributes_take_any_bytes_and_text_attributes_do_not()
    {
        using var server = Generic().WithSchemaChecks().Start();
        using var admin = Connect(server);
        byte[] notText = [0xFF, 0xFE, 0x00, 0x80];

        var photo = new ModifyRequest(AliceDn, new DirectoryAttributeModification { Name = "jpegPhoto", Operation = DirectoryAttributeOperation.Replace });
        photo.Modifications[0].Add(notText);
        admin.SendRequest(photo);

        var description = new ModifyRequest(AliceDn, new DirectoryAttributeModification { Name = "description", Operation = DirectoryAttributeOperation.Replace });
        description.Modifications[0].Add(notText);
        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, description));
    }

    [Fact]
    public void The_message_names_the_value_that_does_not_fit()
    {
        using var server = Generic().WithSchemaChecks().Start();
        using var admin = Connect(server);
        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, Change("cn=staff,ou=groups,dc=example,dc=com", DirectoryAttributeOperation.Add, "member",
            "uid=admin," + Users, "uid=bob," + Users, "not a dn,,")));
        Assert.Equal("member: value #2 invalid per syntax", LastMessage(server));
    }

    [Fact]
    public void Unknown_attributes_take_anything_and_declared_ones_are_checked()
    {
        using var server = Generic().WithSchemaChecks()
            .Configure(d => d.DefineAttribute("badgeNumber", AttributeSyntax.Integer, singleValued: true)
                .DefineAttribute("nickname")) // listed only: nothing is known about it
            .Start();
        using var admin = Connect(server);

        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Add, "shoeSize", "big", "very big"));
        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Add, "nickname", "Al", "Ally"));

        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, Change(AliceDn, DirectoryAttributeOperation.Add, "badgeNumber", "seven")));
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, Change(AliceDn, DirectoryAttributeOperation.Add, "badgeNumber", "7", "8")));
        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Add, "badgeNumber", "7"));

        // a declaration replaces what the server knows about a well-known name
        server.Directory.DefineAttribute("uidNumber", AttributeSyntax.DirectoryString);
        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Replace, "uidNumber", "one thousand", "or so"));
    }

    [Fact]
    public void Only_what_a_request_writes_is_checked()
    {
        // Data loaded by the test may be as wrong as the test needs it.
        using var server = Generic().WithSchemaChecks()
            .WithEntry("uid=odd," + Users, e => e.Set("objectClass", "inetOrgPerson").Set("uid", "odd").Set("cn", "odd").Set("sn", "odd")
                .Set("uidNumber", "one", "two").Set("manager", "nobody"))
            .Start();
        const string odd = "uid=odd," + Users;
        using var admin = Connect(server);

        admin.SendRequest(Change(odd, DirectoryAttributeOperation.Replace, "description", "still odd"));
        admin.SendRequest(new ModifyDNRequest(odd, Users, "uid=odder"));
        // deleting one of the wrong values is a step in the right direction; adding to them is not
        admin.SendRequest(Change("uid=odder," + Users, DirectoryAttributeOperation.Delete, "uidNumber", "two"));
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, Change("uid=odder," + Users, DirectoryAttributeOperation.Add, "uidNumber", "3")));

        // the seeding API is not held to the schema either
        server.Directory.Update(AliceDn, e => e.Set("uidNumber", "x", "y"));
        server.Directory.AddLdif("dn: uid=ldif," + Users + "\nobjectClass: inetOrgPerson\nuid: ldif\ncn: ldif\nsn: ldif\nuidNumber: many\nuidNumber: more\n");
        Assert.Equal(2, server.Directory.Find("uid=ldif," + Users)!.GetValues("uidNumber").Count);
    }

    [Fact]
    public void A_new_entry_is_checked_as_a_whole()
    {
        using var server = Generic().WithSchemaChecks().Start();
        using var admin = Connect(server);
        AddRequest Carol(params DirectoryAttribute[] more) => new("uid=carol," + Users,
            [new DirectoryAttribute("objectClass", "top", "person", "inetOrgPerson"), new DirectoryAttribute("cn", "Carol"), new DirectoryAttribute("sn", "Example"), .. more]);

        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, Carol(new DirectoryAttribute("uidNumber", "abc"))));
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, Carol(new DirectoryAttribute("uidNumber", "1", "2"))));
        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, Carol(new DirectoryAttribute("manager", "the boss"))));
        Assert.False(server.Directory.Exists("uid=carol," + Users));

        admin.SendRequest(Carol(new DirectoryAttribute("uidNumber", "1001"), new DirectoryAttribute("manager", AliceDn)));
        Assert.True(server.Directory.Exists("uid=carol," + Users));
    }

    [Fact]
    public void A_rename_is_checked_for_what_it_writes_into_the_entry()
    {
        using var server = Generic().WithSchemaChecks().Start();
        using var admin = Connect(server);

        // keeping the old name next to the new one gives a single-valued attribute two values
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, new ModifyDNRequest(AliceDn, Users, "uidNumber=5") { DeleteOldRdn = false }));
        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, new ModifyDNRequest(AliceDn, Users, "uidNumber=five")));
        Assert.True(server.Directory.Exists(AliceDn));

        // the value that is there already, or one that takes the place of the old one, is fine
        admin.SendRequest(new ModifyDNRequest(AliceDn, Users, "uidNumber=1000") { DeleteOldRdn = false });
        admin.SendRequest(new ModifyDNRequest("uidNumber=1000," + Users, Users, "uidNumber=5") { DeleteOldRdn = true });
        Assert.Equal(["5"], server.Directory.Find("uidNumber=5," + Users)!.GetStrings("uidNumber"));
        // uid may have several values, so the old name may stay
        admin.SendRequest(new ModifyDNRequest("uidNumber=5," + Users, Users, "uid=alicia") { DeleteOldRdn = false });
        Assert.Equal(["alice", "alicia"], server.Directory.Find("uid=alicia," + Users)!.GetStrings("uid"));

        // seed code may do what a client may not
        server.Directory.Move("uid=alicia," + Users, "uidNumber=five," + Users);
    }

    [Fact]
    public void The_checks_can_be_turned_on_and_off_during_a_test()
    {
        using var server = Generic().Start();
        using var admin = Connect(server);
        server.Directory.SchemaChecks = true;
        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, Change(AliceDn, DirectoryAttributeOperation.Replace, "uidNumber", "x")));
        server.Directory.SchemaChecks = false;
        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Replace, "uidNumber", "x"));

        using var off = Generic().WithSchemaChecks().WithSchemaChecks(false).Start();
        Assert.False(off.Directory.SchemaChecks);
    }

    // ---- Active Directory flavour ----------------------------------------------------------------------------

    [Fact]
    public void Active_directory_answers_with_its_own_codes_and_messages()
    {
        using var server = Ad().WithSchemaChecks().Start();
        using var admin = Connect(server);

        // mail has one value in Active Directory, whether a second one is added next to it or two come at once
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, Change(AdAlice, DirectoryAttributeOperation.Add, "mail", "second@corp.example.com")));
        Assert.Equal("00002081: AtrErr: DSID-03151D9D, #1:\n\t0: 00002081: DSID-03151D9D, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 0 (mail)", LastMessage(server));
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, Change(AdAlice, DirectoryAttributeOperation.Replace, "mail", "a@corp.example.com", "b@corp.example.com")));
        Assert.Equal("00002081: AtrErr: DSID-03151D9D, #1:\n\t0: 00002081: DSID-03151D9D, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 0 (mail)", LastMessage(server));
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, Change(AdAlice, DirectoryAttributeOperation.Add, "title", "a", "b")));

        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, Change(AdAlice, DirectoryAttributeOperation.Replace, "userAccountControl", "enabled")));
        Assert.Equal("00000057: LdapErr: DSID-0C090D8A, comment: Error in attribute conversion operation, data 0, v2580", LastMessage(server));
        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, Change(AdAlice, DirectoryAttributeOperation.Replace, "manager", "the boss")));
        Assert.Equal(["alice@corp.example.com"], server.Directory.Find(AdAlice)!.GetStrings("mail"));
        Assert.Equal("512", server.Directory.Find(AdAlice)!.GetString("userAccountControl"));
    }

    [Theory]
    [InlineData("userAccountControl", "2147483647", true)]
    [InlineData("userAccountControl", "2147483648", false)] // 32 bits
    [InlineData("userAccountControl", "-2147483648", true)]
    [InlineData("accountExpires", "9223372036854775807", true)]
    [InlineData("accountExpires", "9223372036854775808", false)] // 64 bits
    [InlineData("accountExpires", "-9223372036854775809", false)]
    [InlineData("showInAdvancedViewOnly", "TRUE", true)]
    [InlineData("showInAdvancedViewOnly", "true", false)]
    [InlineData("showInAdvancedViewOnly", "1", false)]
    [InlineData("otherWellKnownObjects", "B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=corp,DC=example,DC=com", true)]
    [InlineData("otherWellKnownObjects", "B:32:A9D1CA15768811D1ADED00C04FD8D5:CN=Users,DC=corp,DC=example,DC=com", false)] // 30 digits, 32 announced
    [InlineData("otherWellKnownObjects", "B:4:XYZ!:CN=Users,DC=corp,DC=example,DC=com", false)]
    [InlineData("otherWellKnownObjects", "B:4:ABCD:not a dn,,", false)]
    [InlineData("otherWellKnownObjects", "S:4:ABCD:CN=Users,DC=corp,DC=example,DC=com", false)]
    [InlineData("otherWellKnownObjects", "CN=Users,DC=corp,DC=example,DC=com", false)]
    [InlineData("legacyExchangeDN", "/o=Corp/ou=First/cn=Recipients/cn=alice", true)]
    [InlineData("displayNamePrintable", "Alice (A.)", true)]
    [InlineData("displayNamePrintable", "Älice", false)]
    public void Active_directory_values_are_held_to_its_own_rules(string attribute, string value, bool fits)
    {
        using var server = Ad().WithSchemaChecks().Start();
        using var admin = Connect(server);
        var request = Change(AdAlice, DirectoryAttributeOperation.Replace, attribute, value);
        if (fits) admin.SendRequest(request);
        else Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, request));
        Assert.Equal(fits, server.Directory.Find(AdAlice)!.GetString(attribute) == value);
    }

    [Fact]
    public void Active_directory_writes_of_its_own_kind_still_work_with_checks_on()
    {
        using var server = Ad().WithSchemaChecks().Start();
        using var admin = Connect(server);

        // a new user with a password, the way applications create one
        var add = new AddRequest("CN=carol," + AdUsers,
            new DirectoryAttribute("objectClass", "top", "person", "organizationalPerson", "user"),
            new DirectoryAttribute("sAMAccountName", "carol"),
            new DirectoryAttribute("userAccountControl", "512"));
        add.Attributes.Add(new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes("\"Carol-secret1\"")));
        admin.SendRequest(add);
        Assert.True(server.Directory.Find("CN=carol," + AdUsers)!.Has("objectGUID")); // what the server adds itself is not held against the schema

        var reset = new ModifyRequest("CN=carol," + AdUsers, new DirectoryAttributeModification { Name = "unicodePwd", Operation = DirectoryAttributeOperation.Replace });
        reset.Modifications[0].Add(Encoding.Unicode.GetBytes("\"Carol-secret2\""));
        admin.SendRequest(reset);
        admin.SendRequest(Change("CN=carol," + AdUsers, DirectoryAttributeOperation.Replace, "pwdLastSet", "0"));
        admin.SendRequest(Change("CN=carol," + AdUsers, DirectoryAttributeOperation.Replace, "pwdLastSet", "-1"));
        admin.SendRequest(new ModifyDNRequest("CN=carol," + AdUsers, AdUsers, "CN=caroline"));
        Assert.Equal(["caroline"], server.Directory.Find("CN=caroline," + AdUsers)!.GetStrings("cn"));

        // cn has one value: a name that differs from the one in the DN cannot be added next to it
        Assert.Equal(ResultCode.ConstraintViolation, Fails(admin, new AddRequest("CN=dave," + AdUsers,
            new DirectoryAttribute("objectClass", "top", "person", "organizationalPerson", "user"), new DirectoryAttribute("cn", "David"))));
    }

    [Fact]
    public void A_generic_directory_reads_active_directory_syntaxes_as_what_it_publishes()
    {
        using var server = Generic().WithSchemaChecks().Start();
        using var admin = Connect(server);
        // a large integer is an integer of any size, a DN with a binary part a string
        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Replace, "accountExpires", "9223372036854775808"));
        admin.SendRequest(Change(AliceDn, DirectoryAttributeOperation.Replace, "otherWellKnownObjects", "anything"));
        Assert.Equal(ResultCode.InvalidAttributeSyntax, Fails(admin, Change(AliceDn, DirectoryAttributeOperation.Replace, "accountExpires", "never")));
    }
}
