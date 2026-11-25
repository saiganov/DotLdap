using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;

namespace DotLdap.Testing.Tests;

/// <summary>Test data from JSON: users and groups as the fluent helpers take them, and raw entries.</summary>
public class JsonLoadingTests
{
    private const string Sample = """
        {
          // comments and trailing commas are fine
          "users": [
            { "name": "alice", "password": "s3cret", "email": "alice@example.com", "displayName": "Alice A.",
              "firstName": "Alice", "lastName": "Archer", "groups": ["admins"],
              "attributes": { "title": "Engineer", "telephoneNumber": ["+1 555 0100", "+1 555 0101"], "uidNumber": 1000,
                              "jpegPhoto": { "base64": "/9j/AAEC" } } },
            { "name": "bob", "password": "hunter2", "disabled": true },
            { "name": "viewer", "password": "viewer-secret", "readOnly": true, "lockedOut": false },
          ],
          "groups": [ { "name": "staff", "members": ["alice", "admins"] }, { "name": "empty" } ],
          "entries": [
            { "dn": "ou=printers,dc=example,dc=com",
              "attributes": { "objectClass": ["top", "organizationalUnit"], "ou": "printers", "description": "Second floor" } },
            { "dn": "cn=laser,ou=printers,dc=example,dc=com",
              "attributes": { "objectClass": "device", "cn": "laser", "colour": false, "duplex": true, "weight": 12.50 } }
          ]
        }
        """;

    private static LdapConnection Connect(LdapTestServer server, string user, string password)
    {
        var connection = new LdapConnection(new LdapDirectoryIdentifier(server.Host, server.Port))
        {
            AuthType = AuthType.Basic,
            Credential = new NetworkCredential(user, password),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.Bind();
        return connection;
    }

    [Fact]
    public void A_generic_directory_is_filled_from_json()
    {
        using var server = LdapTestServer.Create().WithJson(Sample).Start();
        var directory = server.Directory;
        const string users = "ou=users,dc=example,dc=com";

        var alice = directory.Find("uid=alice," + users)!;
        Assert.Equal("alice@example.com", alice.GetString("mail"));
        Assert.Equal("Alice A.", alice.GetString("displayName"));
        Assert.Equal("Alice", alice.GetString("givenName"));
        Assert.Equal("Archer", alice.GetString("sn"));
        Assert.Equal("Engineer", alice.GetString("title"));
        Assert.Equal(["+1 555 0100", "+1 555 0101"], alice.GetStrings("telephoneNumber"));
        Assert.Equal("1000", alice.GetString("uidNumber"));
        Assert.Equal([0xFF, 0xD8, 0xFF, 0x00, 0x01, 0x02], alice.GetValues("jpegPhoto")[0]);

        // groups named by a user come into being; members are users or groups by name
        Assert.Equal(["uid=alice," + users], directory.Find("cn=admins,ou=groups,dc=example,dc=com")!.GetStrings("member"));
        Assert.Equal(["uid=alice," + users, "cn=admins,ou=groups,dc=example,dc=com"], directory.Find("cn=staff,ou=groups,dc=example,dc=com")!.GetStrings("member"));
        Assert.True(directory.Exists("cn=empty,ou=groups,dc=example,dc=com"));

        var printer = directory.Find("cn=laser,ou=printers,dc=example,dc=com")!;
        Assert.Equal("FALSE", printer.GetString("colour"));
        Assert.Equal("TRUE", printer.GetString("duplex"));
        Assert.Equal("12.50", printer.GetString("weight")); // a number stays as it was written
        Assert.Equal("Second floor", directory.Find("ou=printers,dc=example,dc=com")!.GetString("description"));

        // and it all works over the wire
        using var connection = Connect(server, "uid=alice," + users, "s3cret");
        var found = (SearchResponse)connection.SendRequest(new SearchRequest("dc=example,dc=com", "(memberOf=cn=admins,ou=groups,dc=example,dc=com)", SearchScope.Subtree, "uid"));
        Assert.Equal("alice", found.Entries[0].Attributes["uid"][0]);
        Assert.Throws<LdapException>(() => Connect(server, "uid=bob," + users, "hunter2")); // disabled
        Assert.True(directory.Find("uid=bob," + users)!.Has("pwdAccountLockedTime"));
        Assert.Equal("hunter2", directory.Find("uid=bob," + users)!.GetString("userPassword"));
        Assert.True(directory.IsReadOnly("uid=viewer," + users));
        using (Connect(server, "uid=viewer," + users, "viewer-secret")) // "lockedOut": false is no lockout
        {
        }
    }

    [Fact]
    public void The_same_file_fills_an_active_directory()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com")
            .WithJson(Sample.Replace("dc=example,dc=com", "DC=corp,DC=example,DC=com")).Start();
        var alice = server.Directory.Find("CN=alice,CN=Users,DC=corp,DC=example,DC=com")!;
        Assert.Equal("alice", alice.GetString("sAMAccountName"));
        Assert.Equal("alice@corp.example.com", alice.GetString("userPrincipalName"));
        Assert.True(alice.Has("objectSid"));
        Assert.Equal("514", server.Directory.Find("CN=bob,CN=Users,DC=corp,DC=example,DC=com")!.GetString("userAccountControl"));
        Assert.True(server.Directory.Find("CN=admins,CN=Users,DC=corp,DC=example,DC=com")!.Has("groupType"));

        using var connection = Connect(server, "alice@corp.example.com", "s3cret");
    }

    [Fact]
    public void Active_directory_account_states_come_from_flags()
    {
        const string json = """
            { "users": [
                { "name": "newbie", "password": "pw", "mustChangePassword": true },
                { "name": "gone", "password": "pw", "accountExpired": true },
                { "name": "stale", "password": "pw", "passwordExpired": true },
                { "name": "locked", "password": "pw", "lockedOut": true } ] }
            """;
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com").WithJson(json).Start();
        string Refusal(string user)
        {
            Assert.Throws<LdapException>(() => Connect(server, user + "@corp.example.com", "pw"));
            // Not Requests[^1]: the client closes the refused connection on its own time, and that unbind
            // (which has no result) can be recorded after this bind.
            return server.Last<Protocol.BindRequest>()!.Result!.Message;
        }
        Assert.Contains("data 773", Refusal("newbie"));
        Assert.Contains("data 701", Refusal("gone"));
        Assert.Contains("data 532", Refusal("stale"));
        Assert.Contains("data 775", Refusal("locked"));

        // a generic directory has no such states, and says where in the file one was asked for
        var error = Assert.Throws<FormatException>(() => LdapTestServer.Create().WithJson(json).Start());
        Assert.Equal("JSON data, $.users[0].mustChangePassword: this needs the Active Directory flavour.", error.Message);
    }

    [Fact]
    public void Json_adds_to_what_is_there_and_can_be_loaded_during_a_test()
    {
        using var server = LdapTestServer.Create()
            .WithUser("admin", "admin-secret")
            .WithJson("""{ "users": [ { "name": "alice", "password": "a" } ] }""")
            .WithJson("""{ "groups": [ { "name": "staff", "members": ["admin", "alice"] } ] }""")
            .Start();
        Assert.Equal(2, server.Directory.Find("cn=staff,ou=groups,dc=example,dc=com")!.GetValues("member").Count);

        Assert.Equal(2, server.Directory.AddJson("""{ "users": [ { "name": "carol", "password": "c" } ], "entries": [ { "dn": "ou=later,dc=example,dc=com" } ] }"""));
        Assert.True(server.Directory.Exists("uid=carol,ou=users,dc=example,dc=com"));
        Assert.True(server.Directory.Exists("ou=later,dc=example,dc=com"));
        Assert.Equal(0, server.Directory.AddJson("{}"));
    }

    [Fact]
    public void Json_comes_from_a_file_too()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dotldap-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, Sample, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        try
        {
            using var server = LdapTestServer.Create().WithJsonFile(path).Start();
            Assert.True(server.Directory.Exists("uid=alice,ou=users,dc=example,dc=com"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Property_names_are_read_whatever_their_case_and_attribute_names_are_kept()
    {
        var directory = new InMemoryDirectory();
        directory.AddJson("""{ "Users": [ { "Name": "alice", "PASSWORD": "a", "Attributes": { "employeeID": "7" } } ] }""");
        var alice = directory.Find("uid=alice,ou=users,dc=example,dc=com")!;
        Assert.Contains(alice.Attributes, a => a.Name == "employeeID");
    }

    [Theory]
    [InlineData("""not json""", "Invalid JSON")]
    [InlineData("""[]""", "$: an object with \"users\", \"groups\" and \"entries\" is expected")]
    [InlineData("""{ "user": [] }""", "$.user: unknown property; known here: users, groups, entries")]
    [InlineData("""{ "users": {} }""", "$.users: a list is expected")]
    [InlineData("""{ "users": [ "alice" ] }""", "$.users[0]: an object is expected")]
    [InlineData("""{ "users": [ { "password": "a" } ] }""", "$.users[0]: \"name\" is missing")]
    [InlineData("""{ "users": [ { "name": "alice" } ] }""", "$.users[0]: \"password\" is missing")]
    [InlineData("""{ "users": [ { "name": "", "password": "a" } ] }""", "$.users[0].name: the value is empty")]
    [InlineData("""{ "users": [ { "name": 7, "password": "a" } ] }""", "$.users[0].name: a string is expected")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "mail": "x" } ] }""", "$.users[0].mail: unknown property")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "name": "bob" } ] }""", "$.users[0].name: the property is given twice")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "Name": "bob" } ] }""", "$.users[0].Name: the property is given twice")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "disabled": "yes" } ] }""", "$.users[0].disabled: true or false is expected")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "groups": "admins" } ] }""", "$.users[0].groups: a list of names is expected")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "groups": [1] } ] }""", "$.users[0].groups[0]: a string is expected")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "attributes": [] } ] }""", "$.users[0].attributes: an object of attribute names and values is expected")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "attributes": { "x": null } } ] }""", "$.users[0].attributes.x: a string, a number, true, false or { \"base64\": \"...\" } is expected")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "attributes": { "x": ["a", ["b"]] } } ] }""", "$.users[0].attributes.x[1]: a string, a number")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "attributes": { "x": { "base64": "***" } } } ] }""", "$.users[0].attributes.x.base64: the value is not base64")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "attributes": { "x": { "hex": "00" } } } ] }""", "$.users[0].attributes.x.hex: unknown property; known here: base64")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "attributes": { "x": "1", "X": "2" } } ] }""", "$.users[0].attributes.X: the attribute is given twice")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "email": "" } ] }""", "$.users[0].email: the value is empty")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "groups": [""] } ] }""", "$.users[0].groups[0]: the value is empty")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "groups": ["ok", "cn=bad,,"] } ] }""", "$.users[0].groups[1]: 'cn=bad,,' is not a DN")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "passwordExpired": true } ] }""", "$.users[0].passwordExpired: this needs the Active Directory flavour")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "accountExpired": true } ] }""", "$.users[0].accountExpired: this needs the Active Directory flavour")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a" }, { "name": "ALICE", "password": "b" } ] }""", "$.users[1].name: 'uid=ALICE,ou=users,dc=example,dc=com' is given twice in this file")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "attributes": { "a b": "x" } } ] }""", "$.users[0].attributes.a b: this is not an attribute name")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "attributes": { "": "x" } } ] }""", "$.users[0].attributes.: this is not an attribute name")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "attributes": { "a=b": "x" } } ] }""", "$.users[0].attributes.a=b: this is not an attribute name")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "attributes": { ";binary": "x" } } ] }""", "$.users[0].attributes.;binary: this is not an attribute name")]
    [InlineData("""{ "users": [ { "name": "a=b", "password": "a" } ] }""", "$.users[0].name: a name cannot contain '='")]
    [InlineData("""{ "groups": [ { "name": "x=y" } ] }""", "$.groups[0].name: a name cannot contain '='")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a" } ], "entries": [ { "dn": "UID=alice, ou=users, dc=example, dc=com" } ] }""", "$.entries[0].dn: 'UID=alice,ou=users,dc=example,dc=com' is given twice in this file")]
    [InlineData("""{ "entries": [ { "dn": "cn=crew,ou=groups,dc=example,dc=com" } ], "groups": [ { "name": "crew" } ] }""", "$.entries[0].dn: 'cn=crew,ou=groups,dc=example,dc=com' is given twice in this file")]
    [InlineData("""{ "groups": [ { "name": "g" }, { "name": "G" } ] }""", "$.groups[1].name: 'cn=G,ou=groups,dc=example,dc=com' is given twice in this file")]
    [InlineData("""{ "groups": [ { "name": "g", "members": ["uid=x,,"] } ] }""", "$.groups[0].members[0]: 'uid=x,,' is not a DN")]
    [InlineData("""{ "groups": [ { "name": "g", "members": [""] } ] }""", "$.groups[0].members[0]: the value is empty")]
    [InlineData("""{ "entries": [ { "dn": "ou=a,dc=example,dc=com" }, { "dn": "OU=A, DC=example, DC=com" } ] }""", "$.entries[1].dn: 'OU=A,DC=example,DC=com' is given twice in this file")]
    [InlineData("""{ "users": null }""", "$.users: a list is expected")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a" }, { "name": "bob" } ] }""", "$.users[1]: \"password\" is missing")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a" } ], "groups": [ { "name": "g" } ], "entries": [ { "dn": "ou=a,dc=example,dc=com", "attributes": [] } ] }""", "$.entries[0].attributes: an object of attribute names and values is expected")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "email": 7 } ] }""", "$.users[0].email: a string is expected")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "email": null } ] }""", "$.users[0].email: a string is expected")]
    [InlineData("""{ "users": [ { "name": "alice", "password": "a", "disabled": null } ] }""", "$.users[0].disabled: true or false is expected")]
    [InlineData("""{ "groups": [ { "name": "" } ] }""", "$.groups[0].name: the value is empty")]
    [InlineData("""{ "groups": [ { "name": "g", "members": "alice" } ] }""", "$.groups[0].members: a list of names is expected")]
    [InlineData("""{ "entries": [ { "dn": "" } ] }""", "$.entries[0].dn: the value is empty")]
    [InlineData("""{ "entries": [ { "dn": " " } ] }""", "$.entries[0].dn: ' ' is not a DN")]
    [InlineData("""{ "groups": [ { "members": [] } ] }""", "$.groups[0]: \"name\" is missing")]
    [InlineData("""{ "groups": [ { "name": "g", "member": [] } ] }""", "$.groups[0].member: unknown property; known here: name, members")]
    [InlineData("""{ "entries": [ { "attributes": {} } ] }""", "$.entries[0]: \"dn\" is missing")]
    [InlineData("""{ "entries": [ { "dn": "not a dn,," } ] }""", "$.entries[0].dn: 'not a dn,,' is not a DN")]
    [InlineData("""{ "entries": [ { "dn": "ou=a,dc=example,dc=com" }, { "dn": "ou=b,dc=example,dc=com", "objectClass": "top" } ] }""", "$.entries[1].objectClass: unknown property; known here: dn, attributes")]
    public void A_mistake_in_the_file_is_named_with_its_place_and_nothing_is_added(string json, string expected)
    {
        var directory = new InMemoryDirectory();
        directory.AddUser("existing", "pw");
        var before = directory.Count;

        var error = Assert.Throws<FormatException>(() => directory.AddJson(json));
        Assert.Contains(expected, error.Message);
        Assert.Equal(before, directory.Count);
    }

    [Fact]
    public void What_the_directory_refuses_is_named_with_its_place()
    {
        var directory = new InMemoryDirectory();
        directory.AddUser("bob", "b");
        var error = Assert.Throws<FormatException>(() => directory.AddJson(
            """{ "users": [ { "name": "alice", "password": "a" }, { "name": "bob", "password": "b" } ] }"""));
        Assert.Equal("JSON data, $.users[1]: Entry 'uid=bob,ou=users,dc=example,dc=com' already exists.", error.Message);
        Assert.IsType<InvalidOperationException>(error.InnerException);
        // unlike a mistake in the file, this is found on the way: what came before it is there
        Assert.True(directory.Exists("uid=alice,ou=users,dc=example,dc=com"));

        error = Assert.Throws<FormatException>(() => directory.AddJson("""{ "groups": [ { "name": "team", "members": ["carol", "nobody"] } ], "users": [ { "name": "carol", "password": "c" } ] }"""));
        Assert.Equal("JSON data, $.groups[0].members[1]: There is no user or group named 'nobody'.", error.Message);
        error = Assert.Throws<FormatException>(() => directory.AddJson("""{ "users": [ { "name": "dave", "password": "d", "groups": ["cn=crew,ou=elsewhere,dc=example,dc=com"] } ] }"""));
        Assert.Equal("JSON data, $.users[0].groups[0]: Group 'cn=crew,ou=elsewhere,dc=example,dc=com' does not exist.", error.Message);
    }

    [Fact]
    public void No_text_at_all_is_an_argument_error()
    {
        Assert.Throws<ArgumentNullException>(() => new InMemoryDirectory().AddJson(null!));
    }

    [Fact]
    public void The_whole_message_of_a_mistake_is_as_documented_and_the_original_error_stays_attached()
    {
        var directory = new InMemoryDirectory();
        Assert.Equal("JSON data, $.users: a list is expected.", Assert.Throws<FormatException>(() => directory.AddJson("""{ "users": {} }""")).Message);
        Assert.IsAssignableFrom<System.Text.Json.JsonException>(Assert.Throws<FormatException>(() => directory.AddJson("not json")).InnerException);
    }

    [Fact]
    public void A_group_or_entry_the_directory_refuses_is_named_with_its_place()
    {
        var directory = new InMemoryDirectory();
        directory.AddGroup("staff");
        directory.Add("ou=a,dc=example,dc=com");
        var error = Assert.Throws<FormatException>(() => directory.AddJson("""{ "groups": [ { "name": "staff" } ] }"""));
        Assert.Equal("JSON data, $.groups[0]: Entry 'cn=staff,ou=groups,dc=example,dc=com' already exists.", error.Message);
        error = Assert.Throws<FormatException>(() => directory.AddJson("""{ "entries": [ { "dn": "OU=A,dc=example,dc=com" } ] }"""));
        Assert.Equal("JSON data, $.entries[0]: Entry 'OU=A,dc=example,dc=com' already exists.", error.Message);
    }

    [Fact]
    public void A_membership_stated_twice_is_kept_once()
    {
        var directory = new InMemoryDirectory();
        directory.AddJson("""
            { "users": [ { "name": "alice", "password": "a", "groups": ["staff", "staff", "CN=Staff , OU=Groups, DC=Example,DC=com", "fresh", "fresh"] } ],
              "groups": [ { "name": "staff", "members": ["alice", "alice", "uid=ALICE, ou=users,dc=example,dc=com", "staff"] } ] }
            """);
        const string alice = "uid=alice,ou=users,dc=example,dc=com";
        Assert.Equal([alice, "cn=staff,ou=groups,dc=example,dc=com"], directory.Find("cn=staff,ou=groups,dc=example,dc=com")!.GetStrings("member")); // a group may hold itself
        Assert.Equal([alice], directory.Find("cn=fresh,ou=groups,dc=example,dc=com")!.GetStrings("member"));

        // the same from code
        directory.AddToGroup("staff", alice);
        directory.AddUser("bob", "b", u => u.MemberOf("team", "team"));
        Assert.Equal(2, directory.Find("cn=staff,ou=groups,dc=example,dc=com")!.GetValues("member").Count);
        Assert.Single(directory.Find("cn=team,ou=groups,dc=example,dc=com")!.GetValues("member"));
    }

    [Fact]
    public void In_active_directory_a_user_and_a_group_of_one_name_are_the_same_entry()
    {
        var directory = new InMemoryDirectory(new DirectoryLayout { Flavor = DirectoryFlavor.ActiveDirectory });
        var before = directory.Count;
        var error = Assert.Throws<FormatException>(() => directory.AddJson(
            """{ "users": [ { "name": "x", "password": "p" }, { "name": "y", "password": "p" } ], "groups": [ { "name": "X" } ] }"""));
        Assert.Equal("JSON data, $.groups[0].name: 'CN=X,CN=Users,dc=example,dc=com' is given twice in this file.", error.Message);
        Assert.Equal(before, directory.Count);

        // a generic directory keeps them in different containers
        Assert.Equal(2, new InMemoryDirectory().AddJson("""{ "users": [ { "name": "x", "password": "p" } ], "groups": [ { "name": "x", "members": ["x"] } ] }"""));

        // and a user cannot be put into the group that would be the user itself
        var self = Assert.Throws<FormatException>(() => directory.AddJson("""{ "users": [ { "name": "z", "password": "p", "groups": ["z"] } ] }"""));
        Assert.Equal("JSON data, $.users[0].groups[0]: 'CN=z,CN=Users,dc=example,dc=com' cannot be a member of itself.", self.Message);
    }

    [Fact]
    public void A_group_that_cannot_be_filled_leaves_no_half_made_user()
    {
        var directory = new InMemoryDirectory();
        var error = Assert.Throws<InvalidOperationException>(() =>
            directory.AddUser("alice", "a", u => u.MemberOf("ok", "cn=nope,ou=x,dc=example,dc=com", "later").ReadOnly()));
        Assert.Equal("Group 'cn=nope,ou=x,dc=example,dc=com' does not exist.", error.Message);
        Assert.Equal(0, directory.Count);

        // the DN the helpers would use themselves is as good as the name, however it is spelled; any other must exist
        directory.AddUser("alice", "a", u => u.MemberOf("CN=Crew, OU=Groups, DC=example, DC=com"));
        Assert.Equal(["uid=alice,ou=users,dc=example,dc=com"], directory.Find("cn=crew,ou=groups,dc=example,dc=com")!.GetStrings("member"));
        directory.Add("cn=far,ou=x,dc=example,dc=com", e => e.Set("objectClass", "groupOfNames"));
        directory.AddUser("bob", "b", u => u.MemberOf("cn=far,ou=x,dc=example,dc=com"));
        Assert.Equal(["uid=bob,ou=users,dc=example,dc=com"], directory.Find("cn=far,ou=x,dc=example,dc=com")!.GetStrings("member"));
    }

    [Fact]
    public void Attribute_names_follow_ldif()
    {
        var directory = new InMemoryDirectory();
        directory.AddJson("""
            { "entries": [ { "dn": "cn=thing,dc=example,dc=com", "attributes": {
                "description;lang-en": "English", "description;lang-de": ["Deutsch"], "my_attr": "x", "2.5.4.13.1": "y", "userCertificate;binary": { "base64": "AAEC" } } } ] }
            """);
        var thing = directory.Find("cn=thing,dc=example,dc=com")!;
        Assert.Equal(["English", "Deutsch"], thing.GetStrings("description")); // options are dropped, the values stay together
        Assert.Equal("x", thing.GetString("my_attr"));
        Assert.Equal("y", thing.GetString("2.5.4.13.1"));
        Assert.True(thing.Has("userCertificate"));
    }

    [Fact]
    public void Values_are_stored_as_they_are_written()
    {
        var directory = new InMemoryDirectory();
        directory.AddJson("""{ "users": [ { "name": "alice", "password": " ", "attributes": { "roomNumber": 1e3, "sn": "Archer" } } ] }""");
        var alice = directory.Find("uid=alice,ou=users,dc=example,dc=com")!;
        Assert.Equal("1e3", alice.GetString("roomNumber"));
        Assert.Equal(" ", alice.GetString("userPassword"));
        Assert.Equal(["Archer"], alice.GetStrings("sn")); // in place of the name the helper puts there, not next to it
    }

    [Fact]
    public void A_file_without_a_byte_order_mark_is_read_as_utf8()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dotldap-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, """{ "users": [ { "name": "zoe", "password": "z", "displayName": "Zoë" } ] }""", new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        try
        {
            using var server = LdapTestServer.Create().WithJsonFile(path).Start();
            Assert.Equal("Zoë", server.Directory.Find("uid=zoe,ou=users,dc=example,dc=com")!.GetString("displayName"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void The_order_within_the_file_is_free()
    {
        // A group named by a user and listed itself, nested groups before the groups they hold, members that
        // are defined further down, a group that is a raw entry: memberships are filled in when everything is there.
        var directory = new InMemoryDirectory();
        Assert.Equal(6, directory.AddJson("""
            {
              "groups": [ { "name": "all", "members": ["staff", "alice", "cn=svc,ou=services,dc=example,dc=com", "cn=ghost,dc=example,dc=com"] },
                          { "name": "staff", "members": ["bob"] },
                          { "name": "admins" } ],
              "users": [ { "name": "alice", "password": "a", "groups": ["admins", "raw", "cn=staff,ou=groups,dc=example,dc=com", "fresh"] },
                         { "name": "bob", "password": "b" } ],
              "entries": [ { "dn": "cn=raw,ou=groups,dc=example,dc=com", "attributes": { "objectClass": ["top", "groupOfNames"], "cn": "raw" } } ]
            }
            """));
        const string users = "ou=users,dc=example,dc=com", groups = "ou=groups,dc=example,dc=com";
        Assert.Equal([$"cn=staff,{groups}", $"uid=alice,{users}", "cn=svc,ou=services,dc=example,dc=com", "cn=ghost,dc=example,dc=com"],
            directory.Find($"cn=all,{groups}")!.GetStrings("member")); // a DN is taken as it is, there or not
        Assert.Equal([$"uid=alice,{users}", $"uid=bob,{users}"], directory.Find($"cn=staff,{groups}")!.GetStrings("member"));
        Assert.Equal([$"uid=alice,{users}"], directory.Find($"cn=admins,{groups}")!.GetStrings("member"));
        Assert.Equal([$"uid=alice,{users}"], directory.Find($"cn=raw,{groups}")!.GetStrings("member"));
        Assert.Equal([$"uid=alice,{users}"], directory.Find($"cn=fresh,{groups}")!.GetStrings("member")); // made on the spot, as MemberOf does
    }

    [Fact]
    public void Attributes_come_after_the_named_properties_and_flags_last()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com").WithJson("""
            { "users": [ { "name": "alice", "password": "a", "email": "first@corp.example.com", "lastName": "First", "disabled": true, "mustChangePassword": true,
                           "attributes": { "mail": "second@corp.example.com", "sn": [], "userAccountControl": 66048, "pwdLastSet": "133000000000000000",
                                           "userCertificate;binary": { "base64": "AAEC" }, "2.5.4.13": "by number" } } ] }
            """).Start();
        var alice = server.Directory.Find("CN=alice,CN=Users,DC=corp,DC=example,DC=com")!;
        Assert.Equal("second@corp.example.com", alice.GetString("mail"));
        Assert.False(alice.Has("sn")); // an empty list takes the attribute away
        Assert.Equal("66050", alice.GetString("userAccountControl")); // the flag is added to what the attribute said
        Assert.Equal("0", alice.GetString("pwdLastSet"));
        Assert.Equal([0, 1, 2], alice.GetValues("userCertificate")[0]); // the option is dropped, as in LDIF
        Assert.Equal("by number", alice.GetString("2.5.4.13"));
    }

    [Fact]
    public void A_mistake_in_a_file_is_reported_with_the_name_of_the_file()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dotldap-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, """{ "users": [ { "name": "alice" } ] }""");
        try
        {
            var error = Assert.Throws<FormatException>(() => LdapTestServer.Create().WithJsonFile(path).Start());
            Assert.Equal($"{path}: JSON data, $.users[0]: \"password\" is missing.", error.Message);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Text_that_is_not_unicode_is_a_format_error_too()
    {
        var directory = new InMemoryDirectory();
        string[] broken =
        [
            """{ "users": [ { "name": "\ud800", "password": "a" } ] }""",
            """{ "users": [ { "name": "alice", "password": "a", "attributes": { "x": "\ud800" } } ] }""",
            """{ "users": [ { "na\ud800me": "alice", "password": "a" } ] }""",
            "{ \"users\": [ { \"name\": \"a\ud800\", \"password\": \"a\" } ] }",
        ];
        foreach (var json in broken)
        {
            var error = Assert.Throws<FormatException>(() => directory.AddJson(json));
            Assert.StartsWith("Invalid JSON: ", error.Message);
        }
        Assert.Equal(0, directory.Count);

        // the error System.Text.Json raised stays attached
        Assert.IsType<InvalidOperationException>(Assert.Throws<FormatException>(() => directory.AddJson(broken[0])).InnerException);
    }

    [Fact]
    public void A_byte_order_mark_in_the_text_and_an_empty_password_are_taken()
    {
        var directory = new InMemoryDirectory();
        Assert.Equal(1, directory.AddJson("\uFEFF{ \"users\": [ { \"name\": \"alice\", \"password\": \"\" } ] }")); // as AddUser takes it
        Assert.Equal("", directory.Find("uid=alice,ou=users,dc=example,dc=com")!.GetString("userPassword"));
    }

    [Fact]
    public void A_user_and_a_group_may_share_a_name_and_the_name_means_the_user()
    {
        var directory = new InMemoryDirectory();
        Assert.Equal(2, directory.AddJson("""{ "users": [ { "name": "ops", "password": "o" } ], "groups": [ { "name": "ops", "members": ["ops"] } ] }"""));
        Assert.Equal(["uid=ops,ou=users,dc=example,dc=com"], directory.Find("cn=ops,ou=groups,dc=example,dc=com")!.GetStrings("member"));
    }

    [Fact]
    public void A_generic_directory_takes_a_lockout_and_active_directory_flags_that_are_false()
    {
        var directory = new InMemoryDirectory();
        directory.AddJson("""
            { "users": [ { "name": "locked", "password": "pw", "lockedOut": true },
                         { "name": "plain", "password": "pw", "mustChangePassword": false, "accountExpired": false, "passwordExpired": false } ] }
            """);
        Assert.True(directory.Find("uid=locked,ou=users,dc=example,dc=com")!.Has("pwdAccountLockedTime"));
        Assert.True(directory.Exists("uid=plain,ou=users,dc=example,dc=com"));
    }

    [Fact]
    public void A_group_of_a_user_that_is_refused_is_named_by_its_index()
    {
        var directory = new InMemoryDirectory();
        var error = Assert.Throws<FormatException>(() => directory.AddJson(
            """{ "users": [ { "name": "dave", "password": "d", "groups": ["crew", "cn=crew,ou=elsewhere,dc=example,dc=com"] } ] }"""));
        Assert.Equal("JSON data, $.users[0].groups[1]: Group 'cn=crew,ou=elsewhere,dc=example,dc=com' does not exist.", error.Message);
    }

    [Fact]
    public void A_mistake_in_a_file_keeps_the_original_error()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dotldap-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, "not json");
        try
        {
            var error = Assert.Throws<FormatException>(() => LdapTestServer.Create().WithJsonFile(path).Start());
            Assert.StartsWith($"{path}: Invalid JSON: ", error.Message);
            Assert.IsAssignableFrom<System.Text.Json.JsonException>(error.InnerException!.InnerException);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void An_entry_without_attributes_and_an_empty_binary_value_are_taken()
    {
        var directory = new InMemoryDirectory();
        directory.AddJson("""{ "entries": [ { "dn": "ou=bare,dc=example,dc=com" }, { "dn": "ou=odd,dc=example,dc=com", "attributes": { "blob": { "base64": "" }, "none": [] } } ] }""");
        Assert.Empty(directory.Find("ou=bare,dc=example,dc=com")!.Attributes);
        var odd = directory.Find("ou=odd,dc=example,dc=com")!;
        Assert.Empty(odd.GetValues("blob")[0]);
        Assert.False(odd.Has("none")); // an empty list is no attribute
    }
}
