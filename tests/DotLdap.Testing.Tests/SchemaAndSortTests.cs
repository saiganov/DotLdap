using System.DirectoryServices.Protocols;
using System.Net;
using DotLdap.Testing.Protocol;
using DotLdap.Testing.Tests.Fuzzing;
using ResultCode = DotLdap.Testing.Protocol.ResultCode;
using SdsSearchRequest = System.DirectoryServices.Protocols.SearchRequest;
using SdsSearchScope = System.DirectoryServices.Protocols.SearchScope;
using SdsLdapConnection = System.DirectoryServices.Protocols.LdapConnection;

namespace DotLdap.Testing.Tests;

/// <summary>
/// What ADSI (System.DirectoryServices) needs from a server besides the basics: a published schema, server-side
/// sorting and an answer to the NTLM bind. ADSI itself runs on Windows only; these tests check the same server
/// features through System.DirectoryServices.Protocols and over a raw socket, on every platform.
/// </summary>
public class SchemaAndSortTests
{
    private const string AdBase = "DC=corp,DC=example,DC=com";

    private static LdapTestServerBuilder ActiveDirectory() => LdapTestServer.Create()
        .AsActiveDirectory()
        .WithBaseDn(AdBase)
        .WithUser("admin", "admin-secret")
        .WithUser("alice", "alice-secret", u => u.Email("alice@corp.example.com"))
        .WithUser("Bob", "bob-secret")
        .WithUser("carol", "carol-secret");

    private static LdapTestServerBuilder Generic() => LdapTestServer.Create()
        .WithUser("admin", "admin-secret")
        .WithUser("alice", "alice-secret");

    private static SdsLdapConnection Connect(LdapTestServer server, bool bind = true)
    {
        var admin = server.Directory.UserDn("admin").ToString();
        var connection = new SdsLdapConnection(new LdapDirectoryIdentifier(server.Host, server.Port))
        {
            AuthType = bind ? AuthType.Basic : AuthType.Anonymous,
            Credential = bind ? new NetworkCredential(admin, "admin-secret") : null,
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.Bind();
        return connection;
    }

    private static SearchResultEntry ReadSchema(LdapTestServer server, SdsLdapConnection connection, params string[] attributes)
    {
        var rootDse = (SearchResponse)connection.SendRequest(new SdsSearchRequest("", "(objectClass=*)", SdsSearchScope.Base, "subschemaSubentry"));
        var dn = (string)rootDse.Entries[0].Attributes["subschemaSubentry"][0];
        Assert.Equal(server.Directory.SubschemaDn.ToString(), dn);
        var response = (SearchResponse)connection.SendRequest(new SdsSearchRequest(dn, "(objectClass=subschema)", SdsSearchScope.Base, attributes));
        return Assert.Single(response.Entries.Cast<SearchResultEntry>());
    }

    private static string[] Values(SearchResultEntry entry, string attribute) =>
        entry.Attributes[attribute].GetValues(typeof(string)).Cast<string>().ToArray();

    // ---- schema ----------------------------------------------------------------------------------------------

    [Fact]
    public void Active_Directory_publishes_its_attributes_the_way_a_domain_controller_writes_them()
    {
        using var server = ActiveDirectory().Start();
        using var connection = Connect(server);

        var schema = ReadSchema(server, connection, "attributeTypes", "objectClasses", "modifyTimeStamp");

        Assert.StartsWith("CN=Aggregate-", schema.DistinguishedName);
        Assert.EndsWith(",CN=Schema,CN=Configuration," + AdBase, schema.DistinguishedName);
        var types = Values(schema, "attributeTypes");
        Assert.Contains("( 2.5.4.3 NAME 'cn' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )", types);
        Assert.Contains("( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )", types);
        Assert.Contains("( 1.2.840.113556.1.4.8 NAME 'userAccountControl' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE )", types);
        Assert.Contains("( 1.2.840.113556.1.4.96 NAME 'pwdLastSet' SYNTAX '1.2.840.113556.1.4.906' SINGLE-VALUE )", types);
        Assert.Contains("( 1.2.840.113556.1.4.146 NAME 'objectSid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' SINGLE-VALUE )", types);
        Assert.Contains("( 1.2.840.113556.1.2.102 NAME 'memberOf' SYNTAX '1.3.6.1.4.1.1466.115.121.1.12' )", types);
        Assert.Contains("( 1.2.840.113556.1.2.2 NAME 'whenCreated' SYNTAX '1.3.6.1.4.1.1466.115.121.1.24' SINGLE-VALUE )", types);
        var classes = Values(schema, "objectClasses");
        Assert.Contains("( 2.5.6.0 NAME 'top' ABSTRACT MUST (objectClass ) )", classes);
        Assert.Contains("( 1.2.840.113556.1.5.9 NAME 'user' SUP organizationalPerson STRUCTURAL )", classes);
        Assert.Matches(@"^\d{14}\.0Z$", Values(schema, "modifyTimeStamp")[0]);
    }

    [Fact]
    public void A_generic_directory_publishes_a_standard_schema()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);

        var schema = ReadSchema(server, connection, "attributeTypes", "objectClasses");

        Assert.StartsWith("cn=Subschema-", schema.DistinguishedName);
        var types = Values(schema, "attributeTypes");
        Assert.Contains("( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", types);
        Assert.Contains("( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", types);
        Assert.Contains("( 1.3.6.1.1.1.1.0 NAME 'uidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )", types);
        Assert.Contains("( 1.3.6.1.1.20 NAME 'entryDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )", types);
        // Nothing of Active Directory's own, as long as the data does not use it.
        Assert.DoesNotContain(types, t => t.Contains("'sAMAccountName'") || t.Contains("'pwdLastSet'"));
        Assert.Contains("( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL )", Values(schema, "objectClasses"));
    }

    [Fact]
    public void Every_attribute_and_class_in_the_published_schema_has_a_unique_name_and_id()
    {
        foreach (var builder in new[] { ActiveDirectory(), Generic() })
        {
            using var server = builder.Start();
            using var connection = Connect(server);
            var schema = ReadSchema(server, connection, "attributeTypes", "objectClasses");
            foreach (var attribute in new[] { "attributeTypes", "objectClasses" })
            {
                var definitions = Values(schema, attribute);
                Assert.NotEmpty(definitions);
                var ids = definitions.Select(d => d.Split(' ')[1]).ToArray();
                var names = definitions.Select(d => d.Split('\'')[1].ToLowerInvariant()).ToArray();
                Assert.Equal(ids.Length, ids.Distinct().Count());
                Assert.Equal(names.Length, names.Distinct().Count());
            }
        }
    }

    [Fact]
    public void Attributes_found_in_the_data_are_added_to_the_schema()
    {
        using var server = Generic()
            .WithEntry("cn=device1,dc=example,dc=com", e => e
                .Set("objectClass", "top", "myDevice")
                .Set("cn", "device1")
                .Set("assetTag", "A-17")
                .SetBinary("firmwareImage", [0xFF, 0xFE, 0x00, 0x80])
                .Set("sAMAccountName", "device1")
                .Set("pwdLastSet", "0")
                .Set("unixHomeDirectory", "/home/device1")
                .Set("not a name", "x"))
            .Start();
        using var connection = Connect(server);

        var schema = ReadSchema(server, connection, "attributeTypes", "objectClasses");

        var types = Values(schema, "attributeTypes");
        Assert.Contains("( assetTag-oid NAME 'assetTag' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", types);
        Assert.Contains("( firmwareImage-oid NAME 'firmwareImage' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )", types);
        // Known from the other flavour: the real id, and a syntax a standard directory has a word for.
        Assert.Contains("( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )", types);
        Assert.Contains("( 1.2.840.113556.1.4.96 NAME 'pwdLastSet' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )", types);
        // Active Directory's name for what the standard calls homeDirectory, with the same id: the id stays with the standard name.
        Assert.Contains("( unixHomeDirectory-oid NAME 'unixHomeDirectory' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )", types);
        Assert.Equal(types.Length, types.Select(t => t.Split(' ')[1]).Distinct().Count());
        Assert.DoesNotContain(types, t => t.Contains("not a name")); // what cannot be an attribute name is left out
        Assert.Contains("( myDevice-oid NAME 'myDevice' SUP top STRUCTURAL )", Values(schema, "objectClasses"));
    }

    [Fact]
    public void A_declared_attribute_is_published_with_its_syntax_before_any_entry_has_it()
    {
        using var server = ActiveDirectory()
            .Configure(d => d.DefineAttribute("badgeNumber", AttributeSyntax.Integer, singleValued: true))
            .Start();
        using var connection = Connect(server);

        var types = Values(ReadSchema(server, connection, "attributeTypes"), "attributeTypes");

        Assert.Contains("( badgeNumber-oid NAME 'badgeNumber' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE )", types);
        Assert.Equal(AttributeSyntax.Integer, server.Directory.SyntaxOf("badgeNumber"));
        Assert.Equal(AttributeSyntax.LargeInteger, server.Directory.SyntaxOf("PWDLASTSET"));
        Assert.Equal(AttributeSyntax.DirectoryString, server.Directory.SyntaxOf("neverHeardOf"));
        Assert.Throws<ArgumentException>(() => server.Directory.DefineAttribute("not a name"));
        Assert.Throws<ArgumentException>(() => server.Directory.DefineAttribute("under_score", AttributeSyntax.Integer)); // not a name in LDAP
        Assert.Throws<ArgumentNullException>(() => server.Directory.DefineAttribute(null!));
        Assert.Throws<ArgumentNullException>(() => server.Directory.SyntaxOf(null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => server.Directory.DefineAttribute("odd", (AttributeSyntax)99));
        Assert.Equal(AttributeSyntax.LargeInteger, server.Directory.SyntaxOf("pwdLastSet;range=0-1")); // options do not change the syntax
    }

    private static string[] AttributeTypes(InMemoryDirectory directory) => directory.FindSubschema(directory.SubschemaDn)!.GetStrings("attributeTypes").ToArray();

    private static string[] ObjectClasses(InMemoryDirectory directory) => directory.FindSubschema(directory.SubschemaDn)!.GetStrings("objectClasses").ToArray();

    [Fact]
    public void Declaring_a_known_attribute_by_name_alone_keeps_what_the_server_knows_about_it()
    {
        var ad = new InMemoryDirectory(new DirectoryLayout { Flavor = DirectoryFlavor.ActiveDirectory });
        ad.DefineAttribute("userAccountControl").DefineAttribute("USERPRINCIPALNAME").DefineAttribute("brandNew");
        Assert.Contains("( 1.2.840.113556.1.4.8 NAME 'userAccountControl' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE )", AttributeTypes(ad));
        Assert.Contains("( 1.2.840.113556.1.4.656 NAME 'userPrincipalName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )", AttributeTypes(ad));
        Assert.Contains("( brandNew-oid NAME 'brandNew' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )", AttributeTypes(ad));

        // A generic directory does not list Active Directory's attributes until something uses or declares them.
        var generic = new InMemoryDirectory();
        Assert.DoesNotContain(AttributeTypes(generic), t => t.Contains("'pwdLastSet'"));
        generic.DefineAttribute("pwdLastSet");
        Assert.Contains("( 1.2.840.113556.1.4.96 NAME 'pwdLastSet' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )", AttributeTypes(generic));
        Assert.Equal(AttributeSyntax.LargeInteger, generic.SyntaxOf("pwdLastSet"));
    }

    [Fact]
    public void Declaring_an_attribute_by_name_alone_takes_nothing_back()
    {
        var directory = new InMemoryDirectory();

        // What a test has said about the attribute stays said.
        directory.DefineAttribute("shoeSize", AttributeSyntax.Integer, singleValued: true).DefineAttribute("shoeSize");
        Assert.Equal(AttributeSyntax.Integer, directory.SyntaxOf("shoeSize"));
        Assert.Contains("( shoeSize-oid NAME 'shoeSize' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )", AttributeTypes(directory));

        var known = new InMemoryDirectory();
        known.DefineAttribute("description", AttributeSyntax.OctetString).DefineAttribute("description");
        Assert.Equal(AttributeSyntax.OctetString, known.SyntaxOf("description"));

        // Nor what the data says: an attribute nobody knows is listed as a string, and as binary once a value is not text.
        directory.DefineAttribute("Blob");
        Assert.Contains("( Blob-oid NAME 'Blob' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", AttributeTypes(directory));
        directory.Add("cn=x,dc=example,dc=com", e => e.Set("cn", "x").SetBinary("blob", [0xFF, 0xFE]));
        Assert.Equal(AttributeSyntax.OctetString, directory.SyntaxOf("blob"));
        Assert.Contains("( Blob-oid NAME 'Blob' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )", AttributeTypes(directory)); // spelled as declared
        Assert.Single(AttributeTypes(directory), t => t.Contains("'blob'", StringComparison.OrdinalIgnoreCase));

        // A syntax stated later wins over the guess.
        directory.DefineAttribute("blob", AttributeSyntax.DirectoryString);
        Assert.Contains("( blob-oid NAME 'blob' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", AttributeTypes(directory));
        Assert.Single(AttributeTypes(directory), t => t.Contains("'blob'", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A_declaration_a_computed_attribute_or_a_failed_update_all_change_the_published_schema()
    {
        var directory = new InMemoryDirectory();
        directory.Add("dc=example,dc=com", e => e.Set("objectClass", "top", "domain").Set("dc", "example"));
        var names = new List<DistinguishedName> { directory.SubschemaDn };
        void AssertChanged(string attribute)
        {
            Assert.DoesNotContain(directory.SubschemaDn, names);
            names.Add(directory.SubschemaDn);
            Assert.Contains(AttributeTypes(directory), t => t.Contains($"'{attribute}'"));
        }

        directory.DefineAttribute("declaredLater", AttributeSyntax.Boolean);
        AssertChanged("declaredLater");
        Assert.Contains("( declaredLater-oid NAME 'declaredLater' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )", AttributeTypes(directory));

        directory.DefineAttribute("declaredByName");
        AssertChanged("declaredByName");

        directory.AddVirtualAttribute(new VirtualAttribute("computedSecret", isOperational: true, (_, _) => ["x"]));
        AssertChanged("computedSecret");
        Assert.Contains("( computedSecret-oid NAME 'computedSecret' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 NO-USER-MODIFICATION USAGE directoryOperation )", AttributeTypes(directory));

        // Declared and computed: the declaration gives the syntax, the provider says that it is operational.
        directory.DefineAttribute("computedSecret", AttributeSyntax.Integer);
        Assert.Contains("( computedSecret-oid NAME 'computedSecret' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 NO-USER-MODIFICATION USAGE directoryOperation )", AttributeTypes(directory));
        names.Add(directory.SubschemaDn);

        // A callback that fails half-way has still changed the entry.
        Assert.Throws<InvalidOperationException>(() => directory.Update("dc=example,dc=com", e =>
        {
            e.Set("halfDone", "1");
            throw new InvalidOperationException("boom");
        }));
        AssertChanged("halfDone");

        directory.Add("cn=x,dc=example,dc=com", e => e.Set("objectClass", "top", "gadget").Set("cn", "x"));
        Assert.DoesNotContain(directory.SubschemaDn, names); // classes are part of the content too
        Assert.Contains("( gadget-oid NAME 'gadget' SUP top STRUCTURAL )", ObjectClasses(directory));
    }

    [Fact]
    public void An_operational_attribute_is_marked_the_Active_Directory_way_too()
    {
        var directory = new InMemoryDirectory(new DirectoryLayout { Flavor = DirectoryFlavor.ActiveDirectory });
        directory.AddVirtualAttribute(new VirtualAttribute("computedSecret", isOperational: true, (_, _) => ["x"]));

        Assert.Contains("( computedSecret-oid NAME 'computedSecret' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' NO-USER-MODIFICATION )", AttributeTypes(directory));
    }

    [Fact]
    public void The_same_data_gives_the_same_schema_in_any_order_and_spelling()
    {
        Action<Entry>[] entries =
        [
            e => e.Set("objectClass", "top", "Widget").Set("shoeSize", "38").Set("blob", "text").Set("mailNickname", "text"),
            e => e.Set("objectClass", "top", "widget").Set("SHOESIZE", "39").SetBinary("blob", [0xFF, 0xFE]).SetBinary("mailNickname", [0xFF]),
            e => e.Set("objectClass", "top", "WIDGET").Set("ShoeSize", "40").Set("blob", "more text"),
        ];
        InMemoryDirectory Build(params int[] order)
        {
            var directory = new InMemoryDirectory();
            foreach (var i in order) directory.Add($"cn=e{i},dc=example,dc=com", e => entries[i](e.Set("cn", "e" + i)));
            return directory;
        }

        var forward = Build(0, 1, 2);
        Assert.Equal(forward.SubschemaDn, Build(2, 1, 0).SubschemaDn);
        Assert.Equal(forward.SubschemaDn, Build(1, 2, 0).SubschemaDn);

        var types = AttributeTypes(forward);
        Assert.Contains("( SHOESIZE-oid NAME 'SHOESIZE' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", types);
        Assert.Contains("( blob-oid NAME 'blob' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )", types); // binary somewhere is binary
        Assert.Contains("( mailNickname-oid NAME 'mailNickname' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )", types); // known: no guessing
        Assert.Contains("( WIDGET-oid NAME 'WIDGET' SUP top STRUCTURAL )", ObjectClasses(forward));
    }

    [Fact]
    public void Names_and_ids_stay_unique_and_superiors_published_whatever_the_data_and_declarations()
    {
        var directory = new InMemoryDirectory();
        directory.DefineAttribute("unixHomeDirectory");                       // Active Directory's name for an id the standard gives homeDirectory
        directory.DefineAttribute("room", AttributeSyntax.Integer);           // an attribute and a class of one name
        directory.Add("cn=pc1,dc=example,dc=com", e => e
            .Set("objectClass", "top", "computer", "room", "msDS-ManagedServiceAccount") // classes of the other flavour, with their superiors
            .Set("cn", "pc1")
            .Set("room", "101")
            .Set("badge;lang-en", "x")                                        // an option on a name set in code
            .Set("snake_case", "x"));                                         // not an LDAP name: left out

        var types = AttributeTypes(directory);
        var classes = ObjectClasses(directory);

        var ids = types.Concat(classes).Select(d => d.Split(' ')[1]).ToArray();
        Assert.Equal(ids.Length, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var definitions in new[] { types, classes })
        {
            var names = definitions.Select(d => d.Split('\'')[1]).ToArray();
            Assert.Equal(names.Length, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        }
        var classNames = classes.Select(d => d.Split('\'')[1]).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.All(classes.Where(c => c.Contains(" SUP ")), c => Assert.Contains(c.Split(" SUP ")[1].Split(' ')[0], classNames));
        Assert.Contains("( 1.2.840.113556.1.3.30 NAME 'computer' SUP user STRUCTURAL )", classes);
        Assert.Contains("( 1.2.840.113556.1.5.9 NAME 'user' SUP organizationalPerson STRUCTURAL )", classes);
        Assert.Contains("( room-oid NAME 'room' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )", types);
        Assert.Contains(classes, c => c.Contains("NAME 'room'") && !c.StartsWith("( room-oid "));
        Assert.Contains("( badge-oid NAME 'badge' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", types);
        Assert.DoesNotContain(types, t => t.Contains("snake_case") || t.Contains(';'));
    }

    [Fact]
    public void A_placeholder_id_that_is_taken_gets_a_number()
    {
        var directory = new InMemoryDirectory();
        directory.Add("cn=g,dc=example,dc=com", e => e
            .Set("objectClass", "top", "gadget", "gadget-class", "gadget-2-class")
            .Set("cn", "g")
            .Set("gadget", "x")
            .Set("gadget-class", "x")      // the id the class "gadget" would get next to the attribute "gadget"
            .Set("gadget-2-class", "x"));  // and the one after that

        var definitions = AttributeTypes(directory).Concat(ObjectClasses(directory)).ToArray();

        var ids = definitions.Select(d => d.Split(' ')[1]).ToArray();
        Assert.Equal(ids.Length, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Contains("( gadget-class-oid NAME 'gadget-class' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", definitions);
        Assert.Contains("( gadget-3-class-oid NAME 'gadget' SUP top STRUCTURAL )", definitions);
    }

    [Fact]
    public void The_schema_follows_a_changed_base_DN()
    {
        var directory = new InMemoryDirectory(new DirectoryLayout { Flavor = DirectoryFlavor.ActiveDirectory, BaseDn = "DC=one,DC=test" });
        Assert.EndsWith(",CN=Schema,CN=Configuration,DC=one,DC=test", directory.SubschemaDn.ToString());

        directory.Layout.RenameBase("DC=two,DC=test");

        Assert.EndsWith(",CN=Schema,CN=Configuration,DC=two,DC=test", directory.SubschemaDn.ToString());
        Assert.NotNull(directory.FindSubschema("CN=Aggregate,CN=Schema,CN=Configuration,DC=two,DC=test"));
        Assert.Null(directory.FindSubschema("CN=Aggregate,CN=Schema,CN=Configuration,DC=one,DC=test"));
    }

    [Fact]
    public void The_schema_is_sent_whole_whatever_the_limit_on_values_per_attribute()
    {
        using var server = ActiveDirectory().WithMaxValuesPerAttribute(5).Start();
        using var connection = Connect(server);

        var schema = ReadSchema(server, connection, "attributeTypes", "objectClasses");

        Assert.Equal(["attributetypes", "objectclasses"], schema.Attributes.AttributeNames.Cast<string>().Select(n => n.ToLowerInvariant()).Order());
        Assert.True(Values(schema, "attributeTypes").Length > 150);
        Assert.True(Values(schema, "objectClasses").Length > 30);
    }

    [Fact]
    public void A_stored_attribute_the_schema_knows_as_operational_comes_only_when_asked_for()
    {
        using var server = Generic().WithUser("mallory", "x", u => u.Disabled().Attribute("entryUUID", "6d5f0a3e-0000-4000-8000-000000000001")).Start();
        using var connection = Connect(server);
        var dn = server.Directory.UserDn("mallory").ToString();
        string[] Names(params string[] attributes) =>
            ((SearchResponse)connection.SendRequest(new SdsSearchRequest(dn, "(pwdAccountLockedTime=*)", SdsSearchScope.Base, attributes)))
            .Entries[0].Attributes.AttributeNames.Cast<string>().Select(n => n.ToLowerInvariant()).ToArray();

        Assert.DoesNotContain("pwdaccountlockedtime", Names());
        Assert.DoesNotContain("entryuuid", Names("*"));
        Assert.Contains("uid", Names("*"));
        Assert.Equal(["pwdaccountlockedtime"], Names("pwdAccountLockedTime"));
        Assert.Contains("entryuuid", Names("+"));
        Assert.Contains("pwdaccountlockedtime", Names("+"));
    }

    [Fact]
    public void What_is_operational_is_the_flavours_own_business()
    {
        // The standards hide entryUUID and pwdAccountLockedTime; to Active Directory they are attributes like any other.
        using var server = ActiveDirectory()
            .WithUser("mallory", "x", u => u
                .Attribute("entryUUID", "6d5f0a3e-0000-4000-8000-000000000001")
                .Attribute("pwdAccountLockedTime", "20260101000000Z")
                .Attribute("creatorsName", "cn=admin"))
            .Start();
        using var connection = Connect(server);
        var dn = server.Directory.UserDn("mallory").ToString();

        var names = ((SearchResponse)connection.SendRequest(new SdsSearchRequest(dn, "(objectClass=*)", SdsSearchScope.Base, "*")))
            .Entries[0].Attributes.AttributeNames.Cast<string>().Select(n => n.ToLowerInvariant()).ToArray();

        Assert.Contains("entryuuid", names);
        Assert.Contains("pwdaccountlockedtime", names);
        Assert.Contains("creatorsname", names);
        Assert.DoesNotContain("tokengroups", names); // its own operational attributes stay hidden
        // The schema says the same: nothing marks them as the server's own.
        var types = Values(ReadSchema(server, connection, "attributeTypes"), "attributeTypes");
        Assert.Contains("( 1.3.6.1.1.16.4 NAME 'entryUUID' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )", types);
        Assert.DoesNotContain(types, t => t.Contains("'pwdAccountLockedTime'") && t.Contains("NO-USER-MODIFICATION"));

        // The other way round: a generic directory does not hide what only Active Directory computes.
        using var generic = Generic().WithUser("m", "x", u => u.Attribute("canonicalName", "stored").Attribute("entryUUID", "stored")).Start();
        using var toGeneric = Connect(generic);
        var genericNames = ((SearchResponse)toGeneric.SendRequest(new SdsSearchRequest(generic.Directory.UserDn("m").ToString(), "(objectClass=*)", SdsSearchScope.Base, "*")))
            .Entries[0].Attributes.AttributeNames.Cast<string>().Select(n => n.ToLowerInvariant()).ToArray();
        Assert.Contains("canonicalname", genericNames);
        Assert.DoesNotContain("entryuuid", genericNames);
    }

    [Fact]
    public void A_search_after_a_write_does_not_put_the_schema_together_again()
    {
        // The schema is built from all the data. Searches that follow writes must not pay for it: neither to
        // tell operational attributes from the rest nor to sort.
        foreach (var builder in new[] { ActiveDirectory(), Generic() })
        {
            using var server = builder
                .Configure(d => d.DefineAttribute("shoeSize", AttributeSyntax.Integer))
                .WithUser("u9", "x", u => u.Attribute("shoeSize", "9").Attribute("unheardOf", "b"))
                .WithUser("u10", "x", u => u.Attribute("shoeSize", "10").Attribute("unheardOf", "a"))
                .Start();
            using var connection = Connect(server);
            var directory = server.Directory;
            var baseDn = directory.Layout.BaseDn.ToString();
            _ = directory.SubschemaDn;
            var builds = directory.SchemaBuilds;

            for (var round = 0; round < 3; round++)
            {
                directory.Update(directory.UserDn("u9"), e => e.Set("description", "round " + round).Set("newIn" + round, "x"));
                var everything = (SearchResponse)connection.SendRequest(new SdsSearchRequest(baseDn, "(shoeSize=*)", SdsSearchScope.Subtree, "*", "+"));
                Assert.Equal(2, everything.Entries.Count);
                Assert.Equal(["u9", "u10"], Sorted(connection, baseDn, "(shoeSize=*)", "cn", new SortRequestControl("shoeSize", false)));
                Assert.Equal(["u10", "u9"], Sorted(connection, baseDn, "(shoeSize=*)", "cn", new SortRequestControl("unheardOf", false)));
                var missing = Assert.Throws<DirectoryOperationException>(() =>
                    connection.SendRequest(new SdsSearchRequest("cn=nobody," + baseDn, "(objectClass=*)", SdsSearchScope.Base)));
                Assert.Equal(System.DirectoryServices.Protocols.ResultCode.NoSuchObject, missing.Response.ResultCode);
            }

            Assert.Equal(builds, directory.SchemaBuilds);
            _ = directory.SubschemaDn; // asked for, it is built once
            Assert.Equal(builds + 1, directory.SchemaBuilds);
        }
    }

    [Fact]
    public void The_schema_and_a_search_agree_on_what_is_operational()
    {
        // A computed attribute says itself whether it is operational, whatever the catalog holds under its name.
        var ad = new InMemoryDirectory(new DirectoryLayout { Flavor = DirectoryFlavor.ActiveDirectory });
        var hash = ad.SubschemaDn;
        Assert.Contains("( 1.3.6.1.1.20 NAME 'entryDN' SYNTAX '1.3.6.1.4.1.1466.115.121.1.12' SINGLE-VALUE NO-USER-MODIFICATION )", AttributeTypes(ad));
        Assert.Contains(AttributeTypes(ad), t => t.Contains("'tokenGroups'") && t.EndsWith("NO-USER-MODIFICATION )"));
        ad.DefineAttribute("entryDN"); // says nothing new
        Assert.Equal(hash, ad.SubschemaDn);

        var generic = new InMemoryDirectory();
        Assert.True(generic.IsOperational("entryUUID"));
        Assert.True(generic.IsOperational("entryUUID;x-option")); // an entry built in code may carry options
        Assert.Throws<ArgumentNullException>("attributeName", () => generic.IsOperational(null!));
        generic.AddVirtualAttribute(new VirtualAttribute("entryUUID", isOperational: false, (_, _) => ["x"]));
        generic.AddVirtualAttribute(new VirtualAttribute("description", isOperational: true, (_, _) => ["x"]));
        generic.DefineAttribute("pwdChangedTime", AttributeSyntax.DirectoryString); // a declared syntax leaves it operational
        generic.Add("cn=x,dc=example,dc=com", e => e.Set("cn", "x").Set("custom", "x").Set("createTimestamp;x-option", "x"));
        Assert.False(generic.IsOperational("entryUUID"));
        Assert.Contains("( 1.3.6.1.1.16.4 NAME 'entryUUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )", AttributeTypes(generic));
        Assert.Contains("( 2.5.4.13 NAME 'description' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 NO-USER-MODIFICATION USAGE directoryOperation )", AttributeTypes(generic));
        Assert.True(generic.IsOperational("pwdChangedTime"));

        // And for every attribute of both: what the schema says is what a search does.
        foreach (var directory in new[] { ad, generic })
        {
            var types = AttributeTypes(directory);
            Assert.True(types.Length > 50);
            foreach (var type in types)
            {
                var name = type.Split('\'')[1];
                var marked = type.Contains(" NO-USER-MODIFICATION") || type.Contains(" USAGE directoryOperation") || type.Contains(" USAGE distributedOperation");
                // The definitions themselves are operational and all the same open to writes: schema extensions.
                if (name is "attributeTypes" or "objectClasses") continue;
                Assert.True(marked == directory.IsOperational(name), type);
            }
        }
    }

    [Fact]
    public void The_generic_schema_entry_is_written_the_standard_way()
    {
        var directory = new InMemoryDirectory();
        var entry = directory.FindSubschema(directory.SubschemaDn)!;

        Assert.Matches(@"^\d{14}Z$", entry.GetString("createTimeStamp")!);
        Assert.Equal(entry.GetString("createTimeStamp"), entry.GetString("modifyTimeStamp"));
        Assert.Contains("( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )", ObjectClasses(directory));
        // Operational, and all the same not closed to writes: that is how a schema is extended on a real server.
        Assert.Contains("( 2.5.21.5 NAME 'attributeTypes' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE directoryOperation )", AttributeTypes(directory));
        Assert.Contains(AttributeTypes(directory), t => t.Contains("'createTimestamp'") && t.EndsWith("NO-USER-MODIFICATION USAGE directoryOperation )"));
    }

    [Fact]
    public void The_schema_follows_every_kind_of_write()
    {
        const string root = "dc=example,dc=com";
        using var server = Generic().WithEntry("cn=e1," + root, e => e.Set("objectClass", "top", "device").Set("cn", "e1").Set("onlyHere", "x")).Start();
        using var connection = Connect(server);
        var directory = server.Directory;
        bool Lists(string name) => AttributeTypes(directory).Any(t => t.Contains($"'{name}'"));
        Assert.True(Lists("onlyHere"));

        // Over LDAP: an attribute first written by a Modify is what ADSI would otherwise not find.
        connection.SendRequest(new System.DirectoryServices.Protocols.ModifyRequest("cn=e1," + root, DirectoryAttributeOperation.Add, "addedByModify", "1"));
        Assert.True(Lists("addedByModify"));
        connection.SendRequest(new ModifyDNRequest("cn=e1," + root, root, "gadgetName=e1"));
        Assert.True(Lists("gadgetName"));
        connection.SendRequest(new System.DirectoryServices.Protocols.AddRequest("cn=e2," + root, new DirectoryAttribute("objectClass", "device"), new DirectoryAttribute("addedByAdd", "1")));
        Assert.True(Lists("addedByAdd"));
        connection.SendRequest(new System.DirectoryServices.Protocols.DeleteRequest("gadgetName=e1," + root));
        Assert.False(Lists("onlyHere"));
        Assert.False(Lists("gadgetName"));

        // From code.
        directory.Add("cn=e3," + root, e => e.Set("cn", "e3").Set("alsoHere", "x"));
        Assert.True(Lists("alsoHere"));
        directory.Remove("cn=e2," + root);
        Assert.False(Lists("addedByAdd"));
        directory.Clear();
        Assert.False(Lists("alsoHere"));
    }

    [Fact]
    public void A_declaration_overrides_what_the_server_knows_and_keeps_the_real_id()
    {
        using var server = ActiveDirectory()
            .Configure(d => d.DefineAttribute("description", AttributeSyntax.OctetString))
            .Start();
        using var connection = Connect(server);

        var types = Values(ReadSchema(server, connection, "attributeTypes"), "attributeTypes");

        Assert.Contains("( 2.5.4.13 NAME 'description' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' )", types);
        Assert.Single(types, t => t.Contains("'description'"));
    }

    [Fact]
    public void The_schema_name_follows_its_content_and_old_names_keep_working()
    {
        using var server = ActiveDirectory().Start();
        using var twin = ActiveDirectory().Start();
        using var connection = Connect(server);
        var before = server.Directory.SubschemaDn;
        Assert.Equal(before, twin.Directory.SubschemaDn); // the same schema under the same name, whatever the server

        server.Directory.Update($"CN=alice,CN=Users,{AdBase}", e => e.Set("shoeSize", "38"));

        var after = server.Directory.SubschemaDn;
        Assert.NotEqual(before, after);
        // Asked for by the plain name of a real server, it answers under that name; otherwise under the current one.
        var plain = $"CN=Aggregate,CN=Schema,CN=Configuration,{AdBase}";
        foreach (var (name, answers) in new[] { (before.ToString(), after.ToString()), (after.ToString(), after.ToString()), (plain, plain), (plain.ToLowerInvariant(), plain) })
        {
            var response = (SearchResponse)connection.SendRequest(new SdsSearchRequest(name, "(objectClass=*)", SdsSearchScope.Base, "attributeTypes", "cn"));
            var entry = Assert.Single(response.Entries.Cast<SearchResultEntry>());
            Assert.Equal(answers, entry.DistinguishedName);
            Assert.Equal([DistinguishedName.Parse(answers).Leaf!.Value], Values(entry, "cn")); // one value: cn is single-valued there
            Assert.Contains(Values(entry, "attributeTypes"), t => t.Contains("'shoeSize'"));
        }
    }

    [Fact]
    public void The_schema_is_not_part_of_the_tree_and_comes_only_when_asked_for()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);

        // "*" gives the entry itself; the definitions are operational, as on a real server.
        var plain = ReadSchema(server, connection);
        Assert.Equal(["cn", "objectclass"], plain.Attributes.AttributeNames.Cast<string>().Select(n => n.ToLowerInvariant()).Order());
        var all = ReadSchema(server, connection, "+");
        Assert.Contains("attributetypes", all.Attributes.AttributeNames.Cast<string>().Select(n => n.ToLowerInvariant()));
        // Computed attributes come as for any entry: a filter finds them, so a search has to return them.
        Assert.Contains("entrydn", all.Attributes.AttributeNames.Cast<string>().Select(n => n.ToLowerInvariant()));
        var byComputed = (SearchResponse)connection.SendRequest(new SdsSearchRequest(
            server.Directory.SubschemaDn.ToString(), $"(entryDN={server.Directory.SubschemaDn})", SdsSearchScope.Base, "entryDN"));
        Assert.Equal([server.Directory.SubschemaDn.ToString()], Values(Assert.Single(byComputed.Entries.Cast<SearchResultEntry>()), "entryDN"));

        // A search of everything, from the root down, does not find it, and a search below it finds nothing.
        var everything = server.Directory.Search(DistinguishedName.Root, Protocol.SearchScope.WholeSubtree, new LdapFilter.Present("objectClass"));
        Assert.NotEmpty(everything);
        Assert.DoesNotContain(everything, e => e.Dn.ToString().Contains("Subschema", StringComparison.OrdinalIgnoreCase));
        using (var raw = new RawClient(server.Host, server.Port))
        {
            var patience = TimeSpan.FromSeconds(10);
            Assert.Equal(0, raw.Exchange(ClientEncoder.Encode(1, new BindRequest(3, server.Directory.UserDn("admin").ToString(), "admin-secret", null)), patience)?.ResultCode);
            var fromRoot = new Protocol.SearchRequest("", Protocol.SearchScope.WholeSubtree, 0, 0, false, LdapFilter.Parse("(objectClass=subschema)"), []);
            Assert.Equal(0, raw.Exchange(ClientEncoder.Encode(2, fromRoot), patience, out var found)?.ResultCode);
            Assert.Equal(0, found);
        }
        var filtered = (SearchResponse)connection.SendRequest(new SdsSearchRequest("cn=Subschema", "(objectClass=person)", SdsSearchScope.Base, "1.1"));
        Assert.Empty(filtered.Entries);
        // It is a leaf: its subtree is the entry itself, below it there is nothing.
        var below = (SearchResponse)connection.SendRequest(new SdsSearchRequest("cn=Subschema", "(objectClass=*)", SdsSearchScope.OneLevel, "1.1"));
        Assert.Empty(below.Entries);
        var subtree = (SearchResponse)connection.SendRequest(new SdsSearchRequest("cn=Subschema", "(cn=Subschema)", SdsSearchScope.Subtree, "cn"));
        Assert.Equal("cn=Subschema", Assert.Single(subtree.Entries.Cast<SearchResultEntry>()).DistinguishedName);
        Assert.Equal(["Subschema"], Values(subtree.Entries[0], "cn"));
    }

    [Fact]
    public void The_root_DSE_names_the_schema_to_a_plain_read()
    {
        foreach (var builder in new[] { ActiveDirectory(), Generic() })
        {
            using var server = builder.Start();
            using var connection = Connect(server);

            var rootDse = ((SearchResponse)connection.SendRequest(new SdsSearchRequest("", "(objectClass=*)", SdsSearchScope.Base))).Entries[0];

            Assert.Equal([server.Directory.SubschemaDn.ToString()], Values(rootDse, "subschemaSubentry"));
        }
    }

    [Fact]
    public void The_Active_Directory_schema_answers_like_the_entry_it_is_on_a_domain_controller()
    {
        using var server = ActiveDirectory().Start();
        using var connection = Connect(server);
        var plain = "CN=Aggregate,CN=Schema,CN=Configuration," + AdBase;
        var hashed = server.Directory.SubschemaDn.ToString();

        // Each name with the filters that fit it, the entry itself and its subtree.
        foreach (var (dn, cn) in new[] { (plain, "Aggregate"), (hashed, server.Directory.SubschemaDn.Leaf!.Value) })
            foreach (var filter in new[] { $"(cn={cn})", "(objectClass=subSchema)", $"(distinguishedName={dn})" })
                foreach (var scope in new[] { SdsSearchScope.Base, SdsSearchScope.Subtree })
                {
                    var found = (SearchResponse)connection.SendRequest(new SdsSearchRequest(dn, filter, scope, "attributeTypes", "distinguishedName"));
                    var entry = Assert.Single(found.Entries.Cast<SearchResultEntry>());
                    Assert.Equal(dn, entry.DistinguishedName);
                    Assert.Equal([dn], Values(entry, "distinguishedName"));
                    Assert.NotEmpty(Values(entry, "attributeTypes"));
                }
        var below = (SearchResponse)connection.SendRequest(new SdsSearchRequest(plain, "(objectClass=*)", SdsSearchScope.OneLevel, "1.1"));
        Assert.Empty(below.Entries);

        // The definitions come only when asked for, here too; what every entry has comes with "*".
        var everything = ((SearchResponse)connection.SendRequest(new SdsSearchRequest(hashed, "(objectClass=*)", SdsSearchScope.Base))).Entries[0];
        var names = everything.Attributes.AttributeNames.Cast<string>().Select(n => n.ToLowerInvariant()).ToArray();
        Assert.Contains("cn", names);
        Assert.Contains("distinguishedname", names);
        Assert.DoesNotContain("attributetypes", names);
        Assert.DoesNotContain("objectclasses", names);
        Assert.DoesNotContain("tokengroups", names);
    }

    [Fact]
    public void An_entry_stored_under_the_schema_name_wins()
    {
        using var server = Generic()
            .WithEntry("cn=Subschema", e => e.Set("objectClass", "top", "subschema").Set("cn", "Subschema").Set("description", "my own"))
            .Start();
        using var connection = Connect(server);

        var response = (SearchResponse)connection.SendRequest(new SdsSearchRequest("cn=Subschema", "(objectClass=*)", SdsSearchScope.Base));

        Assert.Equal("my own", Values(response.Entries[0], "description")[0]);
    }

    [Fact]
    public void The_schema_needs_a_bind_where_a_search_does()
    {
        using var server = ActiveDirectory().Start();
        using var connection = Connect(server, bind: false);
        var rootDse = (SearchResponse)connection.SendRequest(new SdsSearchRequest("", "(objectClass=*)", SdsSearchScope.Base, "subschemaSubentry", "schemaNamingContext", "supportedControl"));
        var dn = Values(rootDse.Entries[0], "subschemaSubentry")[0];
        Assert.Equal("CN=Schema,CN=Configuration," + AdBase, Values(rootDse.Entries[0], "schemaNamingContext")[0]);
        Assert.Contains(LdapEncoder.SortRequestOid, Values(rootDse.Entries[0], "supportedControl"));

        var e = Assert.Throws<DirectoryOperationException>(() =>
            connection.SendRequest(new SdsSearchRequest(dn, "(objectClass=*)", SdsSearchScope.Base, "attributeTypes")));

        Assert.Equal(System.DirectoryServices.Protocols.ResultCode.OperationsError, e.Response.ResultCode);
    }

    // ---- server-side sorting ---------------------------------------------------------------------------------

    private static string[] Sorted(SdsLdapConnection connection, string baseDn, string filter, string returned, params DirectoryControl[] controls)
    {
        var request = new SdsSearchRequest(baseDn, filter, SdsSearchScope.Subtree, returned);
        request.Controls.AddRange(controls);
        var response = (SearchResponse)connection.SendRequest(request);
        var sort = Assert.Single(response.Controls.OfType<SortResponseControl>());
        Assert.Equal(System.DirectoryServices.Protocols.ResultCode.Success, sort.Result);
        return response.Entries.Cast<SearchResultEntry>().Select(e => e.Attributes.Contains(returned) ? Values(e, returned)[0] : "-").ToArray();
    }

    [Fact]
    public void Sorts_text_without_regard_to_case_and_puts_entries_without_the_attribute_last()
    {
        using var server = ActiveDirectory().Start();
        using var connection = Connect(server);

        var byName = Sorted(connection, AdBase, "(objectClass=user)", "sAMAccountName", new SortRequestControl("sAMAccountName", false));
        Assert.Equal(["admin", "alice", "Bob", "carol"], byName);

        var reversed = Sorted(connection, AdBase, "(objectClass=user)", "sAMAccountName", new SortRequestControl("sAMAccountName", true));
        Assert.Equal(["carol", "Bob", "alice", "admin"], reversed);

        var byMail = Sorted(connection, AdBase, "(objectClass=user)", "mail", new SortRequestControl("mail", false));
        Assert.Equal(["alice@corp.example.com", "-", "-", "-"], byMail);

        // No value is the largest value (RFC 2891), so in reverse order those entries come first.
        var byMailReversed = Sorted(connection, AdBase, "(objectClass=user)", "mail", new SortRequestControl("mail", true));
        Assert.Equal(["-", "-", "-", "alice@corp.example.com"], byMailReversed);
    }

    [Fact]
    public void Sorts_numbers_as_numbers_when_the_schema_says_so()
    {
        using var server = Generic()
            .Configure(d => d.DefineAttribute("shoeSize", AttributeSyntax.Integer))
            .WithUser("u9", "x", u => u.Attribute("shoeSize", "9").Attribute("roomNumber", "9"))
            .WithUser("u10", "x", u => u.Attribute("shoeSize", "10").Attribute("roomNumber", "10"))
            .WithUser("u100", "x", u => u.Attribute("shoeSize", "100").Attribute("roomNumber", "100"))
            .Start();
        using var connection = Connect(server);

        Assert.Equal(["9", "10", "100"], Sorted(connection, "dc=example,dc=com", "(shoeSize=*)", "shoeSize", new SortRequestControl("shoeSize", false)));
        Assert.Equal(["10", "100", "9"], Sorted(connection, "dc=example,dc=com", "(roomNumber=*)", "roomNumber", new SortRequestControl("roomNumber", false)));
    }

    [Fact]
    public void A_number_with_spaces_around_it_sorts_where_a_filter_finds_it()
    {
        using var server = Generic()
            .Configure(d => d.DefineAttribute("shoeSize", AttributeSyntax.Integer))
            .WithUser("u9", "x", u => u.Attribute("shoeSize", " 9 "))
            .WithUser("u10", "x", u => u.Attribute("shoeSize", "10"))
            .WithUser("u-5", "x", u => u.Attribute("shoeSize", " -5"))
            .Start();
        using var connection = Connect(server);

        Assert.Equal(["u-5", "u9"], Sorted(connection, "dc=example,dc=com", "(shoeSize<=9)", "uid", new SortRequestControl("shoeSize", false)));
        Assert.Equal(["u-5", "u9", "u10"], Sorted(connection, "dc=example,dc=com", "(shoeSize=*)", "uid", new SortRequestControl("shoeSize", false)));
    }

    [Fact]
    public void Sorts_by_several_keys()
    {
        using var server = Generic()
            .WithUser("u1", "x", u => u.Attribute("l", "Berlin").Attribute("title", "b"))
            .WithUser("u2", "x", u => u.Attribute("l", "Amsterdam").Attribute("title", "z"))
            .WithUser("u3", "x", u => u.Attribute("l", "Berlin").Attribute("title", "a"))
            .Start();
        using var connection = Connect(server);

        var control = new SortRequestControl(new SortKey("l", null, false), new SortKey("title", null, true));

        Assert.Equal(["u2", "u1", "u3"], Sorted(connection, "dc=example,dc=com", "(l=*)", "uid", control));
        Assert.Equal(["u2", "u3", "u1"], Sorted(connection, "dc=example,dc=com", "(l=*)", "uid",
            new SortRequestControl(new SortKey("l", null, false), new SortKey("title", null, false))));
        Assert.Equal(["u3", "u1", "u2"], Sorted(connection, "dc=example,dc=com", "(l=*)", "uid",
            new SortRequestControl(new SortKey("l", null, true), new SortKey("title", null, false))));
    }

    [Fact]
    public void Of_several_values_the_smallest_counts_and_the_name_may_carry_an_option()
    {
        using var server = Generic()
            .WithUser("u1", "x", u => u.Attribute("title", "m"))
            .WithUser("u2", "x", u => u.Attribute("title", "z", "a"))
            .WithUser("u3", "x", u => u.Attribute("title", "n"))
            .Start();
        using var connection = Connect(server);

        Assert.Equal(["u2", "u1", "u3"], Sorted(connection, "dc=example,dc=com", "(title=*)", "uid", new SortRequestControl("title", false)));
        Assert.Equal(["u3", "u1", "u2"], Sorted(connection, "dc=example,dc=com", "(title=*)", "uid", new SortRequestControl("title;lang-en", true)));
    }

    [Fact]
    public void Values_that_differ_in_case_only_come_in_the_same_order_however_they_were_added()
    {
        string[] Run(params string[] order)
        {
            var builder = Generic();
            foreach (var value in order) builder = builder.WithUser(value == "bob" ? "lower" : "upper", "x", u => u.Attribute("title", value));
            using var server = builder.Start();
            using var connection = Connect(server);
            return Sorted(connection, "dc=example,dc=com", "(title=*)", "uid", new SortRequestControl("title", false));
        }

        Assert.Equal(["upper", "lower"], Run("bob", "Bob")); // "Bob" before "bob": by code point where case is all the difference
        Assert.Equal(["upper", "lower"], Run("Bob", "bob"));
    }

    [Fact]
    public void Numbers_the_server_knows_without_being_told_sort_as_numbers()
    {
        using var server = Generic()
            .Configure(d => d.DefineAttribute("big", AttributeSyntax.LargeInteger))
            .WithUser("u9", "x", u => u.Attribute("uidNumber", "9").Attribute("big", "9").Attribute("pwdLastSet", "9"))
            .WithUser("u10", "x", u => u.Attribute("uidNumber", "10").Attribute("big", "10").Attribute("pwdLastSet", "10"))
            .Start();
        using var connection = Connect(server);

        foreach (var attribute in new[] { "uidNumber", "UIDNUMBER", "big", "pwdLastSet" }) // the last is Active Directory's, a large integer
            Assert.Equal(["u9", "u10"], Sorted(connection, "dc=example,dc=com", "(uidNumber=*)", "uid", new SortRequestControl(attribute, false)));
    }

    [Fact]
    public void Numbers_come_before_text_and_text_before_binary_values()
    {
        using var server = Generic()
            .Configure(d => d.DefineAttribute("shoeSize", AttributeSyntax.Integer))
            .WithUser("text", "x", u => u.Attribute("shoeSize", "abc").Attribute("blob", "text"))
            .WithUser("number", "x", u => u.Attribute("shoeSize", "5"))
            .WithUser("binary", "x")
            .Start();
        server.Directory.Update(server.Directory.UserDn("binary"), e => e.SetBinary("blob", [0xFF, 0xFE]));
        using var connection = Connect(server);

        Assert.Equal(["number", "text"], Sorted(connection, "dc=example,dc=com", "(shoeSize=*)", "uid", new SortRequestControl("shoeSize", false)));
        Assert.Equal(["text", "binary"], Sorted(connection, "dc=example,dc=com", "(blob=*)", "uid", new SortRequestControl("blob", false)));
    }

    [Fact]
    public void A_sort_that_is_not_done_leaves_the_order_alone_and_says_so()
    {
        var builder = Generic();
        foreach (var value in new[] { "b", "c", "a" }) builder = builder.WithUser("u" + value, "x", u => u.Attribute("title", value));
        using var server = builder.Start();
        using var connection = Connect(server);
        SdsSearchRequest Request(int keys, bool critical)
        {
            var request = new SdsSearchRequest("dc=example,dc=com", "(title=*)", SdsSearchScope.Subtree, "uid");
            request.Controls.Add(new SortRequestControl(Enumerable.Repeat(new SortKey("title", null, false), keys).ToArray()) { IsCritical = critical });
            return request;
        }
        string[] Uids(SearchResponse response) => response.Entries.Cast<SearchResultEntry>().Select(e => Values(e, "uid")[0]).ToArray();

        var sorted = (SearchResponse)connection.SendRequest(Request(8, true));
        Assert.Equal(["ua", "ub", "uc"], Uids(sorted));

        var unsorted = (SearchResponse)connection.SendRequest(Request(9, false));
        Assert.Equal(["ub", "uc", "ua"], Uids(unsorted));
        Assert.Equal(System.DirectoryServices.Protocols.ResultCode.UnwillingToPerform, Assert.Single(unsorted.Controls.OfType<SortResponseControl>()).Result);

        var refused = Assert.Throws<DirectoryOperationException>(() => connection.SendRequest(Request(9, true)));
        Assert.Equal(System.DirectoryServices.Protocols.ResultCode.UnavailableCriticalExtension, refused.Response.ResultCode);
        Assert.Equal(System.DirectoryServices.Protocols.ResultCode.UnwillingToPerform, Assert.Single(refused.Response.Controls.OfType<SortResponseControl>()).Result);
    }

    [Fact]
    public void A_sorted_paged_search_carries_both_response_controls_on_every_page()
    {
        using var server = Generic().WithUser("u1", "x").WithUser("u2", "x").Start();
        using var connection = Connect(server);
        var paging = new PageResultRequestControl(2);
        var seen = new List<string>();
        for (var page = 0; page < 2; page++)
        {
            var request = new SdsSearchRequest("dc=example,dc=com", "(uid=*)", SdsSearchScope.Subtree, "uid");
            request.Controls.AddRange(new DirectoryControl[] { new SortRequestControl("uid", true), paging });
            var response = (SearchResponse)connection.SendRequest(request);
            Assert.Equal(System.DirectoryServices.Protocols.ResultCode.Success, Assert.Single(response.Controls.OfType<SortResponseControl>()).Result);
            paging.Cookie = Assert.Single(response.Controls.OfType<PageResultResponseControl>()).Cookie;
            seen.AddRange(response.Entries.Cast<SearchResultEntry>().Select(e => Values(e, "uid")[0]));
        }

        Assert.Equal(["u2", "u1", "alice", "admin"], seen);
        Assert.Empty(paging.Cookie);
    }

    [Fact]
    public void Sorts_by_a_computed_attribute_the_client_did_not_ask_to_see()
    {
        using var server = Generic().Start();
        using var connection = Connect(server);

        Assert.Equal(["alice", "admin"], Sorted(connection, "dc=example,dc=com", "(uid=*)", "uid", new SortRequestControl("entryDN", true)));
        Assert.Equal(["admin", "alice"], Sorted(connection, "dc=example,dc=com", "(uid=*)", "uid", new SortRequestControl("entryDN", false)));
    }

    [Fact]
    public void Text_sorts_the_same_way_on_every_machine_and_in_both_flavours()
    {
        // Without regard to case, otherwise by code point. A domain controller would put "_svc" and "Ärger"
        // before "Zoe"; the server does not follow it there, for an order that does not depend on the machine.
        string[] names = ["Zoe", "_svc", "Ärger", "ben"];
        LdapTestServerBuilder WithNames(LdapTestServerBuilder builder) => names.Aggregate(builder, (b, name) => b.WithUser(name, "x"));
        using var ad = WithNames(ActiveDirectory()).Start();
        using var generic = WithNames(Generic()).Start();
        using var toAd = Connect(ad);
        using var toGeneric = Connect(generic);

        Assert.Equal(
            ["admin", "alice", "ben", "Bob", "carol", "Zoe", "_svc", "Ärger"],
            Sorted(toAd, AdBase, "(objectClass=user)", "cn", new SortRequestControl("cn", false)));
        Assert.Equal(
            ["admin", "alice", "ben", "Zoe", "_svc", "Ärger"],
            Sorted(toGeneric, "dc=example,dc=com", "(objectClass=inetOrgPerson)", "uid", new SortRequestControl("uid", false)));
    }

    [Fact]
    public void Active_Directory_sorts_by_one_attribute_only()
    {
        using var server = ActiveDirectory().Start();
        using var connection = Connect(server);
        SdsSearchRequest Request(bool critical)
        {
            var request = new SdsSearchRequest(AdBase, "(objectClass=user)", SdsSearchScope.Subtree, "sAMAccountName");
            request.Controls.Add(new SortRequestControl(new SortKey("sAMAccountName", null, true), new SortKey("cn", null, false)) { IsCritical = critical });
            return request;
        }

        // Critical: the search fails. Not critical: the result comes unsorted, and the response control says why.
        var e = Assert.Throws<DirectoryOperationException>(() => connection.SendRequest(Request(critical: true)));
        Assert.Equal(System.DirectoryServices.Protocols.ResultCode.UnavailableCriticalExtension, e.Response.ResultCode);
        Assert.Empty(((SearchResponse)e.Response).Entries);

        var unsorted = (SearchResponse)connection.SendRequest(Request(critical: false));
        Assert.Equal(System.DirectoryServices.Protocols.ResultCode.UnwillingToPerform, unsorted.Controls.OfType<SortResponseControl>().Single().Result);
        Assert.Equal(["admin", "alice", "Bob", "carol"], unsorted.Entries.Cast<SearchResultEntry>().Select(x => Values(x, "sAMAccountName")[0]));
    }

    [Fact]
    public void Too_many_sort_keys_are_refused_without_being_sorted()
    {
        using var server = Generic().Start();
        using var client = new RawClient(server.Host, server.Port);
        var patience = TimeSpan.FromSeconds(10);
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(1, new BindRequest(3, server.Directory.UserDn("admin").ToString(), "admin-secret", null)), patience)?.ResultCode);
        var search = new Protocol.SearchRequest("dc=example,dc=com", Protocol.SearchScope.WholeSubtree, 0, 0, false, new LdapFilter.Present("objectClass"), []);
        LdapControl Keys(int count, bool critical) =>
            new(LdapEncoder.SortRequestOid, critical, ClientEncoder.SortRequest(Enumerable.Repeat(("cn", (string?)null, false), count).ToArray()));

        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(2, search, [Keys(8, true)]), patience, out var sorted)?.ResultCode);
        Assert.True(sorted > 0);
        Assert.Equal((int)ResultCode.UnavailableCriticalExtension, client.Exchange(ClientEncoder.Encode(3, search, [Keys(9, true)]), patience, out var refused)?.ResultCode);
        Assert.Equal(0, refused);
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(4, search, [Keys(9, false)]), patience, out var unsorted)?.ResultCode);
        Assert.Equal(sorted, unsorted);
        // A request built to exhaust the server: 200,000 keys. It is not even read to the end.
        Assert.Equal((int)ResultCode.ProtocolError, client.Exchange(ClientEncoder.Encode(5, search, [Keys(200_000, false)]), patience, out _)?.ResultCode);
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(6, new Protocol.ExtendedRequest(Protocol.ExtendedRequest.WhoAmI, null)), patience)?.ResultCode);
        Assert.Empty(server.ProtocolErrors);
        Assert.Empty(server.InternalErrors);
    }

    [Fact]
    public void Paging_and_sorting_controls_mean_nothing_outside_a_search()
    {
        using var server = Generic().Start();
        using var client = new RawClient(server.Host, server.Port);
        var patience = TimeSpan.FromSeconds(10);
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(1, new BindRequest(3, server.Directory.UserDn("admin").ToString(), "admin-secret", null)), patience)?.ResultCode);
        var alice = server.Directory.UserDn("alice");
        LdapControl[] controls =
        [
            new(LdapEncoder.SortRequestOid, true, ClientEncoder.SortRequest(("cn", null, false))),
            new(LdapEncoder.PagedResultsOid, true, ClientEncoder.PagedResults(10, [])),
        ];

        foreach (var control in controls)
        {
            var refused = client.Exchange(ClientEncoder.Encode(2, new Protocol.DeleteRequest(alice.ToString()), [control]), patience);
            Assert.Equal((int)ResultCode.UnavailableCriticalExtension, refused?.ResultCode);
            Assert.True(server.Directory.Exists(alice));
        }
        // Not critical: ignored, as any control the operation does not know.
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(3, new Protocol.DeleteRequest(alice.ToString()), [controls[0] with { Critical = false }]), patience)?.ResultCode);
        Assert.False(server.Directory.Exists(alice));
    }

    [Fact]
    public void Sorting_comes_before_paging_and_before_the_size_limit()
    {
        using var server = ActiveDirectory().Start();
        using var connection = Connect(server);
        var sort = new SortRequestControl("sAMAccountName", true);

        var pages = new List<string[]>();
        var paging = new PageResultRequestControl(3);
        do
        {
            var request = new SdsSearchRequest(AdBase, "(objectClass=user)", SdsSearchScope.Subtree, "sAMAccountName");
            request.Controls.AddRange(new DirectoryControl[] { sort, paging });
            var response = (SearchResponse)connection.SendRequest(request);
            pages.Add(response.Entries.Cast<SearchResultEntry>().Select(e => Values(e, "sAMAccountName")[0]).ToArray());
            paging.Cookie = response.Controls.OfType<PageResultResponseControl>().Single().Cookie;
        } while (paging.Cookie.Length > 0);
        Assert.Equal([["carol", "Bob", "alice"], ["admin"]], pages);

        var limited = new SdsSearchRequest(AdBase, "(objectClass=user)", SdsSearchScope.Subtree, "sAMAccountName") { SizeLimit = 2 };
        limited.Controls.Add(sort);
        var e = Assert.Throws<DirectoryOperationException>(() => connection.SendRequest(limited));
        Assert.Equal(["carol", "Bob"], ((SearchResponse)e.Response).Entries.Cast<SearchResultEntry>().Select(x => Values(x, "sAMAccountName")[0]));
    }

    [Fact]
    public void A_broken_sort_request_is_refused_and_the_connection_survives()
    {
        using var server = Generic().Start();
        using var client = new RawClient(server.Host, server.Port);
        var patience = TimeSpan.FromSeconds(10);
        var bind = new BindRequest(3, server.Directory.UserDn("admin").ToString(), "admin-secret", null);
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(1, bind), patience)?.ResultCode);
        var search = new Protocol.SearchRequest("dc=example,dc=com", Protocol.SearchScope.WholeSubtree, 0, 0, false, new LdapFilter.Present("objectClass"), []);

        foreach (var value in new byte[]?[] { [0x04, 0x01, 0x41], ClientEncoder.SortRequest(), null })
        {
            var refused = client.Exchange(ClientEncoder.Encode(2, search, [new LdapControl(LdapEncoder.SortRequestOid, true, value)]), patience, out var entries);
            Assert.Equal((int)ResultCode.ProtocolError, refused?.ResultCode);
            Assert.Equal(0, entries);
        }

        var served = client.Exchange(ClientEncoder.Encode(3, search, [new LdapControl(LdapEncoder.SortRequestOid, true, ClientEncoder.SortRequest(("cn", "2.5.13.3", false)))]), patience, out var found);
        Assert.Equal(0, served?.ResultCode);
        Assert.True(found > 0);
        Assert.Empty(server.ProtocolErrors);
        Assert.Empty(server.InternalErrors);
    }

    // ---- the NTLM bind of Windows clients --------------------------------------------------------------------

    [Theory]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(11)]
    public void An_NTLM_bind_gets_a_clear_refusal_instead_of_a_dropped_connection(int choice)
    {
        using var server = ActiveDirectory().Start();
        using var client = new RawClient(server.Host, server.Port);
        var patience = TimeSpan.FromSeconds(10);
        byte[] ntlmNegotiate = [.. "NTLMSSP\0"u8, 1, 0, 0, 0, 0x07, 0x82, 0x08, 0xA2];

        var response = client.Exchange(ClientEncoder.SicilyBind(1, choice, "", ntlmNegotiate), patience);

        Assert.Equal((int)ResultCode.AuthMethodNotSupported, response?.ResultCode);
        Assert.Contains("AuthenticationTypes.None", response!.Message);
        Assert.Equal(BindRequest.Sicily, ((BindRequest)server.Requests.Single().Request).SaslMechanism);
        // The connection is still good for a simple bind.
        var bind = new BindRequest(3, "admin@corp.example.com", "admin-secret", null);
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(2, bind), patience)?.ResultCode);
        Assert.Empty(server.ProtocolErrors);
    }
}
