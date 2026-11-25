using DotLdap.Testing.Protocol;

namespace DotLdap.Testing.Tests;

public class DistinguishedNameTests
{
    [Fact]
    public void Equality_ignores_case_and_spacing()
    {
        var a = DistinguishedName.Parse("CN=Alice Smith, OU=Users,DC=Example,DC=com");
        var b = DistinguishedName.Parse("cn=alice smith,ou=users,dc=example,dc=com");
        Assert.Equal(a, b);
        Assert.Equal("CN=Alice Smith,OU=Users,DC=Example,DC=com", a.ToString());
    }

    [Fact]
    public void Escapes_are_parsed_and_written_back()
    {
        var dn = DistinguishedName.Parse(@"cn=Smith\, John,ou=R\26D,dc=example,dc=com");
        Assert.Equal("Smith, John", dn.Leaf!.Value);
        Assert.Equal("R&D", dn.Rdns[1].Value);
        Assert.Equal(@"cn=Smith\, John,ou=R&D,dc=example,dc=com", dn.ToString());
    }

    [Fact]
    public void Hierarchy()
    {
        var baseDn = DistinguishedName.Parse("dc=example,dc=com");
        var user = DistinguishedName.Parse("uid=a,ou=users,dc=example,dc=com");
        Assert.True(user.IsWithin(baseDn));
        Assert.False(user.IsChildOf(baseDn));
        Assert.True(user.Parent!.IsChildOf(baseDn));
        Assert.False(DistinguishedName.Parse("dc=notexample,dc=com").IsWithin(baseDn));
        Assert.True(baseDn.IsWithin(DistinguishedName.Root));
        // an escaped comma is part of a value, not the start of another RDN
        Assert.False(DistinguishedName.Parse(@"cn=a\,dc=example,dc=com").IsWithin(baseDn));
        Assert.True(DistinguishedName.Parse(@"cn=a\,b,dc=example,dc=com").IsWithin(baseDn));
    }

    [Theory]
    [InlineData("no-equals-sign")]
    [InlineData("cn=a,,dc=b")]
    public void Invalid_names_are_rejected(string dn) => Assert.False(DistinguishedName.TryParse(dn, out _));
}

public class FilterTests
{
    private static readonly InMemoryDirectory Directory = Seed();

    private static InMemoryDirectory Seed()
    {
        var d = new InMemoryDirectory();
        d.AddUser("alice", "pw", u => u.Email("alice@example.com").Attribute("uidNumber", "1001").MemberOf("devs"));
        d.AddUser("bob", "pw", u => u.Email("bob@example.org").Attribute("uidNumber", "20"));
        d.AddGroup("staff", "devs");
        return d;
    }

    private static string[] Find(string filter) =>
        Directory.Search("dc=example,dc=com", SearchScope.WholeSubtree, filter)
            .Select(e => e.Dn.Leaf!.Value).OrderBy(x => x).ToArray();

    [Theory]
    [InlineData("(uid=ALICE)", "alice")]
    [InlineData("(&(objectClass=person)(mail=*@example.com))", "alice")]
    [InlineData("(|(uid=alice)(uid=bob))", "alice,bob")]
    [InlineData("(&(objectClass=inetOrgPerson)(!(uid=alice)))", "bob")]
    [InlineData("(mail=*example*)", "alice,bob")]
    [InlineData("(mail=a*@*.com)", "alice")]
    [InlineData("(uidNumber>=100)", "alice")]
    [InlineData("(uidNumber<=100)", "bob")]
    [InlineData("(memberOf=cn=devs,ou=groups,dc=example,dc=com)", "alice")]
    [InlineData("(memberOf:1.2.840.113556.1.4.1941:=cn=staff,ou=groups,dc=example,dc=com)", "alice,devs")]
    [InlineData("(member:1.2.840.113556.1.4.1941:=uid=alice,ou=users,dc=example,dc=com)", "devs,staff")]
    [InlineData("(uidNumber:1.2.840.113556.1.4.803:=1)", "alice")]
    [InlineData("(ou:dn:=users)", "alice,bob,users")]
    [InlineData("(description=*)", "")]
    public void Filters_select_the_expected_entries(string filter, string expected) =>
        Assert.Equal(expected, string.Join(",", Find(filter)));

    [Theory]
    [InlineData("(&(a=b)(|(c=d*e)(!(f>=1))))")]
    [InlineData("(cn=a\\2ab)")]
    [InlineData("(memberOf:1.2.840.113556.1.4.1941:=cn=x)")]
    public void Text_form_round_trips(string filter) => Assert.Equal(filter, LdapFilter.Parse(filter).ToString());
}

public class LdifTests
{
    private const string Ldif = """
        version: 1

        # a user with a folded line and a base64 value
        dn: uid=carol,ou=people,dc=example,dc=com
        objectClass: inetOrgPerson
        uid: carol
        cn:: Q2Fyb2wgw5E=
        description: first part,
          second part
        userPassword: {SSHA}5en6G6MezRroT3XKqkdPOmY/BfQ=

        dn: cn=admins,ou=groups,dc=example,dc=com
        objectClass: groupOfNames
        member: uid=carol,ou=people,dc=example,dc=com
        """;

    [Fact]
    public void Parses_entries()
    {
        var entries = LdifReader.Parse(Ldif);
        Assert.Equal(2, entries.Count);
        Assert.Equal("Carol Ñ", entries[0].GetString("cn"));
        Assert.Equal("first part, second part", entries[0].GetString("description"));
    }

    [Fact]
    public void Loading_creates_missing_parents_and_computes_memberOf()
    {
        var directory = new InMemoryDirectory();
        directory.AddLdif(Ldif);
        Assert.True(directory.Exists("ou=people,dc=example,dc=com"));
        var carol = directory.Search("dc=example,dc=com", SearchScope.WholeSubtree, "(uid=carol)").Single();
        Assert.Equal("cn=admins,ou=groups,dc=example,dc=com", carol.GetString("memberOf"));
    }
}

public class PasswordTests
{
    [Theory]
    [InlineData("secret", "secret", true)]
    [InlineData("secret", "Secret", false)]
    [InlineData("{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=", "secret", true)]
    [InlineData("{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=", "wrong", false)]
    [InlineData("{CRYPT}xx", "xx", false)]
    public void Verifies(string stored, string password, bool expected) =>
        Assert.Equal(expected, PasswordVerifier.Verify([System.Text.Encoding.UTF8.GetBytes(stored)], password));

    [Fact]
    public void Verifies_salted_hash()
    {
        var salt = new byte[] { 1, 2, 3, 4 };
        var digest = System.Security.Cryptography.SHA1.HashData([.. "secret"u8, .. salt]);
        var stored = "{SSHA}" + Convert.ToBase64String([.. digest, .. salt]);
        Assert.True(PasswordVerifier.Verify([System.Text.Encoding.UTF8.GetBytes(stored)], "secret"));
        Assert.False(PasswordVerifier.Verify([System.Text.Encoding.UTF8.GetBytes(stored)], "other"));
    }
}

public class SeedOrderTests
{
    [Fact]
    public void A_parent_listed_after_its_child_takes_the_place_of_the_generated_one()
    {
        var directory = new InMemoryDirectory();
        directory.AddLdif("""
            dn: uid=carol,ou=people,dc=example,dc=com
            objectClass: inetOrgPerson
            uid: carol

            dn: ou=people,dc=example,dc=com
            objectClass: organizationalUnit
            ou: people
            description: listed late
            """);
        Assert.Equal("listed late", directory.Find("ou=people,dc=example,dc=com")!.GetString("description"));
        Assert.True(directory.Exists("uid=carol,ou=people,dc=example,dc=com"));
        // only a generated parent gives way: a second explicit entry is still an error
        Assert.Throws<InvalidOperationException>(() => directory.Add("ou=people,dc=example,dc=com", e => e.Set("objectClass", "organizationalUnit")));
    }
}
