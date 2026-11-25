using DotLdap.Testing;
using DotLdap.Testing.Protocol;

namespace DotLdap.Sample.ActiveDirectory.Tests;

/// <summary>
/// The account code against the Active Directory flavour: login names, the data codes a domain controller puts in
/// its refusals, nested groups and password resets, without a domain controller.
/// </summary>
public sealed class AccountServiceTests : IDisposable
{
    private const string Domain = "DC=corp,DC=example,DC=com";

    private readonly LdapTestServer _dc = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(Domain)
        .WithUser("svc-accounts", "svc-secret")
        .WithUser("alice", "alice-secret", u => u.DisplayName("Alice Liddell"))
        .WithUser("bob", "bob-secret", u => u.Disabled())
        .WithUser("carol", "carol-secret", u => u.LockedOut())
        .WithUser("dave", "dave-secret", u => u.MustChangePassword())
        .WithUser("erin", "erin-secret", u => u.PasswordExpired())
        .WithUser("frank", "frank-secret", u => u.AccountExpired())
        .WithGroup("Developers", "alice")
        .WithGroup("Engineering", "Developers")
        .WithGroup("Everyone in Oslo", "Engineering")
        .WithTls() // a self-signed certificate for 127.0.0.1, made for this server
        .Start();

    private readonly AccountService _accounts;

    public AccountServiceTests()
    {
        _accounts = new AccountService(Settings(_dc));
    }

    public void Dispose() => _dc.Dispose();

    /// <summary>ldaps:// as in production, trusting exactly the certificate of this test server.</summary>
    private static DomainSettings Settings(LdapTestServer dc) =>
        new(dc.Host, dc.LdapsPort!.Value, Domain, "svc-accounts@corp.example.com", "svc-secret")
        {
            ValidateCertificate = (_, certificate, _, _) => certificate?.GetCertHashString() == dc.Certificate!.GetCertHashString(),
        };

    [Theory]
    [InlineData("alice@corp.example.com")]
    [InlineData(@"CORP\alice")]
    [InlineData("CN=alice,CN=Users," + Domain)]
    public void A_user_logs_in_by_any_of_the_names_a_domain_controller_takes(string name)
    {
        Assert.Equal(LoginResult.Success, _accounts.LogIn(name, "alice-secret"));
    }

    [Theory]
    [InlineData("alice@corp.example.com", "wrong", LoginResult.WrongPassword)]
    [InlineData("nobody@corp.example.com", "whatever", LoginResult.NoSuchUser)]
    [InlineData("bob@corp.example.com", "bob-secret", LoginResult.AccountDisabled)]
    [InlineData("carol@corp.example.com", "carol-secret", LoginResult.AccountLockedOut)]
    [InlineData("dave@corp.example.com", "dave-secret", LoginResult.MustChangePassword)]
    [InlineData("erin@corp.example.com", "erin-secret", LoginResult.PasswordExpired)]
    [InlineData("frank@corp.example.com", "frank-secret", LoginResult.AccountExpired)]
    [InlineData("alice@corp.example.com", "", LoginResult.Refused)] // an empty password would be an unauthenticated bind, which succeeds
    [InlineData("bob@corp.example.com", "wrong", LoginResult.WrongPassword)] // the state of an account is told only to its password
    public void A_refusal_says_why_as_a_domain_controller_does(string name, string password, LoginResult expected)
    {
        Assert.Equal(expected, _accounts.LogIn(name, password));
    }

    [Fact]
    public void A_data_code_in_capitals_is_read_the_same()
    {
        using var _ = _dc.Intercept(c => c.Request is BindRequest { Name: "alice@corp.example.com" }
            ? new LdapResult(ResultCode.InvalidCredentials, "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52E, v4563")
            : null);

        Assert.Equal(LoginResult.WrongPassword, _accounts.LogIn("alice@corp.example.com", "alice-secret"));
    }

    [Fact]
    public void A_name_with_a_wildcard_finds_nobody_rather_than_the_one_user_it_matches()
    {
        // Unescaped, "al*" would match exactly alice and return her groups.
        Assert.Throws<InvalidOperationException>(() => _accounts.GroupsOf("al*"));
        var search = (SearchRequest)_dc.Last<SearchRequest>()!.Request;
        Assert.Contains(@"(sAMAccountName=al\2a)", search.Filter.ToString());
    }

    [Fact]
    public void Two_accounts_with_one_name_count_as_no_account()
    {
        _dc.Directory.Add("CN=alice2,CN=Users," + Domain, e => e
            .Set("objectClass", "top", "person", "organizationalPerson", "user").Set("cn", "alice2").Set("sAMAccountName", "alice"));

        Assert.Throws<InvalidOperationException>(() => _accounts.GroupsOf("alice"));
    }

    [Fact]
    public void Continuation_references_in_a_search_are_skipped_as_on_a_real_domain_controller()
    {
        // A real domain controller answers a subtree search from the domain root with references to its
        // application partitions as well as the entries.
        using var dc = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(Domain)
            .WithUser("svc-accounts", "svc-secret").WithUser("alice", "alice-secret")
            .WithGroup("Developers", "alice")
            .WithReferral("DC=DomainDnsZones," + Domain, "ldap://DomainDnsZones.corp.example.com/DC=DomainDnsZones," + Domain)
            .WithTls()
            .Start();

        Assert.Equal(["Developers"], new AccountService(Settings(dc)).GroupsOf("alice"));
    }

    [Fact]
    public void Groups_include_the_ones_a_user_is_in_through_other_groups()
    {
        Assert.Equal(["Developers", "Engineering", "Everyone in Oslo"], _accounts.GroupsOf("alice"));
    }

    [Fact]
    public void A_reset_password_works_at_once_and_can_be_made_to_expire()
    {
        _accounts.ResetPassword("alice", "N3w-Passw0rd!", mustChange: false);
        Assert.Equal(LoginResult.WrongPassword, _accounts.LogIn("alice@corp.example.com", "alice-secret"));
        Assert.Equal(LoginResult.Success, _accounts.LogIn("alice@corp.example.com", "N3w-Passw0rd!"));

        _accounts.ResetPassword("alice", "Temp-Passw0rd!", mustChange: true);
        Assert.Equal(LoginResult.MustChangePassword, _accounts.LogIn("alice@corp.example.com", "Temp-Passw0rd!"));
    }

    [Fact]
    public void A_server_that_wants_tls_for_passwords_takes_this_reset_because_it_comes_over_ldaps()
    {
        // As a real domain controller does; code that sent the reset over plain ldap:// would fail here.
        using var strict = LdapTestServer.Create().AsActiveDirectory().WithBaseDn(Domain)
            .WithUser("svc-accounts", "svc-secret").WithUser("alice", "alice-secret")
            .WithOptions(o => o.RequireTlsForUnicodePwd = true)
            .WithTls()
            .Start();

        new AccountService(Settings(strict)).ResetPassword("alice", "N3w-Passw0rd!", mustChange: false);

        var reset = strict.Last<ModifyRequest>()!;
        Assert.True(reset.IsTls);
        Assert.Equal(ResultCode.Success, reset.Result!.Code);
    }
}
