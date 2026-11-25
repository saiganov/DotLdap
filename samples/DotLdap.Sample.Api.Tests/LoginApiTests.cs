using System.Net;
using System.Net.Http.Json;
using DotLdap.Testing;
using DotLdap.Testing.Protocol;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace DotLdap.Sample.Api.Tests;

/// <summary>
/// The API as it runs in production, with one change: the LDAP settings point at a test server. Each test builds
/// the directory it needs in a few lines, and can look at what the API asked the directory.
/// </summary>
public sealed class LoginApiTests : IDisposable
{
    private const string Staff = "cn=staff,ou=groups,dc=example,dc=com";

    private readonly LdapTestServer _ldap = LdapTestServer.Create()
        .WithEntry("ou=services,dc=example,dc=com", e => e.Set("objectClass", "organizationalUnit").Set("ou", "services"))
        .WithEntry("uid=svc-web,ou=services,dc=example,dc=com", e => e
            .Set("objectClass", "account", "simpleSecurityObject").Set("uid", "svc-web").Set("userPassword", "svc-secret"))
        .WithUser("alice", "alice-secret", u => u.DisplayName("Alice Liddell").Email("alice@example.com").MemberOf("staff"))
        .WithUser("bob", "bob-secret", u => u.MemberOf("contractors"))
        .Start();

    private readonly WebApplicationFactory<Program> _api;
    private readonly HttpClient _client;

    public LoginApiTests()
    {
        try
        {
            _api = new WebApplicationFactory<Program>().WithWebHostBuilder(host => host
                .UseSetting("Ldap:Url", _ldap.Url)
                .UseSetting("Ldap:ServicePassword", "svc-secret")
                .UseSetting("Ldap:AllowedGroup", Staff));
            _client = _api.CreateClient();
        }
        catch
        {
            // xunit does not call Dispose when the constructor throws: do not leave the server listening.
            _api?.Dispose();
            _ldap.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        try
        {
            _client.Dispose();
            _api.Dispose();
        }
        finally
        {
            _ldap.Dispose();
        }
    }

    private Task<HttpResponseMessage> LogIn(string user, string password) =>
        _client.PostAsJsonAsync("/login", new { user, password }, TestContext.Current.CancellationToken);

    [Fact]
    public async Task A_member_of_the_allowed_group_logs_in_and_gets_their_name_and_groups()
    {
        var response = await LogIn("alice", "alice-secret");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var user = await response.Content.ReadFromJsonAsync<User>(TestContext.Current.CancellationToken);
        Assert.Equal("Alice Liddell", user!.DisplayName);
        Assert.Equal("alice@example.com", user.Email);
        Assert.Equal([Staff], user.Groups);
    }

    [Theory]
    [InlineData("alice", "wrong")]
    [InlineData("nobody", "whatever")]
    [InlineData("alice", "")]
    public async Task A_wrong_name_or_password_is_401(string user, string password)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await LogIn(user, password)).StatusCode);
    }

    [Fact]
    public async Task A_user_outside_the_allowed_group_is_403()
    {
        Assert.Equal(HttpStatusCode.Forbidden, (await LogIn("bob", "bob-secret")).StatusCode);
    }

    [Fact]
    public async Task A_name_cannot_change_the_search_filter()
    {
        // "*" would match every user if it went into the filter as it is.
        Assert.Equal(HttpStatusCode.Unauthorized, (await LogIn("*", "alice-secret")).StatusCode);
        var search = (SearchRequest)_ldap.Last<SearchRequest>()!.Request;
        Assert.Equal(@"(&(objectClass=inetOrgPerson)(uid=\2a))", search.Filter.ToString());
    }

    [Fact]
    public async Task The_api_binds_as_its_service_account_then_as_the_user()
    {
        await LogIn("alice", "alice-secret");

        var binds = _ldap.Requests.Where(r => r.Request is BindRequest).Select(r => ((BindRequest)r.Request).Name).ToArray();
        Assert.Equal(["uid=svc-web,ou=services,dc=example,dc=com", "uid=alice,ou=users,dc=example,dc=com"], binds);
    }

    [Fact]
    public async Task A_directory_that_is_down_is_503_not_a_wrong_password()
    {
        // Fault injection: every bind is answered "unavailable", as by a domain controller that is shutting down.
        using var _ = _ldap.Intercept(context => context.Request is BindRequest ? new LdapResult(ResultCode.Unavailable) : null);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await LogIn("alice", "alice-secret")).StatusCode);
    }

    [Fact]
    public async Task A_directory_that_goes_down_before_the_user_bind_is_503_not_a_wrong_password()
    {
        // The server stops while the user's bind is on its way: the client sees the connection drop, not an answer.
        using var interception = _ldap.Intercept(context =>
        {
            if (context.Request is not BindRequest { Name: "uid=alice,ou=users,dc=example,dc=com" }) return null;
            // A thread of its own, not the thread pool, which this interceptor is holding a thread of.
            new Thread(_ldap.Dispose) { IsBackground = true }.Start();
            WaitUntilStopped();
            return null;
        });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await LogIn("alice", "alice-secret")).StatusCode);
    }

    /// <summary>Waits until the server no longer takes connections, which it stops doing before it closes them.</summary>
    private void WaitUntilStopped()
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var probe = new System.Net.Sockets.TcpClient();
                probe.Connect(_ldap.Host, _ldap.Port);
            }
            catch (System.Net.Sockets.SocketException)
            {
                Thread.Sleep(100); // give the server a moment to close the open connections too
                return;
            }
            Thread.Sleep(20);
        }
        throw new TimeoutException("The server did not stop.");
    }

    [Theory]
    [InlineData("a*", @"a\2a")]
    [InlineData("a(b", @"a\28b")]
    [InlineData("a)b", @"a\29b")]
    [InlineData(@"a\b", @"a\5cb")]
    [InlineData("a\0b", @"a\00b")]
    public async Task Filter_characters_in_a_name_are_escaped(string name, string escaped)
    {
        await LogIn(name, "whatever");

        var search = (SearchRequest)_ldap.Last<SearchRequest>()!.Request;
        Assert.Equal($"(&(objectClass=inetOrgPerson)(uid={escaped}))", search.Filter.ToString());
    }

    [Fact]
    public async Task Two_entries_with_one_login_name_log_nobody_in()
    {
        _ldap.Directory.Add("ou=partners,dc=example,dc=com", e => e.Set("objectClass", "organizationalUnit").Set("ou", "partners"));
        _ldap.Directory.Add("uid=alice,ou=partners,dc=example,dc=com", e => e
            .Set("objectClass", "inetOrgPerson").Set("uid", "alice").Set("cn", "alice").Set("sn", "alice").Set("userPassword", "alice-secret"));

        Assert.Equal(HttpStatusCode.Unauthorized, (await LogIn("alice", "alice-secret")).StatusCode);
    }

    [Fact]
    public async Task The_allowed_group_is_compared_as_a_dn_ignoring_case()
    {
        using var api = new WebApplicationFactory<Program>().WithWebHostBuilder(host => host
            .UseSetting("Ldap:Url", _ldap.Url)
            .UseSetting("Ldap:ServicePassword", "svc-secret")
            .UseSetting("Ldap:AllowedGroup", "CN=Staff,OU=Groups,DC=example,DC=com"));
        using var client = api.CreateClient();

        var response = await client.PostAsJsonAsync("/login", new { user = "alice", password = "alice-secret" }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public void The_api_takes_its_settings_through_the_validation()
    {
        Assert.Contains(_api.Services.GetServices<IValidateOptions<LdapSettings>>(), v => v is LdapSettingsValidation);
    }

    [Theory]
    [InlineData("ldap://dc.example.com", true)]
    [InlineData("ldaps://dc.example.com:636", true)]
    [InlineData("http://dc.example.com", false)]
    [InlineData("dc.example.com", false)]
    [InlineData("", false)]
    public void Only_an_ldap_or_ldaps_url_is_accepted(string url, bool valid)
    {
        // Checked on the validator itself: a host that fails to start disposes its services while
        // WebApplicationFactory still uses them, so which exception a startup test sees depends on timing.
        Assert.Equal(valid, new LdapSettingsValidation().Validate(null, new LdapSettings { Url = url }).Succeeded);
    }

    [Theory]
    [InlineData("ldap://dc.example.com", "dc.example.com", 389, false)]
    [InlineData("ldaps://dc.example.com", "dc.example.com", 636, true)]
    [InlineData("ldap://dc.example.com:10389", "dc.example.com", 10389, false)]
    [InlineData("ldaps://dc.example.com:10636", "dc.example.com", 10636, true)]
    public void An_ldaps_url_turns_on_tls_and_a_missing_port_gets_the_standard_one(string url, string host, int port, bool secure)
    {
        Assert.Equal((host, port, secure), DirectoryLogin.Endpoint(url));
    }

    [Fact]
    public void An_interceptor_can_be_checked_on_its_own_without_a_server()
    {
        // The same fault injection as above, as a function of its own, with requests made by hand.
        LdapRequestInterceptor failUserBinds = context =>
            context.Request is BindRequest { Name: "uid=alice,ou=users,dc=example,dc=com" } ? new LdapResult(ResultCode.Unavailable) : null;

        var userBind = new LdapRequestContext { Request = new BindRequest { Name = "uid=alice,ou=users,dc=example,dc=com", Password = "x" } };
        Assert.Equal(ResultCode.Unavailable, failUserBinds(userBind)?.Code);
        Assert.Null(failUserBinds(userBind with { Request = new BindRequest { Name = "uid=svc-web,ou=services,dc=example,dc=com" } }));
        Assert.Null(failUserBinds(new LdapRequestContext { Request = new SearchRequest { BaseDn = "dc=example,dc=com" } }));
    }

    [Fact]
    public async Task A_password_changed_in_the_directory_counts_at_once()
    {
        _ldap.Directory.Update("uid=alice,ou=users,dc=example,dc=com", e => e.Set("userPassword", "new-secret"));

        Assert.Equal(HttpStatusCode.Unauthorized, (await LogIn("alice", "alice-secret")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await LogIn("alice", "new-secret")).StatusCode);
    }

    private sealed record User(string Dn, string Name, string? DisplayName, string? Email, string[] Groups);
}
