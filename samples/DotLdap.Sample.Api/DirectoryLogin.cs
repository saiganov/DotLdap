using System.DirectoryServices.Protocols;
using System.Net;
using Microsoft.Extensions.Options;

namespace DotLdap.Sample.Api;

internal sealed class LdapSettings
{
    public string Url { get; set; } = "";
    public string BaseDn { get; set; } = "";
    public string ServiceDn { get; set; } = "";
    public string ServicePassword { get; set; } = "";

    /// <summary>The group a user must be a member of to log in; empty lets every user in.</summary>
    public string AllowedGroup { get; set; } = "";
}

/// <summary>Checks the settings when the application starts, so a wrong URL fails there rather than at the first login.</summary>
internal sealed class LdapSettingsValidation : IValidateOptions<LdapSettings>
{
    public ValidateOptionsResult Validate(string? name, LdapSettings options) =>
        Uri.TryCreate(options.Url, UriKind.Absolute, out var url) && url.Scheme is "ldap" or "ldaps"
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail($"Ldap:Url must be an ldap:// or ldaps:// URL, not '{options.Url}'.");
}

internal enum LoginStatus
{
    Success,
    WrongNameOrPassword,
    NotInAllowedGroup,
    DirectoryUnavailable,
}

internal sealed record DirectoryUser(string Dn, string Name, string? DisplayName, string? Email, IReadOnlyList<string> Groups);

internal sealed record LoginOutcome(LoginStatus Status, DirectoryUser? User = null);

/// <summary>
/// The classic LDAP login: bind as a service account, find the user by login name, then bind as that user with the
/// password they typed. Group membership comes from memberOf.
/// </summary>
internal sealed class DirectoryLogin(IOptions<LdapSettings> options, ILogger<DirectoryLogin> logger)
{
    private readonly LdapSettings _settings = options.Value;

    public LoginOutcome LogIn(string user, string password)
    {
        // An empty password would be an "unauthenticated bind", which many servers answer with success.
        if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password)) return new(LoginStatus.WrongNameOrPassword);
        try
        {
            using var service = Connect(_settings.ServiceDn, _settings.ServicePassword);
            var found = Find(service, user);
            if (found is null) return new(LoginStatus.WrongNameOrPassword);

            try
            {
                using var asUser = Connect(found.Dn, password);
            }
            catch (LdapException e) when (e.ErrorCode == 49) // invalidCredentials
            {
                return new(LoginStatus.WrongNameOrPassword);
            }

            if (_settings.AllowedGroup.Length > 0
                && !found.Groups.Contains(_settings.AllowedGroup, StringComparer.OrdinalIgnoreCase))
                return new(LoginStatus.NotInAllowedGroup, found);
            return new(LoginStatus.Success, found);
        }
        catch (Exception e) when (e is LdapException or DirectoryOperationException)
        {
            logger.LogError(e, "The directory could not be asked about {User}", user);
            return new(LoginStatus.DirectoryUnavailable);
        }
    }

    private DirectoryUser? Find(LdapConnection service, string user)
    {
        var filter = $"(&(objectClass=inetOrgPerson)(uid={Escape(user)}))";
        var request = new SearchRequest(_settings.BaseDn, filter, SearchScope.Subtree, "uid", "displayName", "mail", "memberOf");
        var response = (SearchResponse)service.SendRequest(request);
        if (response.Entries.Count != 1) return null;
        var entry = response.Entries[0];
        return new DirectoryUser(
            entry.DistinguishedName,
            First(entry, "uid") ?? user,
            First(entry, "displayName"),
            First(entry, "mail"),
            All(entry, "memberOf"));
    }

    private LdapConnection Connect(string dn, string password)
    {
        var (host, port, secure) = Endpoint(_settings.Url);
        var connection = new LdapConnection(new LdapDirectoryIdentifier(host, port))
        {
            AuthType = AuthType.Basic,
            Timeout = TimeSpan.FromSeconds(10),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = secure;
        try
        {
            connection.Bind(new NetworkCredential(dn, password));
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    /// <summary>Host, port and TLS from an ldap:// or ldaps:// URL; a URL without a port gets the standard one.</summary>
    internal static (string Host, int Port, bool Secure) Endpoint(string url)
    {
        var uri = new Uri(url);
        var secure = uri.Scheme switch
        {
            "ldap" => false,
            "ldaps" => true,
            _ => throw new InvalidOperationException($"Ldap:Url must start with ldap:// or ldaps://, not '{uri.Scheme}://'."),
        };
        // Uri knows no default port for ldaps (it reports -1), so the standard ports are filled in here.
        var port = uri.IsDefaultPort || uri.Port < 0 ? (secure ? 636 : 389) : uri.Port;
        return (uri.Host, port, secure);
    }

    private static string? First(SearchResultEntry entry, string name) =>
        entry.Attributes.Contains(name) ? (string)entry.Attributes[name][0] : null;

    private static string[] All(SearchResultEntry entry, string name) =>
        entry.Attributes.Contains(name) ? entry.Attributes[name].GetValues(typeof(string)).Cast<string>().ToArray() : [];

    /// <summary>Escapes a value for a search filter (RFC 4515), so a user name cannot change the filter.</summary>
    private static string Escape(string value) => string.Concat(value.Select(c => c switch
    {
        '*' => @"\2a",
        '(' => @"\28",
        ')' => @"\29",
        '\\' => @"\5c",
        '\0' => @"\00",
        _ => c.ToString(),
    }));
}
