using System.Text;
using System.Text.RegularExpressions;
using Novell.Directory.Ldap;

namespace DotLdap.Sample.ActiveDirectory;

/// <summary>Why a domain controller refused a login, from the data code in its error message.</summary>
public enum LoginResult
{
    Success,
    WrongPassword,
    NoSuchUser,
    AccountDisabled,
    AccountLockedOut,
    AccountExpired,
    PasswordExpired,
    MustChangePassword,
    Refused,
}

/// <summary>Where the domain is and how the service account logs in.</summary>
/// <param name="Host">The domain controller.</param>
/// <param name="Port">Its ldaps:// port, 636 in production.</param>
/// <param name="BaseDn">The domain, such as <c>DC=corp,DC=example,DC=com</c>.</param>
/// <param name="ServiceUser">The account the service searches and resets passwords with.</param>
/// <param name="ServicePassword">Its password.</param>
public sealed record DomainSettings(string Host, int Port, string BaseDn, string ServiceUser, string ServicePassword)
{
    /// <summary>
    /// Decides whether to trust the domain controller's certificate. Null leaves it to the machine's trust store,
    /// which is what production wants.
    /// </summary>
    public System.Net.Security.RemoteCertificateValidationCallback? ValidateCertificate { get; init; }
}

/// <summary>
/// What a typical line-of-business application does with Active Directory over ldaps://: log a user in by UPN or
/// <c>DOMAIN\user</c> and say why it failed, list the user's groups including nested ones, and reset a password.
/// </summary>
public sealed partial class AccountService(DomainSettings settings)
{
    /// <summary>Logs a user in. The reason for a refusal is the data code in the domain controller's message.</summary>
    public LoginResult LogIn(string user, string password)
    {
        if (string.IsNullOrEmpty(password)) return LoginResult.Refused;
        try
        {
            using var connection = Connect(user, password);
            return LoginResult.Success;
        }
        catch (LdapException e) when (e.ResultCode == LdapException.InvalidCredentials)
        {
            // "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563"
            // Do not tell the person at the keyboard WrongPassword from NoSuchUser: that would reveal which accounts
            // exist (and many domain controllers answer 52e for both).
            var data = DataCode().Match(e.LdapErrorMessage ?? "");
            return (data.Success ? data.Groups[1].Value.ToLowerInvariant() : "") switch
            {
                "52e" => LoginResult.WrongPassword,
                "525" => LoginResult.NoSuchUser,
                "533" => LoginResult.AccountDisabled,
                "775" => LoginResult.AccountLockedOut,
                "701" => LoginResult.AccountExpired,
                "532" => LoginResult.PasswordExpired,
                "773" => LoginResult.MustChangePassword,
                _ => LoginResult.Refused,
            };
        }
    }

    /// <summary>
    /// The names of every group the user is in, directly or through other groups: one search with the
    /// LDAP_MATCHING_RULE_IN_CHAIN rule instead of walking memberOf by hand. Like Active Directory itself it
    /// leaves out the primary group (Domain Users), which no member attribute lists.
    /// </summary>
    public IReadOnlyList<string> GroupsOf(string samAccountName)
    {
        using var connection = Connect(settings.ServiceUser, settings.ServicePassword);
        var user = FindUser(connection, samAccountName) ?? throw new InvalidOperationException($"No user {samAccountName}.");
        var groups = connection.Search(settings.BaseDn, LdapConnection.ScopeSub,
            $"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={EscapeFilter(user)}))", ["cn"], false);
        var names = new List<string>();
        foreach (var entry in Entries(groups)) names.Add(entry.GetAttribute("cn").StringValue);
        return names.Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>
    /// Sets a new password as an administrator would: unicodePwd, replaced with the password in quotes as UTF-16.
    /// The user must change it at the next login when <paramref name="mustChange"/> is true.
    /// </summary>
    public void ResetPassword(string samAccountName, string newPassword, bool mustChange)
    {
        using var connection = Connect(settings.ServiceUser, settings.ServicePassword);
        var user = FindUser(connection, samAccountName) ?? throw new InvalidOperationException($"No user {samAccountName}.");
        connection.Modify(user,
        [
            new LdapModification(LdapModification.Replace, new LdapAttribute("unicodePwd", Encoding.Unicode.GetBytes($"\"{newPassword}\""))),
            new LdapModification(LdapModification.Replace, new LdapAttribute("pwdLastSet", mustChange ? "0" : "-1")),
        ]);
    }

    private string? FindUser(LdapConnection connection, string samAccountName)
    {
        var results = connection.Search(settings.BaseDn, LdapConnection.ScopeSub,
            $"(&(objectCategory=person)(sAMAccountName={EscapeFilter(samAccountName)}))", ["distinguishedName"], false);
        var found = Entries(results).Select(e => e.Dn).ToList();
        return found.Count == 1 ? found[0] : null;
    }

    /// <summary>
    /// The entries of a search, without its continuation references: a subtree search from the domain root of a real
    /// domain controller also returns references to DomainDnsZones, ForestDnsZones and Configuration, which Novell
    /// reports as an LdapReferralException from Next() when it does not follow referrals.
    /// </summary>
    private static IEnumerable<LdapEntry> Entries(ILdapSearchResults results)
    {
        while (results.HasMore())
        {
            LdapEntry entry;
            try
            {
                entry = results.Next();
            }
            catch (LdapReferralException)
            {
                continue;
            }
            yield return entry;
        }
    }

    private LdapConnection Connect(string user, string password)
    {
        var options = new LdapConnectionOptions().UseSsl();
        if (settings.ValidateCertificate is { } validate) options = options.ConfigureRemoteCertificateValidationCallback(validate);
        var connection = new LdapConnection(options) { ConnectionTimeout = 10_000 };
        try
        {
            connection.Connect(settings.Host, settings.Port);
            connection.Bind(user, password);
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private static string EscapeFilter(string value) => string.Concat(value.Select(c => c switch
    {
        '*' => @"\2a",
        '(' => @"\28",
        ')' => @"\29",
        '\\' => @"\5c",
        '\0' => @"\00",
        _ => c.ToString(),
    }));

    [GeneratedRegex(@"data ([0-9a-fA-F]+)")]
    private static partial Regex DataCode();
}
