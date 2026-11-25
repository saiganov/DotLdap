using DotLdap.Testing;

namespace DotLdap.Sample.Standalone;

/// <summary>What the console program can be told on its command line.</summary>
internal sealed record StandaloneSettings(int Port = 10389, int LdapsPort = 10636, bool ActiveDirectory = false, string? LdifFile = null)
{
    public static StandaloneSettings Parse(string[] args)
    {
        var settings = new StandaloneSettings();
        for (var i = 0; i < args.Length; i++)
        {
            settings = args[i] switch
            {
                "--port" => settings with { Port = int.Parse(args[++i], System.Globalization.CultureInfo.InvariantCulture) },
                "--ldaps-port" => settings with { LdapsPort = int.Parse(args[++i], System.Globalization.CultureInfo.InvariantCulture) },
                "--ad" => settings with { ActiveDirectory = true },
                "--ldif" => settings with { LdifFile = args[++i] },
                _ => throw new ArgumentException($"Unknown option '{args[i]}'. Options: --port N, --ldaps-port N, --ad, --ldif FILE."),
            };
        }
        return settings;
    }
}

/// <summary>A test server with a few users and groups, on fixed ports, with TLS.</summary>
internal static class StandaloneServer
{
    public static LdapTestServer Start(StandaloneSettings settings)
    {
        var builder = LdapTestServer.Create().WithTls().WithPorts(settings.Port, settings.LdapsPort);
        if (settings.ActiveDirectory) builder.AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com");
        builder
            .WithUser("alice", "alice-secret", u => u.Email("alice@example.com").DisplayName("Alice Liddell").MemberOf("admins", "staff"))
            .WithUser("bob", "bob-secret", u => u.MemberOf("staff"));
        if (settings.LdifFile is not null) builder.WithLdifFile(settings.LdifFile);
        return builder.Start();
    }

    /// <summary>The commands that try the server out, for the console.</summary>
    public static IEnumerable<string> Instructions(LdapTestServer server)
    {
        var alice = server.Directory.UserDn("alice");
        yield return $"Listening on {server.Url} and {server.LdapsUrl}; base DN {server.BaseDn}.";
        yield return "Server certificate written to dotldap-ca.pem. Try:";
        yield return $"  ldapsearch -H {server.Url} -x -D '{alice}' -w alice-secret -b '{server.BaseDn}' '(objectClass=*)' '*' +";
        yield return $"  LDAPTLS_CACERT=dotldap-ca.pem ldapwhoami -H {server.LdapsUrl} -x -D '{alice}' -w alice-secret";
        yield return "Every request is printed below. Press Ctrl+C to stop.";
    }
}
