using Novell.Directory.Ldap;

namespace DotLdap.Testing.Benchmarks;

/// <summary>
/// The managed Novell client: the same code on every OS, with no native LDAP library whose cost would be measured
/// along with the server's.
/// </summary>
internal static class Client
{
    public static LdapConnection Connect(string host, int port, string dn, string password)
    {
        var connection = new LdapConnection();
        connection.Connect(host, port);
        connection.Bind(dn, password);
        return connection;
    }

    public static int Count(LdapConnection connection, string baseDn, string filter, int scope = LdapConnection.ScopeSub)
    {
        var results = connection.Search(baseDn, scope, filter, ["cn"], false);
        var count = 0;
        while (results.HasMore())
        {
            results.Next();
            count++;
        }
        return count;
    }
}
