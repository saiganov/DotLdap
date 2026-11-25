using Novell.Directory.Ldap;

namespace DotLdap.Sample.Standalone.Tests;

/// <summary>The console server as a client outside the process sees it: over TCP, on the ports it was given.</summary>
public sealed class StandaloneServerTests
{
    [Fact]
    public void A_client_logs_in_over_ldaps_and_searches()
    {
        // Port 0: a free port, so the test does not depend on 10389 being available.
        using var server = StandaloneServer.Start(new StandaloneSettings(Port: 0, LdapsPort: 0));
        var options = new LdapConnectionOptions().UseSsl()
            .ConfigureRemoteCertificateValidationCallback((_, certificate, _, _) => certificate?.GetCertHashString() == server.Certificate!.GetCertHashString());
        using var connection = new LdapConnection(options);
        connection.Connect(server.Host, server.LdapsPort!.Value);
        connection.Bind("uid=alice,ou=users,dc=example,dc=com", "alice-secret");

        var results = connection.Search("dc=example,dc=com", LdapConnection.ScopeSub, "(memberOf=cn=staff,ou=groups,dc=example,dc=com)", ["uid"], false);
        var names = new List<string>();
        while (results.HasMore()) names.Add(results.Next().GetAttribute("uid").StringValue);
        Assert.Equal(["alice", "bob"], names.Order());
    }

    [Fact]
    public void The_active_directory_flavour_and_extra_data_come_from_the_command_line()
    {
        var ldif = Path.GetTempFileName();
        File.WriteAllText(ldif, """
            dn: CN=carol,CN=Users,DC=corp,DC=example,DC=com
            objectClass: user
            cn: carol
            sAMAccountName: carol
            userPassword: carol-secret
            """);
        try
        {
            using var server = StandaloneServer.Start(StandaloneSettings.Parse(["--port", "0", "--ldaps-port", "0", "--ad", "--ldif", ldif]));
            using var connection = new LdapConnection();
            connection.Connect(server.Host, server.Port);
            connection.Bind(@"CORP\carol", "carol-secret");
            Assert.True(connection.Bound);
        }
        finally
        {
            File.Delete(ldif);
        }
    }

    [Fact]
    public void The_ports_come_from_the_command_line_and_the_server_listens_on_them()
    {
        // Two free ports, held open together so they differ, then released for the server. Another process can take
        // one in between, so a taken port gets a second and third try.
        for (var attempt = 1; ; attempt++)
        {
            int port, ldapsPort;
            using (var first = Listen())
            using (var second = Listen())
            {
                port = ((System.Net.IPEndPoint)first.LocalEndpoint).Port;
                ldapsPort = ((System.Net.IPEndPoint)second.LocalEndpoint).Port;
            }
            try
            {
                using var server = StandaloneServer.Start(StandaloneSettings.Parse(["--port", $"{port}", "--ldaps-port", $"{ldapsPort}"]));
                Assert.Equal(port, server.Port);
                Assert.Equal(ldapsPort, server.LdapsPort);
                return;
            }
            catch (System.Net.Sockets.SocketException) when (attempt < 3)
            {
            }
        }
    }

    private static System.Net.Sockets.TcpListener Listen()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        return listener;
    }

    [Fact]
    public void An_unknown_option_says_which_options_there_are()
    {
        var e = Assert.Throws<ArgumentException>(() => StandaloneSettings.Parse(["--verbose"]));
        Assert.Contains("--port N", e.Message);
    }

    [Fact]
    public void The_instructions_name_the_server_and_a_user_that_works()
    {
        using var server = StandaloneServer.Start(new StandaloneSettings(Port: 0, LdapsPort: 0));
        var text = string.Join("\n", StandaloneServer.Instructions(server));
        Assert.Contains(server.Url, text);
        Assert.Contains("-D 'uid=alice,ou=users,dc=example,dc=com' -w alice-secret", text);
    }
}
