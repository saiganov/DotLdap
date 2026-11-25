using System.Diagnostics;
using DotNet.Testcontainers.Builders;

namespace DotLdap.Testing.Benchmarks;

/// <summary>
/// Time to the first green test: from a fresh process to a bind and a search that succeeded, against DotLdap.Testing
/// and against OpenLDAP started by Testcontainers. Each side runs in a new process, so JIT and runtime start-up count
/// on both; the clock stops when the child reports its search, so tearing the server or container down does not count. <c>dotnet run -c Release -- startup [runs]</c>; needs Docker for the OpenLDAP side.
/// </summary>
internal static class StartupComparison
{
    private const string Image = "bitnamilegacy/openldap:2.6.10-debian-12-r1"; // pinned, so the figure can be reproduced

    private const string Ready = "ready";

    public static async Task RunAsync(string[] args)
    {
        switch (args)
        {
            case ["--one", "dotldap"]:
                OneDotLdap();
                return;
            case ["--one", "openldap"]:
                await OneOpenLdapAsync();
                return;
        }

        var runs = args is [var n, ..] ? int.Parse(n, System.Globalization.CultureInfo.InvariantCulture) : 5;
        foreach (var side in new[] { "dotldap", "openldap" })
        {
            var times = new List<double>();
            for (var i = 0; i < runs; i++) times.Add(RunChild(side));
            times.Sort();
            Console.WriteLine($"{side}: median {times[times.Count / 2]:0.00} s of {runs} runs ({string.Join(", ", times.Select(t => t.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture)))})");
        }
    }

    /// <summary>Starts this program again for one side and measures it from process start to the child's "ready" line.</summary>
    private static double RunChild(string side)
    {
        var self = Environment.ProcessPath!;
        var info = new ProcessStartInfo(self) { RedirectStandardOutput = true };
        if (Path.GetFileNameWithoutExtension(self) == "dotnet") info.ArgumentList.Add(typeof(StartupComparison).Assembly.Location);
        foreach (var arg in new[] { "startup", "--one", side }) info.ArgumentList.Add(arg);
        var watch = Stopwatch.StartNew();
        using var process = Process.Start(info)!;
        TimeSpan? ready = null;
        var output = new List<string>();
        while (process.StandardOutput.ReadLine() is { } line)
        {
            if (ready is null && line == Ready) ready = watch.Elapsed;
            else output.Add(line);
        }
        process.WaitForExit();
        if (process.ExitCode != 0 || ready is null) throw new InvalidOperationException($"{side} failed: {string.Join(Environment.NewLine, output)}");
        return ready.Value.TotalSeconds;
    }

    private static void OneDotLdap()
    {
        using var server = LdapTestServer.Create().WithUser("alice", "alice-secret").Start();
        using var connection = Client.Connect(server.Host, server.Port, "uid=alice,ou=users,dc=example,dc=com", "alice-secret");
        if (Client.Count(connection, "dc=example,dc=com", "(uid=alice)") != 1) throw new InvalidOperationException("alice not found");
        Console.WriteLine(Ready);
    }

    private static async Task OneOpenLdapAsync()
    {
        await using var container = new ContainerBuilder(Image)
            .WithEnvironment("LDAP_ROOT", "dc=example,dc=com")
            .WithEnvironment("LDAP_ADMIN_USERNAME", "admin")
            .WithEnvironment("LDAP_ADMIN_PASSWORD", "admin-secret")
            .WithEnvironment("LDAP_USERS", "alice")
            .WithEnvironment("LDAP_PASSWORDS", "alice-secret")
            .WithPortBinding(1389, true)
            .WithWaitStrategy(Wait.ForUnixContainer().UntilMessageIsLogged("slapd starting"))
            .Build();
        await container.StartAsync();
        using var connection = Client.Connect(container.Hostname, container.GetMappedPublicPort(1389), "cn=alice,ou=users,dc=example,dc=com", "alice-secret");
        if (Client.Count(connection, "dc=example,dc=com", "(cn=alice)") != 1) throw new InvalidOperationException("alice not found");
        Console.WriteLine(Ready);
    }
}
