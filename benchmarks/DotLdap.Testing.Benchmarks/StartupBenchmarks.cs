using BenchmarkDotNet.Attributes;

namespace DotLdap.Testing.Benchmarks;

/// <summary>What a test that builds its own server pays: start, connect, bind, one search, stop.</summary>
[MemoryDiagnoser]
public class StartupBenchmarks
{
    [Benchmark(Description = "New server, connect, bind, search, dispose")]
    public int NewServerPerTest()
    {
        using var server = LdapTestServer.Create().WithUser("alice", "alice-secret").Start();
        using var connection = Client.Connect(server.Host, server.Port, "uid=alice,ou=users,dc=example,dc=com", "alice-secret");
        return Client.Count(connection, "dc=example,dc=com", "(uid=alice)");
    }

    [Benchmark(Description = "New Active Directory server, connect, bind by UPN, search, dispose")]
    public int NewActiveDirectoryServerPerTest()
    {
        using var server = LdapTestServer.Create().AsActiveDirectory().WithBaseDn("DC=corp,DC=example,DC=com")
            .WithUser("alice", "alice-secret").Start();
        using var connection = Client.Connect(server.Host, server.Port, "alice@corp.example.com", "alice-secret");
        return Client.Count(connection, "DC=corp,DC=example,DC=com", "(sAMAccountName=alice)");
    }
}
