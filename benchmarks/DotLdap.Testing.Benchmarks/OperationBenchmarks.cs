using BenchmarkDotNet.Attributes;
using Novell.Directory.Ldap;

namespace DotLdap.Testing.Benchmarks;

/// <summary>Single operations on a running server with 10,000 users, through a real client over TCP.</summary>
[MemoryDiagnoser]
public class OperationBenchmarks
{
    private const string BaseDn = "dc=example,dc=com";
    private LdapTestServer _server = null!;
    private LdapConnection _connection = null!;
    private int _next;

    [GlobalSetup]
    public void Setup()
    {
        _server = LdapTestServer.Create().WithUser("admin", "admin-secret")
            .Configure(d =>
            {
                for (var i = 0; i < 10_000; i++) d.AddUser($"user{i}", "secret", u => u.MemberOf(i % 10 == 0 ? "tenth" : "rest"));
            })
            .Start();
        _connection = Client.Connect(_server.Host, _server.Port, "uid=admin,ou=users," + BaseDn, "admin-secret");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _connection.Dispose();
        _server.Dispose();
    }

    [IterationSetup(Target = nameof(AddAndDelete))]
    public void Next() => _next++;

    [Benchmark(Description = "Bind")]
    public void Bind() => _connection.Bind("uid=user5000,ou=users," + BaseDn, "secret");

    [Benchmark(Description = "Search one user by uid among 10,000")]
    public int SearchOne() => Client.Count(_connection, BaseDn, "(uid=user5000)");

    [Benchmark(Description = "Search 1,000 users by memberOf")]
    public int SearchByGroup() => Client.Count(_connection, BaseDn, "(memberOf=cn=tenth,ou=groups," + BaseDn + ")");

    [Benchmark(Description = "Compare")]
    public bool Compare() => _connection.Compare("uid=user5000,ou=users," + BaseDn, new LdapAttribute("uid", "user5000"));

    [Benchmark(Description = "Add and delete an entry")]
    public void AddAndDelete()
    {
        var dn = $"cn=new{_next},ou=users,{BaseDn}";
        _connection.Add(new LdapEntry(dn, new LdapAttributeSet
        {
            new LdapAttribute("objectClass", ["top", "person"]),
            new LdapAttribute("cn", $"new{_next}"),
            new LdapAttribute("sn", "New"),
        }));
        _connection.Delete(dn);
    }
}
