using System.Text;
using BenchmarkDotNet.Attributes;

namespace DotLdap.Testing.Benchmarks;

/// <summary>Filling a directory with test data, in process, without a client.</summary>
[MemoryDiagnoser]
public class SetupBenchmarks
{
    private string _ldif = "";

    [Params(100, 10_000)]
    public int Users { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        var ldif = new StringBuilder();
        for (var i = 0; i < Users; i++)
            ldif.Append($"dn: uid=user{i},ou=users,dc=example,dc=com\nobjectClass: inetOrgPerson\nuid: user{i}\ncn: User {i}\nsn: {i}\nuserPassword: secret\n\n");
        _ldif = ldif.ToString();
    }

    [Benchmark(Description = "AddUser")]
    public int AddUsers()
    {
        var directory = new InMemoryDirectory();
        for (var i = 0; i < Users; i++) directory.AddUser($"user{i}", "secret");
        return directory.Count;
    }

    [Benchmark(Description = "AddUser, Active Directory flavour")]
    public int AddActiveDirectoryUsers()
    {
        var directory = new InMemoryDirectory(new DirectoryLayout { Flavor = DirectoryFlavor.ActiveDirectory, BaseDn = "DC=corp,DC=example,DC=com" });
        for (var i = 0; i < Users; i++) directory.AddUser($"user{i}", "secret");
        return directory.Count;
    }

    [Benchmark(Description = "LDIF")]
    public int Ldif()
    {
        var directory = new InMemoryDirectory();
        return directory.AddLdif(_ldif);
    }
}
