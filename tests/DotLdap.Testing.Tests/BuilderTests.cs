using System.Net;
using System.Net.Sockets;

namespace DotLdap.Testing.Tests;

/// <summary>The builder, the fixture and starting a server: what is shared, what fails and what is cleaned up.</summary>
public sealed class BuilderTests
{
    [Fact]
    public void Changing_the_builder_after_Start_does_not_change_the_running_server()
    {
        var builder = LdapTestServer.Create().WithUser("alice", "alice-secret");
        using var first = builder.Start();

        builder.WithBaseDn("dc=other,dc=org").AsActiveDirectory().WithOptions(o => o.AllowAnonymousSearch = true);
        using var second = builder.Start();

        Assert.Equal("dc=example,dc=com", first.BaseDn.ToString());
        Assert.False(first.Directory.Layout.IsActiveDirectory);
        Assert.False(first.Options.AllowAnonymousSearch);
        Assert.Equal("dc=other,dc=org", second.BaseDn.ToString());
        Assert.True(second.Directory.Layout.IsActiveDirectory);
        Assert.True(second.Options.AllowAnonymousSearch);
        Assert.NotSame(first.Directory.Layout, second.Directory.Layout);
    }

    [Fact]
    public void An_empty_base_DN_is_refused_with_a_reason()
    {
        Assert.Throws<ArgumentException>(() => LdapTestServer.Create().WithBaseDn(""));
        Assert.Throws<ArgumentException>(() => new DirectoryLayout { BaseDn = DistinguishedName.Parse("") });
    }

    [Fact]
    public void A_taken_ldaps_port_stops_the_ldap_listener_that_already_started()
    {
        using var taken = new TcpListener(IPAddress.Loopback, 0);
        taken.Start();
        var takenPort = ((IPEndPoint)taken.LocalEndpoint).Port;
        var ldapPort = FreePort();

        Assert.ThrowsAny<SocketException>(() => LdapTestServer.Create().WithTls().WithPorts(ldapPort, takenPort).Start());

        // Had the ldap:// listener been left running, this port would still be in use.
        using var again = new TcpListener(IPAddress.Loopback, ldapPort);
        again.Start();
    }

    [Fact]
    public void A_derived_fixture_cleans_up_its_own_things_and_the_server()
    {
        var fixture = new FixtureWithCleanup();
        var server = fixture.Server;

        fixture.Dispose();

        Assert.True(fixture.CleanedUp);
        using var client = new TcpClient();
        Assert.ThrowsAny<SocketException>(() => client.Connect(IPAddress.Loopback, server.Port)); // the server stopped
    }

    [Fact]
    public void A_stored_attribute_wins_over_a_virtual_one_of_the_same_name()
    {
        using var server = LdapTestServer.Create()
            .WithEntry("cn=thing,dc=example,dc=com", e => e.Set("objectClass", "device").Set("cn", "thing").Set("description", "stored"))
            .WithEntry("cn=other,dc=example,dc=com", e => e.Set("objectClass", "device").Set("cn", "other"))
            .Start();
        server.Directory.AddVirtualAttribute(new VirtualAttribute("description", isOperational: false, (_, _) => ["virtual"]));

        IReadOnlyList<string> Description(string cn) =>
            Assert.Single(server.Directory.Search("dc=example,dc=com", Protocol.SearchScope.WholeSubtree, $"(cn={cn})")).GetStrings("description");
        Assert.Equal(["stored"], Description("thing"));
        Assert.Equal(["virtual"], Description("other"));
    }

    [Fact]
    public void The_values_of_an_attribute_cannot_be_changed_around_the_entry()
    {
        var entry = new Entry("cn=thing,dc=example,dc=com").Set("description", "one");
        var values = entry.Attributes.Single(a => a.Name == "description").Values;

        Assert.False(values is List<byte[]>);
        Assert.Throws<NotSupportedException>(() => ((IList<byte[]>)values).Add([1]));
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private sealed class FixtureWithCleanup : LdapServerFixture
    {
        public bool CleanedUp { get; private set; }

        protected override void Dispose(bool disposing)
        {
            CleanedUp = true;
            base.Dispose(disposing);
        }
    }
}
