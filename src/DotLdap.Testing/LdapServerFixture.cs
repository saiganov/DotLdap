namespace DotLdap.Testing;

/// <summary>
/// A ready-made test fixture: one server for a test class or collection. It has no dependency on a test
/// framework, so it works as an xUnit <c>IClassFixture&lt;T&gt;</c>/collection fixture and equally from
/// NUnit <c>[OneTimeSetUp]</c> or MSTest <c>[ClassInitialize]</c>. Derive from it and override
/// <see cref="Configure"/> to define the data.
/// </summary>
public class LdapServerFixture : IDisposable
{
    private readonly Lazy<LdapTestServer> _server;

    /// <summary>A fixture whose server starts on first use of <see cref="Server"/>.</summary>
    public LdapServerFixture()
    {
        _server = new Lazy<LdapTestServer>(() =>
        {
            var builder = LdapTestServer.Create();
            Configure(builder);
            return builder.Start();
        });
    }

    /// <summary>The running server; started on first use.</summary>
    public LdapTestServer Server => _server.Value;

    /// <summary>Defines the data and options. The base does nothing: an empty server under <c>dc=example,dc=com</c>.</summary>
    /// <param name="builder">The builder the server is started from.</param>
    protected virtual void Configure(LdapTestServerBuilder builder)
    {
    }

    /// <summary>Stops the server if it was started.</summary>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Stops the server if it was started. Override it to clean up what a derived fixture holds, and call the base.
    /// </summary>
    /// <param name="disposing">True when called from <see cref="Dispose()"/>.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing && _server.IsValueCreated) _server.Value.Dispose();
    }
}
