using System.Security.Cryptography.X509Certificates;

namespace DotLdap.Testing;

/// <summary>Collects configuration and seed data, then starts the server.</summary>
public sealed class LdapTestServerBuilder
{
    // Kept as plain values and turned into a fresh layout and options on each Start(), so that a running server
    // shares nothing with the builder (or with a second server from the same builder).
    private DistinguishedName _baseDn = new DirectoryLayout().BaseDn;
    private DirectoryFlavor _flavor;
    private string? _usersContainer;
    private string? _groupsContainer;
    private readonly LdapTestServerOptions _options = new();
    private readonly List<Action<InMemoryDirectory>> _seed = [];

    /// <summary>The suffix the data lives under. Defaults to <c>dc=example,dc=com</c>.</summary>
    /// <param name="baseDn">The base DN, such as <c>DC=corp,DC=example,DC=com</c>.</param>
    /// <returns>This builder, for chaining.</returns>
    /// <exception cref="FormatException">The text is not a DN.</exception>
    /// <exception cref="ArgumentException">The DN is empty.</exception>
    public LdapTestServerBuilder WithBaseDn(string baseDn)
    {
        var dn = DistinguishedName.Parse(baseDn);
        _baseDn = !dn.IsRoot ? dn : throw new ArgumentException("The base DN cannot be empty.", nameof(baseDn));
        return this;
    }

    /// <summary>Shapes users, groups and server behaviour like OpenLDAP (default) or Active Directory.</summary>
    public LdapTestServerBuilder WithFlavor(DirectoryFlavor flavor)
    {
        _flavor = flavor;
        return this;
    }

    /// <summary>Shorthand for <c>WithFlavor(DirectoryFlavor.ActiveDirectory)</c>.</summary>
    /// <returns>This builder, for chaining.</returns>
    public LdapTestServerBuilder AsActiveDirectory() => WithFlavor(DirectoryFlavor.ActiveDirectory);

    /// <summary>RDNs of the containers for users and groups below the base DN, e.g. "ou=people" and "ou=roles".</summary>
    public LdapTestServerBuilder WithContainers(string? users = null, string? groups = null)
    {
        _usersContainer = users ?? _usersContainer;
        _groupsContainer = groups ?? _groupsContainer;
        return this;
    }

    /// <summary>Adds a user who can bind with the password: see <see cref="DirectorySeedExtensions.AddUser"/>.</summary>
    /// <param name="name">The login name: <c>uid</c> in the generic flavour, <c>sAMAccountName</c> and <c>CN</c> in Active Directory.</param>
    /// <param name="password">The password, as clear text or a ready-made hash such as <c>{SSHA}...</c>.</param>
    /// <param name="configure">Sets attributes, groups and account state, or null.</param>
    /// <returns>This builder, for chaining.</returns>
    public LdapTestServerBuilder WithUser(string name, string password, Action<UserBuilder>? configure = null) =>
        Configure(d => d.AddUser(name, password, configure));

    /// <summary>Adds a group. Members are user names, names of earlier groups (nesting) or full DNs.</summary>
    public LdapTestServerBuilder WithGroup(string name, params string[] members) =>
        Configure(d => d.AddGroup(name, members));

    /// <summary>
    /// Makes a user that already exists at this point (from <see cref="WithLdif"/> or <see cref="WithEntry"/>)
    /// read-only; for <see cref="WithUser"/> there is <c>u => u.ReadOnly()</c>. Takes a full DN or the login name
    /// <see cref="WithUser"/> would use. See <see cref="InMemoryDirectory.SetReadOnly"/>.
    /// </summary>
    /// <remarks>The seed calls run in order, so call this after the call that adds the user.</remarks>
    public LdapTestServerBuilder WithReadOnlyUser(string nameOrDn) =>
        Configure(d =>
        {
            var dn = nameOrDn.Contains('=') ? DistinguishedName.Parse(nameOrDn) : d.UserDn(nameOrDn);
            if (!d.Exists(dn))
                throw new InvalidOperationException(
                    $"WithReadOnlyUser: '{dn}' does not exist yet. Call it after the WithLdif, WithJson or WithEntry call that adds the user.");
            d.SetReadOnly(dn);
        });

    /// <summary>Adds any entry, attributes and all.</summary>
    /// <param name="dn">The entry's name.</param>
    /// <param name="configure">Sets the attributes.</param>
    /// <returns>This builder, for chaining.</returns>
    public LdapTestServerBuilder WithEntry(string dn, Action<Entry> configure) =>
        Configure(d => d.Add(dn, configure));

    /// <summary>Adds the entries of LDIF text (content records).</summary>
    /// <param name="ldif">The LDIF text.</param>
    /// <returns>This builder, for chaining.</returns>
    public LdapTestServerBuilder WithLdif(string ldif) => Configure(d => d.AddLdif(ldif));

    /// <summary>Like <see cref="WithLdif"/>, from a file.</summary>
    /// <param name="path">The file.</param>
    /// <returns>This builder, for chaining.</returns>
    public LdapTestServerBuilder WithLdifFile(string path) => Configure(d => d.AddLdif(File.ReadAllText(path)));

    /// <summary>Users, groups and entries from JSON; see <see cref="DirectorySeedExtensions.AddJson"/> for the format.</summary>
    public LdapTestServerBuilder WithJson(string json) => Configure(d => d.AddJson(json));

    /// <summary>Like <see cref="WithJson"/>, from a file. A mistake in it is reported with the file's name.</summary>
    public LdapTestServerBuilder WithJsonFile(string path) => Configure(d =>
    {
        try
        {
            d.AddJson(File.ReadAllText(path));
        }
        catch (FormatException e)
        {
            throw new FormatException($"{path}: {e.Message}", e);
        }
    });

    /// <summary>
    /// A part of the tree that other servers hold: see <see cref="DirectorySeedExtensions.AddReferral"/>. To
    /// test a client that follows referrals, point the URL at a second test server.
    /// </summary>
    public LdapTestServerBuilder WithReferral(string dn, params string[] urls) => Configure(d => d.AddReferral(dn, urls));

    /// <summary>Where clients are sent that name something outside this directory: see <see cref="InMemoryDirectory.DefaultReferral"/>.</summary>
    public LdapTestServerBuilder WithDefaultReferral(params string[] urls) => Configure(d => d.DefaultReferral = urls);

    /// <summary>Runs arbitrary seeding code against the directory, in the order the builder calls were made.</summary>
    public LdapTestServerBuilder Configure(Action<InMemoryDirectory> seed)
    {
        _seed.Add(seed);
        return this;
    }

    /// <summary>Enables StartTLS and an ldaps:// listener. Without a certificate a self-signed one is generated.</summary>
    public LdapTestServerBuilder WithTls(X509Certificate2? certificate = null)
    {
        _options.EnableTls = true;
        _options.Certificate = certificate;
        return this;
    }

    /// <summary>Fixed ports instead of free ones. Prefer the default: free ports let tests run in parallel.</summary>
    public LdapTestServerBuilder WithPorts(int ldap, int ldaps = 0)
    {
        _options.Port = ldap;
        _options.LdapsPort = ldaps;
        return this;
    }

    /// <summary>Lets clients that have not bound search the tree; see <see cref="LdapTestServerOptions.AllowAnonymousSearch"/>.</summary>
    /// <param name="allow">False to turn it off again.</param>
    /// <returns>This builder, for chaining.</returns>
    public LdapTestServerBuilder AllowAnonymousSearch(bool allow = true)
    {
        _options.AllowAnonymousSearch = allow;
        return this;
    }

    /// <summary>Server-side search limit, like MaxPageSize in Active Directory (1000 there).</summary>
    public LdapTestServerBuilder WithMaxSearchResults(int limit)
    {
        _options.MaxSearchResults = limit;
        return this;
    }

    /// <summary>Values of one attribute returned at once before ranged retrieval kicks in (MaxValRange, 1500 in Active Directory).</summary>
    public LdapTestServerBuilder WithMaxValuesPerAttribute(int limit)
    {
        _options.MaxValuesPerAttribute = limit;
        return this;
    }

    /// <summary>
    /// Holds what clients write against the schema: a second value for a single-valued attribute, text where a
    /// number, a date or a DN belongs. Off by default. See <see cref="InMemoryDirectory.SchemaChecks"/>.
    /// </summary>
    public LdapTestServerBuilder WithSchemaChecks(bool enable = true) => Configure(d => d.SchemaChecks = enable);

    /// <summary>Sets any of the server options, including those without a builder method of their own.</summary>
    /// <param name="configure">Changes the options.</param>
    /// <returns>This builder, for chaining.</returns>
    public LdapTestServerBuilder WithOptions(Action<LdapTestServerOptions> configure)
    {
        configure(_options);
        return this;
    }

    /// <summary>Creates the directory, runs the seed calls in order and starts listening.</summary>
    /// <returns>The running server; dispose it at the end of the test.</returns>
    /// <exception cref="System.Net.Sockets.SocketException">A fixed port set with <see cref="WithPorts"/> is in use.</exception>
    /// <remarks>Each call starts a new server with its own copy of the configuration; changing the builder afterwards does not affect it.</remarks>
    public LdapTestServer Start()
    {
        var layout = new DirectoryLayout { BaseDn = _baseDn, Flavor = _flavor, UsersContainer = _usersContainer, GroupsContainer = _groupsContainer };
        var directory = new InMemoryDirectory(layout);
        var root = new Entry(layout.BaseDn)
            .Set("objectClass", layout.IsActiveDirectory ? ["top", "domain", "domainDNS"] : ["top", "domain"])
            .Set(layout.BaseDn.Leaf!.Type, layout.BaseDn.Leaf.Value);
        // The base entry is there from the start, but test data that lists it (as every export does) replaces it.
        directory.AddGenerated(root);
        foreach (var seed in _seed) seed(directory);
        return new LdapTestServer(directory, _options.Clone());
    }
}
