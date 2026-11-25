using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>Which kind of server the directory imitates.</summary>
public enum DirectoryFlavor
{
    /// <summary>OpenLDAP-like: uid=...,ou=users / groupOfNames, memberOf is operational.</summary>
    Generic,

    /// <summary>Active Directory-like: CN=...,CN=Users / sAMAccountName, userPrincipalName, objectGUID, objectSid, AD bind names and error texts.</summary>
    ActiveDirectory,
}

/// <summary>Where the fluent helpers put users and groups, and how they shape them.</summary>
public sealed class DirectoryLayout
{
    private DistinguishedName _baseDn = "dc=example,dc=com";

    /// <summary>
    /// The suffix the data lives under. Defaults to <c>dc=example,dc=com</c>. Set when the layout is made; afterwards
    /// it changes only when the base entry is renamed with <see cref="InMemoryDirectory.Move"/>.
    /// </summary>
    /// <exception cref="ArgumentException">The DN is empty.</exception>
    public DistinguishedName BaseDn
    {
        get => _baseDn;
        init => _baseDn = !value.IsRoot ? value : throw new ArgumentException("The base DN cannot be empty.", nameof(value));
    }

    /// <summary>Generic (OpenLDAP-like) or Active Directory. Defaults to generic.</summary>
    public DirectoryFlavor Flavor { get; init; } = DirectoryFlavor.Generic;

    /// <summary>RDN of the users container below the base DN. Defaults to ou=users (Generic) or CN=Users (AD).</summary>
    public string? UsersContainer { get; init; }

    /// <summary>RDN of the groups container below the base DN. Defaults to ou=groups (Generic) or CN=Users (AD).</summary>
    public string? GroupsContainer { get; init; }

    /// <summary>The base entry was renamed: users and groups added later go below the new name.</summary>
    internal void RenameBase(DistinguishedName baseDn) => _baseDn = baseDn;

    /// <summary>True for the Active Directory flavour.</summary>
    public bool IsActiveDirectory => Flavor == DirectoryFlavor.ActiveDirectory;

    /// <summary>Where <c>WithUser</c> and <c>AddUser</c> put users.</summary>
    public DistinguishedName UsersDn => DistinguishedName.Parse((UsersContainer ?? (IsActiveDirectory ? "CN=Users" : "ou=users")) + "," + BaseDn);
    /// <summary>Where groups named by <c>MemberOf</c> go.</summary>
    public DistinguishedName GroupsDn => DistinguishedName.Parse((GroupsContainer ?? (IsActiveDirectory ? "CN=Users" : "ou=groups")) + "," + BaseDn);

    /// <summary>DNS-style domain derived from the dc components: dc=example,dc=com gives example.com.</summary>
    public string DomainName => string.Join(".", BaseDn.Rdns.Where(r => r.Type.Equals("dc", StringComparison.OrdinalIgnoreCase)).Select(r => r.Value));

    /// <summary>
    /// Active Directory flavour: how long a lockoutTime that comes with imported data keeps the account locked,
    /// as the domain's lockout policy sets it (30 minutes by default). Exports are full of accounts whose
    /// lockout ran out years ago. Zero means any lockoutTime locks until it is cleared. A lockout made with
    /// <see cref="UserBuilder.LockedOut"/> does not run out by itself.
    /// </summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>The lockoutTime values written by <see cref="UserBuilder.LockedOut"/>.</summary>
    internal System.Collections.Concurrent.ConcurrentDictionary<long, byte> PermanentLockouts { get; } = new();

    internal uint[] DomainSid { get; } = [(uint)Random.Shared.Next(), (uint)Random.Shared.Next(), (uint)Random.Shared.Next()];
    internal int NextRid = 1103;
}

/// <summary>
/// The data behind the server: a thread-safe tree of entries. A schema is published for clients that need one
/// (see <see cref="DefineAttribute(string, AttributeSyntax, bool)"/>); writes over the wire are checked against it
/// only when <see cref="SchemaChecks"/> is on. The directory owns its entries:
/// <see cref="Add(Entry)"/> stores a copy and reads return copies, so change data through <see cref="Update"/>.
/// It can be changed while the server is running.
/// </summary>
public sealed partial class InMemoryDirectory : IDirectoryView
{
    private static readonly string[] MemberAttributes = ["member", "uniqueMember"];

    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _index = new(StringComparer.Ordinal);
    private readonly List<Entry> _entries = [];
    private readonly List<IVirtualAttributeProvider> _virtual = [];
    private Dictionary<string, List<DistinguishedName>>? _groupsByMember;
    private DistinguishedName? _domainUsers;                      // Active Directory flavour: where "Domain Users" was last seen
    private readonly HashSet<Entry> _placeholders = new(ReferenceEqualityComparer.Instance); // parents created by AutoCreateParents
    private Entry? _generatedDomainUsers;                         // ...the one the directory made up itself, while untouched
    private IReadOnlyList<DistinguishedName> _generatedContainers = []; // ...and the containers created just for it
    private readonly HashSet<string> _readOnly = new(StringComparer.Ordinal); // normalized DNs of users who may not write

    /// <summary>An empty directory.</summary>
    /// <param name="layout">The base DN, flavour and containers; the generic defaults when null.</param>
    public InMemoryDirectory(DirectoryLayout? layout = null)
    {
        Layout = layout ?? new DirectoryLayout();
        _virtual.Add(VirtualAttribute.EntryDn());
        _virtual.Add(VirtualAttribute.MemberOf(isOperational: !Layout.IsActiveDirectory));
        if (Layout.IsActiveDirectory)
        {
            _virtual.Add(VirtualAttribute.DistinguishedNameAttribute());
            _virtual.Add(new ActiveDirectory.TokenGroups());
            _virtual.Add(new ActiveDirectory.PrimaryGroupToken());
        }
    }

    /// <summary>The base DN, flavour and containers the directory was made with.</summary>
    public DirectoryLayout Layout { get; }

    /// <summary>Create missing ancestors (down from the base DN) when an entry is added. On by default.</summary>
    public bool AutoCreateParents { get; set; } = true;

    /// <summary>The number of entries, without the root DSE and the subschema entry.</summary>
    public int Count
    {
        get { lock (_gate) return _entries.Count; }
    }

    /// <summary>Registers a computed attribute; a later registration replaces an earlier one with the same name.</summary>
    public InMemoryDirectory AddVirtualAttribute(IVirtualAttributeProvider provider)
    {
        lock (_gate)
        {
            _virtual.RemoveAll(p => p.AttributeName.Equals(provider.AttributeName, StringComparison.OrdinalIgnoreCase));
            _virtual.Add(provider);
            _schema = null;
        }
        return this;
    }

    /// <summary>Adds an entry by name, filled in by <paramref name="configure"/>.</summary>
    /// <param name="dn">The entry's name.</param>
    /// <param name="configure">Sets the attributes, or null for none.</param>
    /// <returns>This directory, for chaining.</returns>
    /// <exception cref="InvalidOperationException">An entry has the name already.</exception>
    public InMemoryDirectory Add(string dn, Action<Entry>? configure = null)
    {
        var entry = new Entry(dn);
        configure?.Invoke(entry);
        return Add(entry);
    }

    /// <summary>
    /// Adds a copy of an entry. Missing parents are created when <see cref="AutoCreateParents"/> is on; in the
    /// Active Directory flavour the attributes AD generates are added where the entry does not bring them.
    /// </summary>
    /// <param name="entry">The entry.</param>
    /// <returns>This directory, for chaining.</returns>
    /// <exception cref="ArgumentException">The entry is the root DSE.</exception>
    /// <exception cref="InvalidOperationException">An entry has the name already.</exception>
    public InMemoryDirectory Add(Entry entry)
    {
        lock (_gate)
        {
            if (entry.Dn.IsRoot) throw new ArgumentException("The root DSE cannot be added as an entry.");
            var stored = entry.Clone();
            // Test data that brings its own "Domain Users" takes the place of the one created automatically.
            var replaced = Layout.IsActiveDirectory && IsThisDomainsDomainUsers(stored) ? GeneratedDomainUsers() : null;
            // So does an explicit entry for a container that so far only existed because something below it
            // needed a parent: test data need not list parents first.
            _index.TryGetValue(entry.Dn.Normalized, out var existing);
            var placeholder = existing is not null && _placeholders.Contains(existing) ? existing : null;
            if (existing is not null && !ReferenceEquals(existing, replaced) && placeholder is null)
                throw new InvalidOperationException($"Entry '{entry.Dn}' already exists.");
            if (replaced is not null) AbsorbGeneratedDomainUsers(replaced, stored);
            if (AutoCreateParents) CreateParents(entry.Dn);
            // Whatever the source (builder, WithEntry, LDIF), an entry in the Active Directory flavour gets the
            // attributes AD would have generated; values the test data brings are kept.
            if (Layout.IsActiveDirectory) ApplyActiveDirectoryDefaults(stored);
            if (placeholder is not null && _index.ContainsKey(entry.Dn.Normalized))
            {
                _placeholders.Remove(placeholder);
                ReplaceStored(placeholder, stored);
            }
            else
            {
                Store(stored);
            }
            if (Layout.IsActiveDirectory && ActiveDirectory.NeedsDomainUsers(stored)) EnsureDomainUsers(stored);
        }
        return this;
    }

    /// <summary>
    /// Makes a user read-only (or lifts that): the server answers what they try to write with
    /// insufficientAccessRights. They still bind, search and compare like everyone else, and may change a password
    /// they can prove they know (Password Modify with the old password; in the Active Directory flavour deleting
    /// the old <c>unicodePwd</c> and adding the new one). The mark follows the entry when it is renamed or moved
    /// and goes away with it. It takes effect at once, also on connections that are already open; a connection
    /// whose user has since been renamed or deleted stays what it was when the server last saw that entry.
    /// </summary>
    /// <exception cref="InvalidOperationException">There is no such entry.</exception>
    public InMemoryDirectory SetReadOnly(DistinguishedName user, bool readOnly = true)
    {
        lock (_gate)
        {
            if (!_index.ContainsKey(user.Normalized)) throw new InvalidOperationException($"Entry '{user}' does not exist.");
            if (readOnly) _readOnly.Add(user.Normalized);
            else _readOnly.Remove(user.Normalized);
        }
        return this;
    }

    /// <summary>Whether the user was marked with <see cref="SetReadOnly"/>.</summary>
    public bool IsReadOnly(DistinguishedName user)
    {
        lock (_gate) return _readOnly.Contains(user.Normalized);
    }

    /// <summary>Null when there is no such entry (any more).</summary>
    internal bool? ReadOnlyState(DistinguishedName user)
    {
        lock (_gate) return _index.ContainsKey(user.Normalized) ? _readOnly.Contains(user.Normalized) : null;
    }

    /// <summary>Removes one entry, without looking at its children.</summary>
    /// <param name="dn">The entry's name.</param>
    /// <returns>True when the entry existed.</returns>
    public bool Remove(DistinguishedName dn)
    {
        lock (_gate)
        {
            if (!_index.Remove(dn.Normalized, out var entry)) return false;
            _readOnly.Remove(dn.Normalized);
            _entries.Remove(entry);
            _placeholders.Remove(entry);
            Invalidate();
            return true;
        }
    }

    /// <summary>Removes every entry. Settings such as the default referral and schema definitions stay.</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _index.Clear();
            _entries.Clear();
            _readOnly.Clear();
            Invalidate();
            _domainUsers = null;
            _generatedDomainUsers = null;
            _generatedContainers = [];
            _placeholders.Clear();
        }
    }

    /// <summary>Changes an entry in place. Returns false when it does not exist.</summary>
    public bool Update(DistinguishedName dn, Action<Entry> change)
    {
        lock (_gate)
        {
            if (!_index.TryGetValue(dn.Normalized, out var entry)) return false;
            // What the test has changed by hand is no longer something explicit test data may silently replace.
            // Members are the exception for the generated "Domain Users": they move to the group that replaces it.
            _placeholders.Remove(entry);
            var generated = ReferenceEquals(entry, _generatedDomainUsers) ? Fingerprint(entry) : null;
            try
            {
                change(entry);
            }
            finally
            {
                // Also when the callback throws half-way: what it changed until then stays changed.
                if (generated is not null && generated != Fingerprint(entry)) _generatedDomainUsers = null;
                Invalidate();
            }
            return true;
        }
    }

    /// <summary>True when an entry has the name.</summary>
    /// <param name="dn">The name.</param>
    public bool Exists(DistinguishedName dn)
    {
        lock (_gate) return _index.ContainsKey(dn.Normalized);
    }

    /// <summary>Returns a copy of the stored entry (without virtual attributes), or null.</summary>
    public Entry? Find(DistinguishedName dn)
    {
        lock (_gate) return _index.TryGetValue(dn.Normalized, out var entry) ? entry.Clone() : null;
    }

    /// <summary>
    /// Suffixes: entries whose parent is not in the directory. A referral entry at the top is one of them here;
    /// the root DSE a client reads leaves it out of <c>namingContexts</c>, because another server holds that name.
    /// </summary>
    public IReadOnlyList<DistinguishedName> NamingContexts
    {
        get
        {
            lock (_gate)
                return _entries.Where(e => e.Dn.Parent is { } p && (p.IsRoot || !_index.ContainsKey(p.Normalized))).Select(e => e.Dn).ToArray();
        }
    }

    /// <summary>Runs a search given as text and returns copies of the matching entries with virtual attributes filled in.</summary>
    /// <param name="baseDn">Where the search starts.</param>
    /// <param name="scope">How far below the base it looks.</param>
    /// <param name="filter">An RFC 4515 filter, such as <c>(objectClass=person)</c>.</param>
    public IReadOnlyList<Entry> Search(string baseDn, SearchScope scope, string filter) =>
        Search(DistinguishedName.Parse(baseDn), scope, LdapFilter.Parse(filter));

    /// <summary>Runs a search and returns copies of the matching entries with virtual attributes filled in.</summary>
    public IReadOnlyList<Entry> Search(DistinguishedName baseDn, SearchScope scope, LdapFilter filter) =>
        Search(baseDn, scope, filter, requested: null);

    /// <summary>
    /// As <see cref="Search(DistinguishedName, SearchScope, LdapFilter)"/>, but computes operational virtual
    /// attributes (tokenGroups...) only when <paramref name="requested"/> names them or holds "+". A server
    /// search would not return the others anyway, and some are expensive to compute for every entry.
    /// </summary>
    internal IReadOnlyList<Entry> Search(DistinguishedName baseDn, SearchScope scope, LdapFilter filter, IReadOnlyList<string>? requested)
    {
        lock (_gate)
        {
            var evaluator = new FilterEvaluator(this);
            var result = new List<Entry>();
            foreach (var entry in _entries)
            {
                var inScope = scope switch
                {
                    SearchScope.BaseObject => entry.Dn.Equals(baseDn),
                    SearchScope.SingleLevel => entry.Dn.IsChildOf(baseDn),
                    _ => entry.Dn.IsWithin(baseDn),
                };
                if (inScope && evaluator.Matches(filter, entry)) result.Add(Materialize(entry, requested));
            }
            return result;
        }
    }

    /// <summary>Evaluates a filter against one entry that need not be stored in the directory (used for the root DSE).</summary>
    public bool Matches(LdapFilter filter, Entry entry)
    {
        lock (_gate) return new FilterEvaluator(this).Matches(filter, entry);
    }

    /// <summary>
    /// Operational attributes are returned only when asked for by name or with "+": the computed ones marked
    /// so, and stored ones the flavour's own schema knows as operational (pwdAccountLockedTime or entryUUID in a
    /// generic directory; to Active Directory those two are ordinary attributes).
    /// </summary>
    internal bool IsOperational(string attributeName)
    {
        ArgumentNullException.ThrowIfNull(attributeName);
        attributeName = FilterEvaluator.StripOptions(attributeName); // entries built in code may carry options
        lock (_gate)
        {
            if (_virtual.FirstOrDefault(p => p.AttributeName.Equals(attributeName, StringComparison.OrdinalIgnoreCase)) is { } computed)
                return computed.IsOperational;
            // Not the published schema: that is rebuilt from all the data after every write, and this runs for
            // every attribute of every entry a search returns. Only a declaration or the catalog can say "operational".
            return KnownAttribute(attributeName)?.Operational ?? false;
        }
    }

    /// <summary>Finds the deepest existing ancestor of a DN, for the matchedDN field of noSuchObject.</summary>
    internal DistinguishedName? NearestExistingAncestor(DistinguishedName dn)
    {
        lock (_gate)
        {
            for (var current = dn.Parent; current is { IsRoot: false }; current = current.Parent)
                if (_index.ContainsKey(current.Normalized)) return current;
            return null;
        }
    }

    // ---- internals -------------------------------------------------------------------------------------------

    internal IReadOnlyList<byte[]> GetValues(Entry entry, string attributeName)
    {
        var stored = entry.GetValues(attributeName);
        if (stored.Count > 0) return stored;
        foreach (var provider in _virtual)
            if (provider.AttributeName.Equals(attributeName, StringComparison.OrdinalIgnoreCase))
                return provider.GetValues(entry, this);
        return stored;
    }

    internal IEnumerable<string> AttributeNames(Entry entry) =>
        entry.Attributes.Select(a => a.Name).Concat(_virtual.Select(p => p.AttributeName));

    // ---- Active Directory: generated attributes and the "Domain Users" group ------------------------------------

    private void ApplyActiveDirectoryDefaults(Entry stored)
    {
        // RID 513 belongs to one object of this domain. A group called "Domain Users" gets it only while nobody
        // holds it; a second group of that name, in another container or another tree, is an ordinary group.
        if (ActiveDirectory.IsDomainUsers(stored) && !stored.Has("objectSid")
            && (!IsThisDomainsDomainUsers(stored) || FindBySid(DomainUsersSid) is not null))
            stored.SetBinary("objectSid", ActiveDirectory.NewSid(Layout));
        ActiveDirectory.ApplyDefaults(stored, Layout);
    }

    /// <summary>A group called "Domain Users" below the base DN. A second tree next to it is another domain.</summary>
    private bool IsThisDomainsDomainUsers(Entry entry) => ActiveDirectory.IsDomainUsers(entry) && entry.Dn.IsWithin(Layout.BaseDn);

    /// <summary>Adds an entry the directory needs by itself; explicit test data for the same DN replaces it.</summary>
    internal void AddGenerated(Entry entry)
    {
        lock (_gate)
        {
            Add(entry);
            _placeholders.Add(_index[entry.Dn.Normalized]);
        }
    }

    internal Entry? DomainUsersGroup()
    {
        lock (_gate) return FindDomainUsers();
    }

    // Everything but the members, to tell whether a test changed the generated group by hand.
    private static string Fingerprint(Entry entry) => string.Join("\n", entry.Attributes
        .Where(a => !a.Name.Equals("member", StringComparison.OrdinalIgnoreCase))
        .OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
        .Select(a => a.Name + "=" + string.Join(",", a.Values.Select(Convert.ToHexString))));

    private byte[] DomainUsersSid => ActiveDirectory.NewSid(Layout, ActiveDirectory.DomainUsersRid);

    private Entry? FindBySid(byte[] sid) =>
        _entries.FirstOrDefault(e => e.GetValues("objectSid") is { Count: > 0 } values && values[0].AsSpan().SequenceEqual(sid));

    /// <summary>
    /// The group that plays "Domain Users": the holder of RID 513 in this domain (whatever it is called by now),
    /// or else a group of that name, which test data taken from a real domain brings with that domain's SID.
    /// </summary>
    private Entry? FindDomainUsers(byte[]? accountSid = null)
    {
        var sid = DomainUsersSid;
        // An account from a real domain names its primary group by that domain's SID, whatever the group is
        // called there ("Domänen-Benutzer").
        var accountDomainSid = accountSid is not null && ActiveDirectory.Rid(accountSid) is not null
            ? ActiveDirectory.WithRid(accountSid, ActiveDirectory.DomainUsersRid)
            : null;
        bool Holds(Entry e, byte[]? wanted) => wanted is not null && e.GetValues("objectSid") is { Count: > 0 } values && values[0].AsSpan().SequenceEqual(wanted);
        bool Plays(Entry e) => Holds(e, sid) || Holds(e, accountDomainSid) || IsThisDomainsDomainUsers(e);
        // Once a group has been found in that role it keeps it for as long as it sits at that DN: the SID that
        // identified it may have been one particular account's.
        if (_domainUsers is not null)
        {
            if (_index.TryGetValue(_domainUsers.Normalized, out var known)
                && known.GetStrings("objectClass").Contains("group", StringComparer.OrdinalIgnoreCase)) return known;
            _domainUsers = null;
        }
        var found = _entries.FirstOrDefault(Plays);
        if (found is not null) _domainUsers = found.Dn;
        return found;
    }

    /// <summary>
    /// Every AD domain has "Domain Users" (RID 513), the primary group of ordinary accounts. It appears with the
    /// first account, next to the other groups, unless the test data already brought one.
    /// </summary>
    private void EnsureDomainUsers(Entry account)
    {
        // The cheap answers first: this runs for every account that is added.
        if (_domainUsers is not null && _index.ContainsKey(_domainUsers.Normalized)) return;
        // An account in a second tree next to the base DN belongs to another domain; nothing is made up for it.
        if (!account.Dn.IsWithin(Layout.BaseDn)) return;
        var dn = this.GroupDn(ActiveDirectory.DomainUsersName);
        if (_index.ContainsKey(dn.Normalized)) return; // there already, or the name is taken by something else
        // Without its container the group would hang in the air and show up as a naming context.
        if (!AutoCreateParents && !_index.ContainsKey(dn.Parent!.Normalized)) return;
        if (FindDomainUsers(account.GetValues("objectSid") is { Count: > 0 } own ? own[0] : null) is not null) return;

        var group = new Entry(dn)
            .Set("objectClass", "top", "group")
            .Set("cn", ActiveDirectory.DomainUsersName)
            .Set("sAMAccountName", ActiveDirectory.DomainUsersName)
            .Set("groupType", "-2147483646");
        var before = _entries.Count;
        if (AutoCreateParents) CreateParents(dn);
        _generatedContainers = _entries.Skip(before).Select(e => e.Dn).ToArray();
        ApplyActiveDirectoryDefaults(group);
        Store(group);
        _generatedDomainUsers = group;
        _domainUsers = dn;
    }

    /// <summary>The generated group, as long as it is still the very entry the directory created.</summary>
    private Entry? GeneratedDomainUsers() =>
        _generatedDomainUsers is { } generated && _index.TryGetValue(generated.Dn.Normalized, out var current) && ReferenceEquals(current, generated)
            ? generated
            : null;

    /// <summary>
    /// Called before the test data's own "Domain Users" is stored. The generated group goes away as if it had
    /// never been there: its SID and members move to the incoming entry, references follow, and containers that
    /// were created only for it are removed again. The result does not depend on the order of the test data.
    /// </summary>
    private void AbsorbGeneratedDomainUsers(Entry generated, Entry incoming)
    {
        if (!incoming.Has("objectSid")) incoming.SetBinary("objectSid", generated.GetValues("objectSid").ToArray());
        foreach (var member in generated.GetValues("member"))
            if (!incoming.GetValues("member").Any(v => FilterEvaluator.ValueEquals("member", v, member))) incoming.AddBinary("member", member);
        _index.Remove(generated.Dn.Normalized);
        _entries.Remove(generated);
        _readOnly.Remove(generated.Dn.Normalized);

        foreach (var container in _generatedContainers.Reverse())
        {
            if (incoming.Dn.IsWithin(container) || !_index.TryGetValue(container.Normalized, out var entry)) continue;
            if (!_placeholders.Contains(entry) || _entries.Any(e => !ReferenceEquals(e, entry) && e.Dn.IsWithin(container))) continue;
            _index.Remove(container.Normalized);
            _entries.Remove(entry);
            _readOnly.Remove(container.Normalized);
            _placeholders.Remove(entry);
        }
        if (!generated.Dn.Equals(incoming.Dn))
            RewriteReferences(new Dictionary<string, DistinguishedName?> { [generated.Dn.Normalized] = incoming.Dn });

        Invalidate();
        _generatedDomainUsers = null;
        _generatedContainers = [];
        _domainUsers = incoming.Dn;
    }

    private Entry Materialize(Entry entry, IReadOnlyList<string>? requested)
    {
        var copy = entry.Clone();
        var allOperational = requested is null || requested.Contains("+");
        foreach (var provider in _virtual)
        {
            if (copy.Has(provider.AttributeName)) continue;
            if (provider.IsOperational && !allOperational
                && !requested!.Any(r => FilterEvaluator.StripOptions(r).Equals(provider.AttributeName, StringComparison.OrdinalIgnoreCase)))
                continue;
            copy.AddBinary(provider.AttributeName, provider.GetValues(entry, this).ToArray());
        }
        return copy;
    }

    private void Store(Entry entry)
    {
        _index.Add(entry.Dn.Normalized, entry);
        _entries.Add(entry);
        Invalidate();
    }

    private void CreateParents(DistinguishedName dn)
    {
        if (!dn.IsWithin(Layout.BaseDn) || dn.Equals(Layout.BaseDn)) return;
        var missing = new Stack<DistinguishedName>();
        for (var current = dn.Parent; current is not null && current.IsWithin(Layout.BaseDn); current = current.Parent)
        {
            if (_index.ContainsKey(current.Normalized)) break;
            missing.Push(current);
        }
        foreach (var parent in missing)
        {
            var rdn = parent.Leaf!;
            var objectClass = rdn.Type.ToLowerInvariant() switch
            {
                "dc" => Layout.IsActiveDirectory ? new[] { "top", "domain", "domainDNS" } : ["top", "domain"],
                "ou" => ["top", "organizationalUnit"],
                "o" => ["top", "organization"],
                "cn" when Layout.IsActiveDirectory => ["top", "container"],
                _ => new[] { "top", "extensibleObject" },
            };
            var created = new Entry(parent).Set("objectClass", objectClass).Set(rdn.Type, rdn.Value);
            if (Layout.IsActiveDirectory) ActiveDirectory.ApplyDefaults(created, Layout);
            Store(created);
            _placeholders.Add(created);
        }
    }

    IReadOnlyList<Entry> IDirectoryView.Entries => _entries;

    Entry? IDirectoryView.Find(DistinguishedName dn) => _index.GetValueOrDefault(dn.Normalized);

    /// <summary>The groups whose <c>member</c> or <c>uniqueMember</c> names the entry.</summary>
    /// <param name="member">The member's name.</param>
    /// <param name="transitive">True to include the groups those groups are members of, and so on.</param>
    public IReadOnlyCollection<DistinguishedName> GroupsOf(DistinguishedName member, bool transitive)
    {
        lock (_gate)
        {
            var index = _groupsByMember ??= BuildMemberIndex();
            if (!index.TryGetValue(member.Normalized, out var direct)) return [];
            if (!transitive) return direct;

            var seen = new Dictionary<string, DistinguishedName>();
            var queue = new Queue<DistinguishedName>(direct);
            while (queue.Count > 0)
            {
                var group = queue.Dequeue();
                if (!seen.TryAdd(group.Normalized, group)) continue;
                if (index.TryGetValue(group.Normalized, out var parents))
                    foreach (var parent in parents) queue.Enqueue(parent);
            }
            return seen.Values;
        }
    }

    private Dictionary<string, List<DistinguishedName>> BuildMemberIndex()
    {
        var index = new Dictionary<string, List<DistinguishedName>>(StringComparer.Ordinal);
        foreach (var group in _entries)
        {
            foreach (var attribute in MemberAttributes)
            {
                foreach (var value in group.GetValues(attribute))
                {
                    if (!DistinguishedName.TryParse(Utf8.String(value), out var member)) continue;
                    if (!index.TryGetValue(member.Normalized, out var groups)) index[member.Normalized] = groups = [];
                    if (!groups.Contains(group.Dn)) groups.Add(group.Dn);
                }
            }
        }
        return index;
    }
}
