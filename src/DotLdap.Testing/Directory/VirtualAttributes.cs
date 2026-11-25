using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>Read-only view of the directory handed to extension points. Only valid during the call.</summary>
public interface IDirectoryView
{
    /// <summary>Every stored entry. Do not change them.</summary>
    IReadOnlyList<Entry> Entries { get; }
    /// <summary>The stored entry with the name, or null. Do not change it.</summary>
    /// <param name="dn">The name.</param>
    Entry? Find(DistinguishedName dn);

    /// <summary>Groups that list <paramref name="member"/> in member/uniqueMember, optionally following nested groups.</summary>
    IReadOnlyCollection<DistinguishedName> GroupsOf(DistinguishedName member, bool transitive);
}

/// <summary>
/// An attribute computed at read time instead of stored: memberOf, entryDN, distinguishedName and so on.
/// Virtual attributes take part in filters and in search results. This is the main extension point for
/// server-specific behaviour (the Active Directory long tail).
/// </summary>
public interface IVirtualAttributeProvider
{
    /// <summary>
    /// The attribute's name. An entry that stores an attribute of the same name keeps its stored values: the provider
    /// fills in only for entries without one.
    /// </summary>
    string AttributeName { get; }

    /// <summary>Operational attributes are returned only when asked for by name or with "+".</summary>
    bool IsOperational { get; }

    /// <summary>The values for one entry; empty when the entry has none.</summary>
    /// <param name="entry">The entry being read.</param>
    /// <param name="directory">The rest of the directory, for attributes that depend on other entries.</param>
    IReadOnlyList<byte[]> GetValues(Entry entry, IDirectoryView directory);
}

/// <summary>A virtual attribute defined by a delegate.</summary>
/// <param name="name">The attribute name.</param>
/// <param name="isOperational">True to return it only when asked for by name or with "+".</param>
/// <param name="values">Computes the values of one entry, as text.</param>
public sealed class VirtualAttribute(string name, bool isOperational, Func<Entry, IDirectoryView, IEnumerable<string>> values)
    : IVirtualAttributeProvider
{
    /// <inheritdoc/>
    public string AttributeName => name;
    /// <inheritdoc/>
    public bool IsOperational => isOperational;

    /// <inheritdoc/>
    public IReadOnlyList<byte[]> GetValues(Entry entry, IDirectoryView directory) =>
        values(entry, directory).Select(Utf8.Bytes).ToArray();

    /// <summary>memberOf, computed from the member/uniqueMember attributes of group entries (direct groups only, as in AD).</summary>
    public static VirtualAttribute MemberOf(bool isOperational) =>
        new("memberOf", isOperational, (entry, directory) => directory.GroupsOf(entry.Dn, transitive: false).Select(dn => dn.ToString()));

    /// <summary>entryDN (RFC 5020): the entry's own name, operational.</summary>
    public static VirtualAttribute EntryDn() => new("entryDN", true, (entry, _) => [entry.Dn.ToString()]);

    /// <summary>distinguishedName, as Active Directory has it: the entry's own name, a user attribute.</summary>
    public static VirtualAttribute DistinguishedNameAttribute() => new("distinguishedName", false, (entry, _) => [entry.Dn.ToString()]);
}
