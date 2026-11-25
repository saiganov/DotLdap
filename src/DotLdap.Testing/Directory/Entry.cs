using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>One attribute of an <see cref="Entry"/>: its name as first written and its values.</summary>
/// <param name="name">The attribute name.</param>
public sealed class EntryAttribute(string name)
{
    /// <summary>The attribute name, as it was first written.</summary>
    public string Name { get; } = name;
    /// <summary>The values, as bytes, in the order they were added. Change them through the <see cref="Entry"/> methods.</summary>
    public IReadOnlyList<byte[]> Values => _view ??= Items.AsReadOnly();

    private System.Collections.ObjectModel.ReadOnlyCollection<byte[]>? _view;

    internal List<byte[]> Items { get; } = [];
    /// <summary>The values read as UTF-8.</summary>
    public IEnumerable<string> StringValues => Values.Select(v => Utf8.String(v));
}

/// <summary>
/// A directory entry: a DN plus multi-valued attributes. Attribute names are case-insensitive; values are raw
/// bytes with UTF-8 string helpers. An entry is not held to a schema: any attribute may be set on any entry.
/// </summary>
public sealed class Entry
{
    private readonly Dictionary<string, EntryAttribute> _attributes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>An entry with this name and no attributes.</summary>
    /// <param name="dn">The entry's name.</param>
    public Entry(DistinguishedName dn) => Dn = dn;

    /// <summary>The entry's name.</summary>
    public DistinguishedName Dn { get; }
    /// <summary>The attributes, live: changes to the entry show here.</summary>
    public IReadOnlyCollection<EntryAttribute> Attributes => _attributes.Values;

    /// <summary>Replaces all values of an attribute. An empty value list removes it.</summary>
    public Entry Set(string name, params string[] values) => SetBinary(name, values.Select(Utf8.Bytes).ToArray());

    /// <summary>Replaces all values of an attribute with bytes, for binary attributes such as <c>jpegPhoto</c> or <c>objectGUID</c>. No values removes it.</summary>
    /// <param name="name">The attribute name.</param>
    /// <param name="values">The new values.</param>
    /// <returns>This entry, for chaining.</returns>
    public Entry SetBinary(string name, params byte[][] values)
    {
        _attributes.Remove(name);
        return AddBinary(name, values);
    }

    /// <summary>Appends values to an attribute, creating it when missing.</summary>
    public Entry Add(string name, params string[] values) => AddBinary(name, values.Select(Utf8.Bytes).ToArray());

    /// <summary>Appends byte values to an attribute, creating it when missing.</summary>
    /// <param name="name">The attribute name.</param>
    /// <param name="values">The values to append.</param>
    /// <returns>This entry, for chaining.</returns>
    public Entry AddBinary(string name, params byte[][] values)
    {
        if (values.Length == 0) return this;
        if (!_attributes.TryGetValue(name, out var attribute)) _attributes[name] = attribute = new EntryAttribute(name);
        attribute.Items.AddRange(values);
        return this;
    }

    /// <summary>Removes an attribute with all its values.</summary>
    /// <param name="name">The attribute name.</param>
    /// <returns>True when the entry had the attribute.</returns>
    public bool Remove(string name) => _attributes.Remove(name);

    /// <summary>Removes one value of an attribute, compared ignoring case; the attribute goes when its last value does.</summary>
    /// <param name="name">The attribute name.</param>
    /// <param name="value">The value to remove.</param>
    /// <returns>True when the value was there.</returns>
    public bool RemoveValue(string name, string value)
    {
        if (!_attributes.TryGetValue(name, out var attribute)) return false;
        var removed = attribute.Items.RemoveAll(v => string.Equals(Utf8.String(v), value, StringComparison.OrdinalIgnoreCase)) > 0;
        if (attribute.Values.Count == 0) _attributes.Remove(name);
        return removed;
    }

    /// <summary>True when the entry has the attribute.</summary>
    /// <param name="name">The attribute name.</param>
    public bool Has(string name) => _attributes.ContainsKey(name);

    /// <summary>The values of an attribute as bytes; empty when the entry does not have it.</summary>
    /// <param name="name">The attribute name.</param>
    public IReadOnlyList<byte[]> GetValues(string name) =>
        _attributes.TryGetValue(name, out var attribute) ? attribute.Values : [];

    /// <summary>The values of an attribute read as UTF-8; empty when the entry does not have it.</summary>
    /// <param name="name">The attribute name.</param>
    public IReadOnlyList<string> GetStrings(string name) => GetValues(name).Select(v => Utf8.String(v)).ToArray();

    /// <summary>The first value of an attribute read as UTF-8, or null when the entry does not have it.</summary>
    /// <param name="name">The attribute name.</param>
    public string? GetString(string name) => GetValues(name) is { Count: > 0 } values ? Utf8.String(values[0]) : null;

    /// <summary>A copy with the same name and copies of the attribute lists.</summary>
    public Entry Clone()
    {
        var clone = new Entry(Dn);
        foreach (var attribute in _attributes.Values) clone.AddBinary(attribute.Name, attribute.Values.ToArray());
        return clone;
    }

    /// <summary>The entry's name.</summary>
    public override string ToString() => Dn.ToString();
}
