using System.Text;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>One RDN: usually a single type=value pair, occasionally several joined by '+'.</summary>
public sealed class Rdn
{
    internal Rdn(IReadOnlyList<(string Type, string Value)> components)
    {
        Components = components;
        Normalized = string.Join("+", components
            .Select(c => c.Type.ToLowerInvariant() + "=" + DistinguishedName.EscapeValue(c.Value.ToLowerInvariant()))
            .OrderBy(c => c, StringComparer.Ordinal));
    }

    /// <summary>Lower-cased canonical form of this RDN.</summary>
    internal string Normalized { get; }

    /// <summary>The type=value pairs, in the order written.</summary>
    public IReadOnlyList<(string Type, string Value)> Components { get; }
    /// <summary>The type of the first pair, such as <c>cn</c>.</summary>
    public string Type => Components[0].Type;
    /// <summary>The value of the first pair, unescaped.</summary>
    public string Value => Components[0].Value;

    /// <summary>The RFC 4514 text, escaped where needed.</summary>
    public override string ToString() => string.Join("+", Components.Select(c => c.Type + "=" + DistinguishedName.EscapeValue(c.Value)));

}

/// <summary>An RFC 4514 distinguished name. Equality is case-insensitive and ignores insignificant whitespace.</summary>
public sealed class DistinguishedName : IEquatable<DistinguishedName>
{
    /// <summary>The empty name: the root DSE.</summary>
    public static readonly DistinguishedName Root = new([]);

    private readonly string _text;

    private DistinguishedName(IReadOnlyList<Rdn> rdns)
    {
        Rdns = rdns;
        _text = string.Join(",", rdns);
        Normalized = string.Join(",", rdns.Select(r => r.Normalized));
    }

    /// <summary>RDNs from the leaf to the suffix.</summary>
    public IReadOnlyList<Rdn> Rdns { get; }

    /// <summary>Lower-cased canonical form, suitable as a dictionary key.</summary>
    public string Normalized { get; }

    /// <summary>True for the empty name.</summary>
    public bool IsRoot => Rdns.Count == 0;
    /// <summary>The first RDN, the entry's own name below its parent; null for the root.</summary>
    public Rdn? Leaf => IsRoot ? null : Rdns[0];
    /// <summary>The name one level up; null for the root.</summary>
    public DistinguishedName? Parent => IsRoot ? null : new DistinguishedName(Rdns.Skip(1).ToArray());

    /// <summary>The name of a child of this entry.</summary>
    /// <param name="type">The RDN type, such as <c>cn</c>.</param>
    /// <param name="value">The RDN value, unescaped.</param>
    public DistinguishedName Child(string type, string value) =>
        new(Rdns.Prepend(new Rdn([(type, value)])).ToArray());

    /// <summary>True when this DN equals <paramref name="other"/> or lies below it.</summary>
    public bool IsWithin(DistinguishedName other)
    {
        // RDN by RDN from the suffix end. A string suffix test would be fooled by an escaped comma inside a value.
        var offset = Rdns.Count - other.Rdns.Count;
        if (offset < 0) return false;
        for (var i = other.Rdns.Count - 1; i >= 0; i--)
            if (Rdns[i + offset].Normalized != other.Rdns[i].Normalized) return false;
        return true;
    }

    /// <summary>The same relative path under another base: moves this DN from <paramref name="oldBase"/> to <paramref name="newBase"/>.</summary>
    internal DistinguishedName Rebase(DistinguishedName oldBase, DistinguishedName newBase) =>
        new(Rdns.Take(Rdns.Count - oldBase.Rdns.Count).Concat(newBase.Rdns).ToArray());

    internal static DistinguishedName Join(Rdn leaf, DistinguishedName parent) => new(parent.Rdns.Prepend(leaf).ToArray());

    /// <summary>True when this DN lies exactly one level below <paramref name="other"/>.</summary>
    /// <param name="other">The possible parent.</param>
    public bool IsChildOf(DistinguishedName other) => Rdns.Count == other.Rdns.Count + 1 && IsWithin(other);

    /// <summary>Parses text, so a string can be passed wherever a DN is asked for.</summary>
    /// <param name="dn">The text.</param>
    /// <exception cref="FormatException">The text is no distinguished name.</exception>
    public static implicit operator DistinguishedName(string dn) => Parse(dn);

    /// <summary>Parses RFC 4514 text. Blank text is the root.</summary>
    /// <param name="dn">The text.</param>
    /// <exception cref="FormatException">The text is no distinguished name.</exception>
    public static DistinguishedName Parse(string dn) =>
        TryParse(dn, out var result) ? result : throw new FormatException($"Invalid distinguished name '{dn}'.");

    /// <summary>Parses RFC 4514 text without throwing. Blank text is the root.</summary>
    /// <param name="dn">The text.</param>
    /// <param name="result">The name; the root when parsing failed.</param>
    /// <returns>False when the text is null or no distinguished name.</returns>
    public static bool TryParse(string? dn, out DistinguishedName result)
    {
        result = Root;
        if (dn is null) return false;
        if (string.IsNullOrWhiteSpace(dn)) return true;

        var rdns = new List<Rdn>();
        var components = new List<(string, string)>();
        var pos = 0;
        while (true)
        {
            // attribute type
            var start = pos;
            while (pos < dn.Length && dn[pos] != '=') pos++;
            if (pos >= dn.Length) return false;
            var type = dn[start..pos].Trim();
            while (type.StartsWith("OID.", StringComparison.OrdinalIgnoreCase)) type = type[4..].TrimStart();
            if (type.Length == 0 || type.AsSpan().IndexOfAny(",+\\ ") >= 0) return false;
            pos++;

            // attribute value
            while (pos < dn.Length && dn[pos] == ' ') pos++;
            var bytes = new List<byte>();
            var protectedLength = 0; // trailing spaces before this point are escaped and must be kept
            while (pos < dn.Length && dn[pos] is not (',' or ';' or '+'))
            {
                var ch = dn[pos];
                if (ch == '\\')
                {
                    if (pos + 1 >= dn.Length) return false;
                    if (pos + 2 < dn.Length && Uri.IsHexDigit(dn[pos + 1]) && Uri.IsHexDigit(dn[pos + 2]))
                    {
                        bytes.Add(Convert.ToByte(dn.Substring(pos + 1, 2), 16));
                        pos += 3;
                    }
                    else
                    {
                        bytes.AddRange(Utf8.Bytes(dn[pos + 1].ToString()));
                        pos += 2;
                    }
                    protectedLength = bytes.Count;
                }
                else
                {
                    var len = char.IsSurrogatePair(dn, pos) ? 2 : 1;
                    bytes.AddRange(Utf8.Bytes(dn.Substring(pos, len)));
                    pos += len;
                }
            }
            while (bytes.Count > protectedLength && bytes[^1] == (byte)' ') bytes.RemoveAt(bytes.Count - 1);
            components.Add((type, Utf8.String(bytes.ToArray())));

            if (pos >= dn.Length || dn[pos] != '+')
            {
                rdns.Add(new Rdn(components.ToArray()));
                components.Clear();
            }
            if (pos >= dn.Length) break;
            pos++; // separator
        }

        result = new DistinguishedName(rdns);
        return true;
    }

    internal static string EscapeValue(string value)
    {
        var sb = new StringBuilder(value.Length + 4);
        for (var i = 0; i < value.Length; i++)
        {
            var ch = value[i];
            var escape = ch is ',' or '+' or '"' or '\\' or '<' or '>' or ';' or '='
                || (i == 0 && ch is ' ' or '#')
                || (i == value.Length - 1 && ch == ' ');
            if (ch == '\0') sb.Append("\\00");
            else
            {
                if (escape) sb.Append('\\');
                sb.Append(ch);
            }
        }
        return sb.ToString();
    }

    /// <summary>Equal when the normalized forms are: case and insignificant whitespace do not count.</summary>
    /// <param name="other">The other name.</param>
    public bool Equals(DistinguishedName? other) => other is not null && Normalized == other.Normalized;
    /// <inheritdoc cref="Equals(DistinguishedName?)"/>
    public override bool Equals(object? obj) => Equals(obj as DistinguishedName);
    /// <summary>A hash of the normalized form.</summary>
    public override int GetHashCode() => Normalized.GetHashCode();
    /// <summary>The name as written when parsed, re-escaped.</summary>
    public override string ToString() => _text;
}
