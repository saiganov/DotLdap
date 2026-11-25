using System.Globalization;
using System.Numerics;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>
/// Evaluates search filters against entries. Without a schema, matching rules are picked by attribute name:
/// DN-valued attributes compare as DNs, a few binary attributes compare byte for byte, everything else is a
/// case-insensitive string (numeric when both sides are numbers, for ordering).
/// </summary>
internal sealed class FilterEvaluator(InMemoryDirectory directory)
{
    public const string MatchingRuleInChain = "1.2.840.113556.1.4.1941";
    public const string MatchingRuleBitAnd = "1.2.840.113556.1.4.803";
    public const string MatchingRuleBitOr = "1.2.840.113556.1.4.804";
    private const string CaseExactMatch = "2.5.13.5";

    private static readonly HashSet<string> DnAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "member", "uniqueMember", "memberOf", "manager", "owner", "seeAlso", "roleOccupant", "secretary",
        "distinguishedName", "entryDN", "directReports", "managedBy", "objectCategory",
    };

    private static readonly HashSet<string> BinaryAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "userPassword", "objectGUID", "objectSid", "jpegPhoto", "thumbnailPhoto", "userCertificate",
    };

    public bool Matches(LdapFilter filter, Entry entry) => filter switch
    {
        LdapFilter.And and => and.Filters.All(f => Matches(f, entry)),
        LdapFilter.Or or => or.Filters.Any(f => Matches(f, entry)),
        LdapFilter.Not not => !Matches(not.Filter, entry),
        LdapFilter.Present present => Values(entry, present.Attribute).Count > 0,
        LdapFilter.Equality eq => Values(entry, eq.Attribute).Any(v => AssertionMatches(eq.Attribute, v, eq.Value)),
        LdapFilter.Approx approx => Values(entry, approx.Attribute).Any(v => AssertionMatches(approx.Attribute, v, approx.Value)),
        LdapFilter.GreaterOrEqual ge => Values(entry, ge.Attribute).Any(v => Compare(v, ge.Value) >= 0),
        LdapFilter.LessOrEqual le => Values(entry, le.Attribute).Any(v => Compare(v, le.Value) <= 0),
        LdapFilter.Substrings sub => Values(entry, sub.Attribute).Any(v => MatchesSubstrings(sub, v)),
        LdapFilter.Extensible ext => MatchesExtensible(ext, entry),
        _ => false,
    };

    /// <summary>
    /// Equality as a search filter sees it: <see cref="ValueEquals"/> plus the short forms Active Directory
    /// accepts in a filter. Those are ways to write the assertion, not values the attribute holds, so Compare
    /// and Modify do not know them.
    /// </summary>
    public static bool AssertionMatches(string attribute, byte[] stored, byte[] asserted)
    {
        attribute = StripOptions(attribute);
        // A SID in its string form, (objectSid=S-1-5-21-...), for an attribute that holds the binary form.
        if (attribute.Equals("objectSid", StringComparison.OrdinalIgnoreCase) && asserted.Length > 4
            && Utf8.TryString(asserted, out var text) && text.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
            && ActiveDirectory.ParseSid(text) is { } sid && stored.AsSpan().SequenceEqual(sid))
            return true;
        // A class name, (objectCategory=person), for an attribute that holds CN=Person,CN=Schema,CN=Configuration,...
        if (attribute.Equals("objectCategory", StringComparison.OrdinalIgnoreCase)
            && Utf8.TryString(stored, out var a) && Utf8.TryString(asserted, out var b) && !b.Contains('=')
            && DistinguishedName.TryParse(a, out var category) && !category.IsRoot)
            return string.Equals(category.Leaf!.Value, ActiveDirectory.CategoryOfClass(b.Trim()) ?? b.Trim(), StringComparison.OrdinalIgnoreCase);
        return ValueEquals(attribute, stored, asserted);
    }

    public static bool ValueEquals(string attribute, byte[] stored, byte[] asserted)
    {
        attribute = StripOptions(attribute);
        if (BinaryAttributes.Contains(attribute)) return stored.AsSpan().SequenceEqual(asserted);
        // Without a schema, a value that is not text is taken as binary: two different photos must not turn
        // equal because both decode to the same replacement characters.
        if (!Utf8.TryString(stored, out var a) || !Utf8.TryString(asserted, out var b))
            return stored.AsSpan().SequenceEqual(asserted);
        if (DnAttributes.Contains(attribute)
            && DistinguishedName.TryParse(a, out var dnA) && DistinguishedName.TryParse(b, out var dnB))
            return dnA.Equals(dnB);
        return string.Equals(a.Trim(), b.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A key that is the same for two values exactly when <see cref="ValueEquals"/> calls them equal. Lets the
    /// write paths find duplicates in one pass.
    /// </summary>
    public static string EqualityKey(string attribute, byte[] value)
    {
        attribute = StripOptions(attribute);
        if (BinaryAttributes.Contains(attribute) || !Utf8.TryString(value, out var text)) return "b:" + Convert.ToHexString(value);
        if (DnAttributes.Contains(attribute) && DistinguishedName.TryParse(text, out var dn)) return "d:" + dn.Normalized;
        return "s:" + text.Trim().ToUpperInvariant();
    }

    private IReadOnlyList<byte[]> Values(Entry entry, string attribute) => directory.GetValues(entry, StripOptions(attribute));

    internal static string StripOptions(string attribute)
    {
        var semicolon = attribute.IndexOf(';');
        return semicolon < 0 ? attribute : attribute[..semicolon];
    }

    private static int Compare(byte[] stored, byte[] asserted)
    {
        var a = Utf8.String(stored).Trim();
        var b = Utf8.String(asserted).Trim();
        if (BigInteger.TryParse(a, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var numA)
            && BigInteger.TryParse(b, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var numB))
            return numA.CompareTo(numB);
        return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesSubstrings(LdapFilter.Substrings filter, byte[] stored)
    {
        const StringComparison cmp = StringComparison.OrdinalIgnoreCase;
        var value = Utf8.String(stored);
        var pos = 0;
        if (filter.Initial is not null)
        {
            var initial = Utf8.String(filter.Initial);
            if (!value.StartsWith(initial, cmp)) return false;
            pos = initial.Length;
        }
        foreach (var anyBytes in filter.Any)
        {
            var any = Utf8.String(anyBytes);
            var found = value.IndexOf(any, pos, cmp);
            if (found < 0) return false;
            pos = found + any.Length;
        }
        if (filter.Final is not null)
        {
            var final = Utf8.String(filter.Final);
            if (value.Length - pos < final.Length || !value.EndsWith(final, cmp)) return false;
        }
        return true;
    }

    private bool MatchesExtensible(LdapFilter.Extensible filter, Entry entry)
    {
        switch (filter.MatchingRule)
        {
            case MatchingRuleInChain:
                return filter.Attribute is not null && MatchesInChain(StripOptions(filter.Attribute), filter.Value, entry);
            case MatchingRuleBitAnd:
            case MatchingRuleBitOr:
                if (filter.Attribute is null || !long.TryParse(Utf8.String(filter.Value), out var mask)) return false;
                return Values(entry, filter.Attribute).Any(v =>
                    long.TryParse(Utf8.String(v), out var number)
                    && (filter.MatchingRule == MatchingRuleBitAnd ? (number & mask) == mask : (number & mask) != 0));
        }

        Func<string, byte[], bool> equals = filter.MatchingRule == CaseExactMatch
            ? (_, v) => Utf8.String(v) == Utf8.String(filter.Value)
            : (name, v) => AssertionMatches(name, v, filter.Value);

        var names = filter.Attribute is not null ? [filter.Attribute] : directory.AttributeNames(entry).ToArray();
        if (names.Any(name => Values(entry, name).Any(v => equals(name, v)))) return true;

        // ":dn" also matches against the components of the entry's DN, e.g. (ou:dn:=people)
        return filter.DnAttributes && entry.Dn.Rdns.SelectMany(r => r.Components).Any(c =>
            (filter.Attribute is null || c.Type.Equals(StripOptions(filter.Attribute), StringComparison.OrdinalIgnoreCase))
            && equals(c.Type, Utf8.Bytes(c.Value)));
    }

    /// <summary>LDAP_MATCHING_RULE_IN_CHAIN: nested group membership in a single filter, as Active Directory does it.</summary>
    private bool MatchesInChain(string attribute, byte[] value, Entry entry)
    {
        if (!DistinguishedName.TryParse(Utf8.String(value), out var target)) return false;
        if (attribute.Equals("memberOf", StringComparison.OrdinalIgnoreCase))
            return directory.GroupsOf(entry.Dn, transitive: true).Contains(target);
        if (attribute.Equals("member", StringComparison.OrdinalIgnoreCase))
            return directory.GroupsOf(target, transitive: true).Contains(entry.Dn);
        return false;
    }
}
