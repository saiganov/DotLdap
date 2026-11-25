using System.Text;

namespace DotLdap.Testing.Protocol;

/// <summary>Search filter AST (RFC 4511 §4.5.1.7). ToString() renders the RFC 4515 text form.</summary>
/// <remarks>
/// Values are byte arrays, which record equality compares by reference: compare two filters by their
/// <c>ToString()</c>, as in <c>Assert.Equal("(uid=alice)", search.Filter.ToString())</c>.
/// </remarks>
public abstract record LdapFilter
{
    // Only the filter types of this library: the evaluator and the encoder know no others.
    private protected LdapFilter()
    {
    }

    /// <summary>Every filter matches. An empty list is true (RFC 4526).</summary>
    /// <param name="Filters">The filters.</param>
    public sealed record And(IReadOnlyList<LdapFilter> Filters) : LdapFilter
    {
        /// <summary>The RFC 4515 text form.</summary>
        public override string ToString() => "(&" + string.Concat(Filters) + ")";
    }

    /// <summary>One filter or more matches. An empty list is false (RFC 4526).</summary>
    /// <param name="Filters">The filters.</param>
    public sealed record Or(IReadOnlyList<LdapFilter> Filters) : LdapFilter
    {
        /// <summary>The RFC 4515 text form.</summary>
        public override string ToString() => "(|" + string.Concat(Filters) + ")";
    }

    /// <summary>The filter does not match.</summary>
    /// <param name="Filter">The filter.</param>
    public sealed record Not(LdapFilter Filter) : LdapFilter
    {
        /// <summary>The RFC 4515 text form.</summary>
        public override string ToString() => "(!" + Filter + ")";
    }

    /// <summary><c>(attr=value)</c>: the attribute has the value, by its equality rule.</summary>
    /// <param name="Attribute">The attribute description.</param>
    /// <param name="Value">The value.</param>
    public sealed record Equality(string Attribute, byte[] Value) : LdapFilter
    {
        /// <summary>The RFC 4515 text form.</summary>
        public override string ToString() => $"({Attribute}={Escape(Value)})";
    }

    /// <summary><c>(attr=ini*any*fin)</c>: a value has these parts, in this order.</summary>
    /// <param name="Attribute">The attribute description.</param>
    /// <param name="Initial">What a value starts with, or null.</param>
    /// <param name="Any">What a value has in between, in order.</param>
    /// <param name="Final">What a value ends with, or null.</param>
    public sealed record Substrings(string Attribute, byte[]? Initial, IReadOnlyList<byte[]> Any, byte[]? Final) : LdapFilter
    {
        /// <summary>The RFC 4515 text form.</summary>
        public override string ToString()
        {
            var sb = new StringBuilder().Append('(').Append(Attribute).Append('=');
            if (Initial is not null) sb.Append(Escape(Initial));
            sb.Append('*');
            foreach (var any in Any) sb.Append(Escape(any)).Append('*');
            if (Final is not null) sb.Append(Escape(Final));
            return sb.Append(')').ToString();
        }
    }

    /// <summary><c>(attr&gt;=value)</c>: a value sorts at or after this one, by the attribute's ordering rule.</summary>
    /// <param name="Attribute">The attribute description.</param>
    /// <param name="Value">The value.</param>
    public sealed record GreaterOrEqual(string Attribute, byte[] Value) : LdapFilter
    {
        /// <summary>The RFC 4515 text form.</summary>
        public override string ToString() => $"({Attribute}>={Escape(Value)})";
    }

    /// <summary><c>(attr&lt;=value)</c>: a value sorts at or before this one, by the attribute's ordering rule.</summary>
    /// <param name="Attribute">The attribute description.</param>
    /// <param name="Value">The value.</param>
    public sealed record LessOrEqual(string Attribute, byte[] Value) : LdapFilter
    {
        /// <summary>The RFC 4515 text form.</summary>
        public override string ToString() => $"({Attribute}<={Escape(Value)})";
    }

    /// <summary><c>(attr=*)</c>: the entry has the attribute.</summary>
    /// <param name="Attribute">The attribute description.</param>
    public sealed record Present(string Attribute) : LdapFilter
    {
        /// <summary>The RFC 4515 text form.</summary>
        public override string ToString() => $"({Attribute}=*)";
    }

    /// <summary><c>(attr~=value)</c>: approximately equal; this server treats it as equality.</summary>
    /// <param name="Attribute">The attribute description.</param>
    /// <param name="Value">The value.</param>
    public sealed record Approx(string Attribute, byte[] Value) : LdapFilter
    {
        /// <summary>The RFC 4515 text form.</summary>
        public override string ToString() => $"({Attribute}~={Escape(Value)})";
    }

    /// <summary><c>(attr:dn:rule:=value)</c>: a match by a named matching rule.</summary>
    /// <param name="MatchingRule">The matching rule's OID, or null for the attribute's equality rule.</param>
    /// <param name="Attribute">The attribute description, or null for every attribute the rule applies to.</param>
    /// <param name="Value">The value.</param>
    /// <param name="DnAttributes">True when the values in the entry's name count as well.</param>
    public sealed record Extensible(string? MatchingRule, string? Attribute, byte[] Value, bool DnAttributes) : LdapFilter
    {
        /// <summary>The RFC 4515 text form.</summary>
        public override string ToString() =>
            $"({Attribute}{(DnAttributes ? ":dn" : "")}{(MatchingRule is null ? "" : ":" + MatchingRule)}:={Escape(Value)})";
    }

    /// <summary>Parses the RFC 4515 text form, e.g. <c>(&amp;(objectClass=person)(uid=a*))</c>.</summary>
    public static LdapFilter Parse(string text) => LdapFilterParser.Parse(text);

    internal static string Escape(ReadOnlySpan<byte> value)
    {
        var sb = new StringBuilder();
        var valid = IsValidUtf8(value);
        if (valid)
        {
            foreach (var ch in Utf8.String(value))
            {
                if (ch is '*' or '(' or ')' or '\\' or '\0') sb.Append('\\').Append(((int)ch).ToString("x2"));
                else sb.Append(ch);
            }
        }
        else
        {
            foreach (var b in value) sb.Append('\\').Append(b.ToString("x2"));
        }
        return sb.ToString();
    }

    private static bool IsValidUtf8(ReadOnlySpan<byte> value)
    {
        try
        {
            new UTF8Encoding(false, throwOnInvalidBytes: true).GetCharCount(value);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}

internal static class LdapFilterParser
{
    public static LdapFilter Parse(string text)
    {
        var pos = 0;
        text = text.Trim();
        if (!text.StartsWith('(')) text = "(" + text + ")";
        var filter = ParseFilter(text, ref pos, 0);
        if (pos != text.Length) throw new FormatException($"Unexpected trailing characters in filter at position {pos}.");
        return filter;
    }

    private static LdapFilter ParseFilter(string s, ref int pos, int depth)
    {
        if (depth > 64) throw new FormatException("Filter is nested too deeply.");
        Expect(s, ref pos, '(');
        if (pos >= s.Length) throw new FormatException("Unexpected end of filter.");
        LdapFilter result;
        switch (s[pos])
        {
            case '&':
            case '|':
                var isAnd = s[pos++] == '&';
                var list = new List<LdapFilter>();
                while (pos < s.Length && s[pos] == '(') list.Add(ParseFilter(s, ref pos, depth + 1));
                result = isAnd ? new LdapFilter.And(list) : new LdapFilter.Or(list);
                break;
            case '!':
                pos++;
                result = new LdapFilter.Not(ParseFilter(s, ref pos, depth + 1));
                break;
            default:
                result = ParseItem(s, ref pos);
                break;
        }
        Expect(s, ref pos, ')');
        return result;
    }

    private static LdapFilter ParseItem(string s, ref int pos)
    {
        var end = s.IndexOf(')', pos);
        if (end < 0) throw new FormatException("Missing ')' in filter.");
        var item = s[pos..end];
        pos = end;
        var eq = item.IndexOf('=');
        if (eq <= 0) throw new FormatException($"Invalid filter item '{item}'.");
        var left = item[..eq];
        var right = item[(eq + 1)..];
        switch (left[^1])
        {
            case '~': return new LdapFilter.Approx(left[..^1], Unescape(right));
            case '>': return new LdapFilter.GreaterOrEqual(left[..^1], Unescape(right));
            case '<': return new LdapFilter.LessOrEqual(left[..^1], Unescape(right));
            case ':':
                var parts = left[..^1].Split(':');
                var attribute = parts[0].Length == 0 ? null : parts[0];
                var dn = parts.Skip(1).Any(p => p.Equals("dn", StringComparison.OrdinalIgnoreCase));
                var rule = parts.Skip(1).FirstOrDefault(p => !p.Equals("dn", StringComparison.OrdinalIgnoreCase));
                return new LdapFilter.Extensible(rule, attribute, Unescape(right), dn);
        }
        if (right == "*") return new LdapFilter.Present(left);
        if (!right.Contains('*')) return new LdapFilter.Equality(left, Unescape(right));
        var pieces = right.Split('*');
        return new LdapFilter.Substrings(
            left,
            pieces[0].Length == 0 ? null : Unescape(pieces[0]),
            pieces[1..^1].Where(p => p.Length > 0).Select(Unescape).ToList(),
            pieces[^1].Length == 0 ? null : Unescape(pieces[^1]));
    }

    private static byte[] Unescape(string value)
    {
        if (!value.Contains('\\')) return Utf8.Bytes(value);
        var bytes = new List<byte>();
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\')
            {
                if (i + 2 >= value.Length) throw new FormatException("Truncated escape in filter value.");
                // checked by hand: Convert.ToByte takes "-f" and "0x" for hex and fails in its own ways
                if (!Uri.IsHexDigit(value[i + 1]) || !Uri.IsHexDigit(value[i + 2]))
                    throw new FormatException($"Invalid escape '\\{value.Substring(i + 1, 2)}' in filter value: a backslash takes two hex digits.");
                bytes.Add(Convert.ToByte(value.Substring(i + 1, 2), 16));
                i += 2;
            }
            else
            {
                var len = char.IsHighSurrogate(value[i]) && i + 1 < value.Length ? 2 : 1;
                bytes.AddRange(Utf8.Bytes(value.Substring(i, len)));
                i += len - 1;
            }
        }
        return bytes.ToArray();
    }

    private static void Expect(string s, ref int pos, char ch)
    {
        if (pos >= s.Length || s[pos] != ch) throw new FormatException($"Expected '{ch}' at position {pos} in filter.");
        pos++;
    }
}
