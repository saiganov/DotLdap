using System.Text;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>Reads LDIF content records (RFC 2849): comments, folded lines, base64 values. Change records are not supported.</summary>
public static class LdifReader
{
    /// <summary>Reads the entries of LDIF text.</summary>
    /// <param name="ldif">The LDIF text.</param>
    /// <returns>The entries, in the order written.</returns>
    /// <exception cref="FormatException">The text is no well-formed LDIF.</exception>
    /// <exception cref="NotSupportedException">The text holds change records or URL values.</exception>
    public static IReadOnlyList<Entry> Parse(string ldif)
    {
        var entries = new List<Entry>();
        Entry? current = null;

        foreach (var line in Unfold(ldif))
        {
            if (line.Length == 0)
            {
                Flush();
                continue;
            }
            if (line.StartsWith('#')) continue;

            var colon = line.IndexOf(':');
            if (colon <= 0) throw new FormatException($"Invalid LDIF line: '{line}'.");
            var name = line[..colon];
            byte[] value;
            if (line.AsSpan(colon + 1).StartsWith(":"))
                value = Convert.FromBase64String(line[(colon + 2)..].Trim());
            else if (line.AsSpan(colon + 1).StartsWith("<"))
                throw new NotSupportedException("LDIF URL values (attr:< url) are not supported.");
            else
                value = Utf8.Bytes(line[(colon + 1)..].TrimStart(' '));

            if (name.Equals("version", StringComparison.OrdinalIgnoreCase) && current is null) continue;
            if (name.Equals("dn", StringComparison.OrdinalIgnoreCase))
            {
                Flush();
                current = new Entry(DistinguishedName.Parse(Utf8.String(value)));
                continue;
            }
            if (current is null) throw new FormatException($"LDIF attribute '{name}' appears before any dn line.");
            if (name.Equals("changetype", StringComparison.OrdinalIgnoreCase))
                throw new NotSupportedException("LDIF change records are not supported; use content records.");
            current.AddBinary(FilterEvaluator.StripOptions(name), value); // "userCertificate;binary" is userCertificate
        }
        Flush();
        return entries;

        void Flush()
        {
            if (current is not null) entries.Add(current);
            current = null;
        }
    }

    private static IEnumerable<string> Unfold(string ldif)
    {
        StringBuilder? pending = null;
        foreach (var raw in ldif.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith(' ') && pending is not null)
            {
                pending.Append(line, 1, line.Length - 1);
                continue;
            }
            if (pending is not null) yield return pending.ToString();
            pending = new StringBuilder(line);
        }
        if (pending is not null) yield return pending.ToString();
    }
}
