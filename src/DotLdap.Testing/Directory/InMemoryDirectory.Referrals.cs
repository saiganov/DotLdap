using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>
/// Referrals: entries that stand for a part of the tree another server holds (named subordinate references,
/// RFC 3296), and the answer for names this directory has no part of at all.
/// </summary>
public sealed partial class InMemoryDirectory
{
    private IReadOnlyList<string> _defaultReferral = [];

    /// <summary>
    /// Where to send a client that names something outside every naming context of this directory: LDAP URLs
    /// such as <c>ldap://other.example.com</c>. A URL without a DN gets the DN the client asked for (and, for a
    /// search, its scope); one with a DN is sent exactly as it is given. Empty (default): such a request ends
    /// with noSuchObject.
    /// </summary>
    public IReadOnlyList<string> DefaultReferral
    {
        get
        {
            lock (_gate) return _defaultReferral;
        }
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            var urls = value.ToArray();
            foreach (var url in urls) LdapUrl.Check(url);
            lock (_gate) _defaultReferral = urls;
        }
    }

    /// <summary>An entry of class <c>referral</c> that says where to go in <c>ref</c>.</summary>
    internal static bool IsReferral(Entry entry) =>
        entry.GetStrings("ref").Any(url => !string.IsNullOrWhiteSpace(url))
        && entry.GetStrings("objectClass").Contains("referral", StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The referral entry that stands between a client and <paramref name="dn"/>: the entry itself or the one
    /// nearest the root above it. Null when the name is this directory's own business.
    /// </summary>
    internal Entry? ReferralAtOrAbove(DistinguishedName dn)
    {
        lock (_gate)
        {
            Entry? found = null;
            for (var current = dn; current is { IsRoot: false }; current = current.Parent)
                if (_index.TryGetValue(current.Normalized, out var entry) && IsReferral(entry)) found = entry;
            return found?.Clone();
        }
    }

    /// <summary>
    /// The referral entries a search from <paramref name="baseDn"/> runs into: below the base, within the scope,
    /// and not behind another referral entry.
    /// </summary>
    internal IReadOnlyList<Entry> ReferralsBelow(DistinguishedName baseDn, SearchScope scope)
    {
        if (scope == SearchScope.BaseObject) return [];
        lock (_gate)
        {
            var all = _entries.Where(e => IsReferral(e) && !e.Dn.Equals(baseDn) && e.Dn.IsWithin(baseDn)).ToArray();
            if (all.Length == 0) return [];
            return all
                .Where(e => scope == SearchScope.WholeSubtree ? !all.Any(o => !ReferenceEquals(o, e) && e.Dn.IsWithin(o.Dn)) : e.Dn.IsChildOf(baseDn))
                .Select(e => e.Clone())
                .ToArray();
        }
    }

    /// <summary>True when some naming context of this directory holds the name, whether or not an entry has it.</summary>
    internal bool Holds(DistinguishedName dn)
    {
        if (dn.IsRoot || FindSubschema(dn) is not null) return true;
        // The base DN is this directory's own also while no entry has it: that is where the first entry goes.
        return dn.IsWithin(Layout.BaseDn) || NamingContexts.Any(dn.IsWithin);
    }
}

/// <summary>The little of RFC 4516 that referrals need: the DN of an LDAP URL, read and replaced.</summary>
internal static class LdapUrl
{
    /// <summary>
    /// Throws unless the text is an ldap:// or ldaps:// URL that names a host. Stricter than RFC 4516, which
    /// lets the host be left out: a referral is there to say which server.
    /// </summary>
    public static void Check(string url)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (!TrySplit(url, out var server, out _))
            throw new ArgumentException($"'{url}' is not an LDAP URL; expected ldap://host[:port][/dn] or ldaps://...", nameof(url));
        if (server.EndsWith("//", StringComparison.Ordinal))
            throw new ArgumentException($"'{url}' names no host; expected ldap://host[:port][/dn] or ldaps://...", nameof(url));
    }

    /// <summary>
    /// Splits a URL into "scheme://host:port" and its DN (null when it has none). Attributes, scope, filter and
    /// extensions are dropped. The host may be missing, as RFC 4516 allows; user names in the URL are not taken.
    /// </summary>
    public static bool TrySplit(string url, out string server, out string? dn)
    {
        server = "";
        dn = null;
        var scheme = url.StartsWith("ldap://", StringComparison.OrdinalIgnoreCase) ? 7
            : url.StartsWith("ldaps://", StringComparison.OrdinalIgnoreCase) ? 8 : 0;
        if (scheme == 0) return false;
        var slash = url.IndexOf('/', scheme);
        var question = url.IndexOf('?', scheme);
        var hostEnd = slash >= 0 && (question < 0 || slash < question) ? slash : question >= 0 ? question : url.Length;
        if (url.AsSpan().ContainsAny(" \t\r\n")) return false;
        // nothing, host, host:port, [v6] or [v6]:port
        var host = url.AsSpan(scheme, hostEnd - scheme);
        if (!host.IsEmpty)
        {
            var colon = host.LastIndexOf(':');
            if (colon > host.LastIndexOf(']'))
            {
                if (!ushort.TryParse(host[(colon + 1)..], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _)) return false;
                host = host[..colon];
            }
            var bracketed = host.Length > 2 && host[0] == '[' && host[^1] == ']';
            if (host.IsEmpty || host.Contains('@') || (!bracketed && host.ContainsAny(":[]"))) return false;
            // what is in brackets is an IPv6 address (RFC 3986 §3.2.2)
            if (bracketed && !(System.Net.IPAddress.TryParse(host[1..^1], out var address)
                && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)) return false;
        }
        server = url[..hostEnd];
        if (hostEnd == slash)
        {
            var end = question > slash ? question : url.Length;
            if (end > slash + 1)
            {
                var escaped = url.AsSpan(slash + 1, end - slash - 1);
                // "%" is followed by two hex digits or the URL is broken.
                for (var i = escaped.IndexOf('%'); i >= 0; i = escaped[(i + 1)..].IndexOf('%') is >= 0 and var next ? i + 1 + next : -1)
                    if (i + 2 >= escaped.Length || !char.IsAsciiHexDigit(escaped[i + 1]) || !char.IsAsciiHexDigit(escaped[i + 2])) return false;
                dn = Uri.UnescapeDataString(escaped.ToString());
            }
        }
        return true;
    }

    /// <summary>"scheme://host:port/dn", with what a URL cannot carry as it is written percent-encoded, and "??scope" after it when one is given.</summary>
    public static string Build(string server, string dn, string? scope = null)
    {
        var text = new System.Text.StringBuilder(server).Append('/');
        foreach (var b in Utf8.Bytes(dn))
        {
            var c = (char)b;
            // RFC 4516 §2.1: what RFC 3986 calls unreserved or reserved goes as it is, except "?".
            if (b < 0x80 && (char.IsAsciiLetterOrDigit(c) || "-._~!$&'()*+,;=:@/".Contains(c))) text.Append(c);
            else text.Append('%').Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
        }
        if (scope is not null) text.Append("??").Append(scope);
        return text.ToString();
    }
}
