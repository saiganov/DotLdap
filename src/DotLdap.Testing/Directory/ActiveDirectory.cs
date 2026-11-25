using System.Buffers.Binary;
using System.Globalization;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>
/// What makes an entry look like it came from Active Directory: the attributes AD fills in by itself,
/// SID handling, account state for bind, and the constructed attributes tokenGroups and primaryGroupToken.
/// </summary>
internal static class ActiveDirectory
{
    public const int DomainUsersRid = 513;
    private const long Never = long.MaxValue; // accountExpires value meaning "does not expire"

    private const int AccountDisabled = 0x2;
    private const int PasswordExpired = 0x800000;

    /// <summary>Fills in the attributes Active Directory generates for a new object. Existing values are kept.</summary>
    public static void ApplyDefaults(Entry entry, DirectoryLayout layout)
    {
        var classes = entry.GetStrings("objectClass");
        bool Is(string name) => classes.Any(c => c.Equals(name, StringComparison.OrdinalIgnoreCase));
        var isComputer = Is("computer");
        var isUser = Is("user") && !isComputer;
        var isGroup = Is("group");

        SetIfMissing(entry, "name", entry.Dn.Leaf!.Value);
        SetIfMissing(entry, "whenCreated", DateTime.UtcNow.ToString("yyyyMMddHHmmss'.0Z'", CultureInfo.InvariantCulture));
        if (!entry.Has("objectGUID")) entry.SetBinary("objectGUID", Guid.NewGuid().ToByteArray());

        // The most specific class decides; the table is the one filters use, so (objectCategory=contact) finds
        // what was stored for a contact.
        var category = CategoryClasses.Where(Is).Select(CategoryOfClass).FirstOrDefault();
        if (category is not null) SetIfMissing(entry, "objectCategory", $"CN={category},CN=Schema,CN=Configuration,{DomainOf(entry.Dn, layout)}");

        if (!isUser && !isGroup && !isComputer) return;
        // "Domain Users" is the one group with a fixed RID: it is what primaryGroupID 513 points at.
        int? rid = IsDomainUsers(entry) ? DomainUsersRid : null;
        if (!entry.Has("objectSid")) entry.SetBinary("objectSid", NewSid(layout, rid));
        SetIfMissing(entry, "sAMAccountType", isComputer ? "805306369" : isUser ? "805306368" : "268435456");
        if (isGroup) return;

        SetIfMissing(entry, "primaryGroupID", (isComputer ? 515 : DomainUsersRid).ToString(CultureInfo.InvariantCulture));
        SetIfMissing(entry, "accountExpires", Never.ToString(CultureInfo.InvariantCulture));
        if (entry.Has("userPassword")) SetIfMissing(entry, "pwdLastSet", Now());
        ResolvePwdLastSet(entry);
    }

    /// <summary>
    /// The domain an entry belongs to: the DC components its DN ends with. Test data may hold a second tree next
    /// to the layout's base DN; its entries belong to their own domain, not to the layout's.
    /// </summary>
    private static string DomainOf(DistinguishedName dn, DirectoryLayout layout)
    {
        var domain = dn.Rdns.Reverse().TakeWhile(r => r.Type.Equals("dc", StringComparison.OrdinalIgnoreCase)).Reverse().ToArray();
        return domain.Length == 0 ? layout.BaseDn.ToString() : string.Join(",", domain.Select(r => r.ToString()));
    }

    public const string DomainUsersName = "Domain Users";

    private static readonly string[] CategoryClasses =
        ["computer", "group", "user", "contact", "inetOrgPerson", "organizationalUnit", "domainDNS", "container", "person"];

    /// <summary>A group called "Domain Users", by sAMAccountName or, without one, by its RDN.</summary>
    public static bool IsDomainUsers(Entry entry) =>
        DomainUsersName.Equals(entry.GetString("sAMAccountName") ?? entry.Dn.Leaf!.Value, StringComparison.OrdinalIgnoreCase)
        && entry.GetStrings("objectClass").Contains("group", StringComparer.OrdinalIgnoreCase);

    /// <summary>True for an account whose primary group is "Domain Users", which then has to exist.</summary>
    public static bool NeedsDomainUsers(Entry entry) =>
        entry.GetString("primaryGroupID") == DomainUsersRid.ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// The CN of the objectCategory a class name stands for in a filter: Active Directory reads
    /// (objectCategory=user) as "the default category of class user", which is Person. Null for a name that is
    /// not one of the common classes.
    /// </summary>
    public static string? CategoryOfClass(string className) => className.ToLowerInvariant() switch
    {
        "person" or "organizationalperson" or "user" or "contact" or "inetorgperson" => "Person",
        "computer" => "Computer",
        "group" => "Group",
        "organizationalunit" => "Organizational-Unit",
        "domaindns" or "domain" => "Domain-DNS",
        "container" => "Container",
        _ => null,
    };

    /// <summary>Call after a password was set: the "must change password at next logon" state ends.</summary>
    /// <param name="entry">The account.</param>
    /// <param name="mustChange">The same request asks for "must change at next logon" (pwdLastSet 0), which then stays.</param>
    public static void PasswordWasSet(Entry entry, bool mustChange = false)
    {
        if (!mustChange) entry.Set("pwdLastSet", Now());
        // ...and so does "password expired"
        if (long.TryParse(entry.GetString("userAccountControl"), out var control) && (control & PasswordExpired) != 0)
            entry.Set("userAccountControl", (control & ~(long)PasswordExpired).ToString(CultureInfo.InvariantCulture));
    }

    /// <summary>The ACCOUNTDISABLE bit of userAccountControl.</summary>
    public static bool IsDisabled(Entry entry) =>
        long.TryParse(entry.GetString("userAccountControl"), out var control) && (control & AccountDisabled) != 0;

    /// <summary>
    /// Locked out: lockoutTime is set and the lockout has not run out yet. A domain controller leaves the old
    /// lockoutTime in place afterwards, so exports are full of accounts with a lockoutTime years back that log on fine.
    /// </summary>
    public static bool IsLockedOut(Entry entry, DirectoryLayout layout)
    {
        if (!long.TryParse(entry.GetString("lockoutTime"), out var time) || time <= 0) return false;
        if (layout.LockoutDuration <= TimeSpan.Zero) return true; // until an administrator unlocks the account
        // A lockout made by LockedOut() stays: whether a test passes must not depend on how long the suite has
        // been running.
        if (layout.PermanentLockouts.ContainsKey(time)) return true;
        // Compared in ticks so that an absurd lockoutTime cannot overflow a DateTime.
        return time > DateTime.UtcNow.ToFileTimeUtc() - layout.LockoutDuration.Ticks;
    }

    /// <summary>Writing pwdLastSet = -1 is how a client says "the password was set just now".</summary>
    public static void ResolvePwdLastSet(Entry entry)
    {
        if (entry.GetString("pwdLastSet") == "-1") entry.Set("pwdLastSet", Now());
    }

    /// <summary>
    /// The sub-code AD puts into the bind error text when the password is right but the account may not log on:
    /// 533 disabled, 701 account expired, 532 password expired, 773 must change password. Null when logon is allowed.
    /// </summary>
    public static string? LogonRestriction(Entry entry)
    {
        long.TryParse(entry.GetString("userAccountControl"), out var control);
        if ((control & AccountDisabled) != 0) return "533";
        if (long.TryParse(entry.GetString("accountExpires"), out var expires) && expires != 0 && expires != Never
            && expires < DateTime.UtcNow.ToFileTimeUtc()) return "701";
        if ((control & PasswordExpired) != 0) return "532";
        if (entry.GetString("pwdLastSet") == "0") return "773";
        return null;
    }

    private static string Now() => DateTime.UtcNow.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture);

    private static void SetIfMissing(Entry entry, string name, string value)
    {
        if (!entry.Has(name)) entry.Set(name, value);
    }

    // ---- SIDs: S-1-5-21-<domain: three numbers>-<rid> ----------------------------------------------------------

    public static byte[] NewSid(DirectoryLayout layout, int? rid = null)
    {
        uint[] sub = [21, .. layout.DomainSid, (uint)(rid ?? Interlocked.Increment(ref layout.NextRid))];
        var sid = new byte[8 + sub.Length * 4];
        sid[0] = 1;
        sid[1] = (byte)sub.Length;
        sid[7] = 5;
        for (var i = 0; i < sub.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(sid.AsSpan(8 + i * 4), sub[i]);
        return sid;
    }

    /// <summary>The SID of another object in the same domain: the same SID with the last number replaced.</summary>
    public static byte[] WithRid(byte[] sid, uint rid)
    {
        var result = (byte[])sid.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(result.Length - 4), rid);
        return result;
    }

    public static uint? Rid(byte[] sid) =>
        sid.Length >= 12 && sid.Length == 8 + sid[1] * 4 ? BinaryPrimitives.ReadUInt32LittleEndian(sid.AsSpan(sid.Length - 4)) : null;

    public static string SidToString(byte[] sid)
    {
        ulong authority = 0;
        for (var i = 2; i < 8; i++) authority = (authority << 8) | sid[i];
        var parts = new List<string> { "S", sid[0].ToString(CultureInfo.InvariantCulture), authority.ToString(CultureInfo.InvariantCulture) };
        for (var i = 0; i < sid[1]; i++)
            parts.Add(BinaryPrimitives.ReadUInt32LittleEndian(sid.AsSpan(8 + i * 4)).ToString(CultureInfo.InvariantCulture));
        return string.Join("-", parts);
    }

    public static byte[]? ParseSid(string text)
    {
        var parts = text.Split('-');
        if (parts.Length < 3 || parts.Length > 18 || !parts[0].Equals("S", StringComparison.OrdinalIgnoreCase)) return null;
        if (!byte.TryParse(parts[1], out var revision) || !ulong.TryParse(parts[2], out var authority)) return null;
        var sid = new byte[8 + (parts.Length - 3) * 4];
        sid[0] = revision;
        sid[1] = (byte)(parts.Length - 3);
        for (var i = 7; i >= 2; i--)
        {
            sid[i] = (byte)(authority & 0xFF);
            authority >>= 8;
        }
        for (var i = 3; i < parts.Length; i++)
        {
            if (!uint.TryParse(parts[i], out var sub)) return null;
            BinaryPrimitives.WriteUInt32LittleEndian(sid.AsSpan(8 + (i - 3) * 4), sub);
        }
        return sid;
    }

    // ---- constructed attributes ----------------------------------------------------------------------------------

    /// <summary>tokenGroups: SIDs of every group the object belongs to, nested groups and the primary group included.</summary>
    public sealed class TokenGroups : IVirtualAttributeProvider
    {
        public string AttributeName => "tokenGroups";
        public bool IsOperational => true;

        public IReadOnlyList<byte[]> GetValues(Entry entry, IDirectoryView directory)
        {
            if (!entry.Has("objectSid")) return [];
            var groups = new Dictionary<string, DistinguishedName>();
            foreach (var group in directory.GroupsOf(entry.Dn, transitive: true)) groups.TryAdd(group.Normalized, group);

            var ownSid = entry.GetValues("objectSid")[0];
            if (uint.TryParse(entry.GetString("primaryGroupID"), out var primaryRid) && Rid(ownSid) is not null)
            {
                // The primary group lives in the account's own domain: same SID, with the RID replaced.
                var primarySid = WithRid(ownSid, primaryRid);
                var primary = directory.Entries.FirstOrDefault(e =>
                    e.GetValues("objectSid") is { Count: > 0 } sid && sid[0].AsSpan().SequenceEqual(primarySid)
                    && e.GetStrings("objectClass").Contains("group", StringComparer.OrdinalIgnoreCase));
                // Accounts and "Domain Users" need not share a domain SID: test data from a real domain next to
                // builder users, or a generated group next to imported accounts. 513 still means that group.
                if (primary is null && primaryRid == DomainUsersRid && directory is InMemoryDirectory inMemory)
                    primary = inMemory.DomainUsersGroup();
                if (primary is not null)
                {
                    groups.TryAdd(primary.Dn.Normalized, primary.Dn);
                    foreach (var group in directory.GroupsOf(primary.Dn, transitive: true)) groups.TryAdd(group.Normalized, group);
                }
            }

            return groups.Values
                .Select(dn => directory.Find(dn)?.GetValues("objectSid"))
                .Where(sid => sid is { Count: > 0 })
                .Select(sid => sid![0])
                .ToArray();
        }
    }

    /// <summary>primaryGroupToken: the RID of a group, the value users carry in primaryGroupID.</summary>
    public sealed class PrimaryGroupToken : IVirtualAttributeProvider
    {
        public string AttributeName => "primaryGroupToken";
        public bool IsOperational => true;

        public IReadOnlyList<byte[]> GetValues(Entry entry, IDirectoryView directory) =>
            entry.GetStrings("objectClass").Contains("group", StringComparer.OrdinalIgnoreCase)
            && entry.GetValues("objectSid") is { Count: > 0 } sid && Rid(sid[0]) is { } rid
                ? [Utf8.Bytes(rid.ToString(CultureInfo.InvariantCulture))]
                : [];
    }
}
