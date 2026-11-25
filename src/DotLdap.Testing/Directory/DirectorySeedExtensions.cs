using System.Buffers.Binary;

namespace DotLdap.Testing;

/// <summary>Fluent helpers that create typical user and group entries for the directory's <see cref="DirectoryLayout"/>.</summary>
public static class DirectorySeedExtensions
{
    /// <summary>DN the helpers use for a user with this login name.</summary>
    public static DistinguishedName UserDn(this InMemoryDirectory directory, string name) =>
        directory.Layout.UsersDn.Child(directory.Layout.IsActiveDirectory ? "CN" : "uid", name);

    /// <summary>DN the helpers use for a group with this name.</summary>
    public static DistinguishedName GroupDn(this InMemoryDirectory directory, string name) =>
        directory.Layout.GroupsDn.Child(directory.Layout.IsActiveDirectory ? "CN" : "cn", name);

    /// <summary>
    /// Adds a user that can bind with the given password. The password is stored as given, so it may also be a
    /// ready-made hash such as <c>{SSHA}...</c>. Returns the user's DN.
    /// </summary>
    /// <exception cref="InvalidOperationException">An entry with the user's DN exists already, or an account-state method needs the other flavour.</exception>
    public static DistinguishedName AddUser(this InMemoryDirectory directory, string name, string password, Action<UserBuilder>? configure = null)
    {
        var layout = directory.Layout;
        var entry = new Entry(directory.UserDn(name));
        if (layout.IsActiveDirectory)
        {
            entry.Set("objectClass", "top", "person", "organizationalPerson", "user")
                .Set("cn", name)
                .Set("sAMAccountName", name)
                .Set("userPrincipalName", name + "@" + layout.DomainName)
                .Set("userAccountControl", "512");
        }
        else
        {
            entry.Set("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
                .Set("uid", name)
                .Set("cn", name)
                .Set("sn", name);
        }
        entry.Set("userPassword", password); // as given: clear text, or a ready-made {SSHA}-style hash

        var builder = new UserBuilder(entry, layout);
        configure?.Invoke(builder);
        // Before the user is added: a group that cannot be filled must not leave half a user behind.
        foreach (var group in builder.Groups) directory.GroupFor(group, entry.Dn);
        directory.Add(entry); // the Active Directory flavour fills in the attributes AD generates
        foreach (var group in builder.Groups) directory.AddToGroup(group, entry.Dn);
        if (builder.IsReadOnly) directory.SetReadOnly(entry.Dn);
        return entry.Dn;
    }

    /// <summary>
    /// Adds a group. Members are user names, names of existing groups (nested groups), or full DNs.
    /// Returns the group's DN.
    /// </summary>
    /// <exception cref="InvalidOperationException">An entry with the group's DN exists already.</exception>
    public static DistinguishedName AddGroup(this InMemoryDirectory directory, string name, params string[] members)
    {
        var layout = directory.Layout;
        var dn = directory.GroupDn(name);
        var resolved = members.Select(m => directory.ResolveMember(m).ToString()).ToArray();
        var entry = new Entry(dn).Set("cn", name);
        if (layout.IsActiveDirectory)
        {
            entry.Set("objectClass", "top", "group")
                .Set("sAMAccountName", name)
                .Set("groupType", "-2147483646");
        }
        else
        {
            entry.Set("objectClass", "top", "groupOfNames");
        }
        entry.Add("member", resolved);
        directory.Add(entry);
        return dn;
    }

    /// <summary>
    /// Adds a member to a group; a member that is there already is not added again. The group is given by name
    /// or by DN. By name it is created when it does not exist yet. A DN says where the group is, so it has to be
    /// there already, unless it is the very DN a group of that name would get from <see cref="AddGroup"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The group is given by a DN that does not exist, or it is the member itself.</exception>
    public static void AddToGroup(this InMemoryDirectory directory, string group, DistinguishedName member)
    {
        var dn = directory.GroupFor(group, member);
        if (!directory.Exists(dn)) directory.AddGroup(dn.Leaf!.Value);
        directory.AddMember(dn, member);
    }

    /// <summary>The DN of the group <see cref="AddToGroup"/> would fill, or the reason it cannot.</summary>
    internal static DistinguishedName GroupFor(this InMemoryDirectory directory, string group, DistinguishedName member)
    {
        var dn = group.Contains('=') ? DistinguishedName.Parse(group) : directory.GroupDn(group);
        // In Active Directory users and groups share a container: a user "x" in a group "x" would be put into itself.
        if (dn.Equals(member)) throw new InvalidOperationException($"'{dn}' cannot be a member of itself.");
        if (!directory.Exists(dn) && !dn.Equals(directory.GroupDn(dn.Leaf!.Value)))
            throw new InvalidOperationException($"Group '{dn}' does not exist.");
        return dn;
    }

    /// <summary>Adds a member value unless one that names the same entry is there, however it is spelled.</summary>
    internal static void AddMember(this InMemoryDirectory directory, DistinguishedName group, DistinguishedName member) =>
        directory.Update(group, g =>
        {
            if (!g.GetStrings("member").Any(m => DistinguishedName.TryParse(m, out var present) && present.Equals(member)))
                g.Add("member", member.ToString());
        });

    /// <summary>Loads LDIF content records. Returns the number of entries added.</summary>
    public static int AddLdif(this InMemoryDirectory directory, string ldif)
    {
        var entries = LdifReader.Parse(ldif);
        foreach (var entry in entries) directory.Add(entry);
        return entries.Count;
    }

    /// <summary>
    /// Loads users, groups and entries from JSON. Returns how many of them the text describes (groups that come
    /// into being only because a user names them are not counted).
    /// <code>
    /// {
    ///   "users":   [ { "name": "alice", "password": "s3cret", "email": "alice@example.com", "groups": ["admins"],
    ///                  "attributes": { "title": "Engineer" }, "disabled": false } ],
    ///   "groups":  [ { "name": "staff", "members": ["alice", "admins"] } ],
    ///   "entries": [ { "dn": "ou=printers,dc=example,dc=com", "attributes": { "objectClass": ["top", "organizationalUnit"] } } ]
    /// }
    /// </code>
    /// Users and groups are what <see cref="AddUser"/> and <see cref="AddGroup"/> make of them, so one file serves
    /// both flavours. A user also takes <c>displayName</c>, <c>firstName</c>, <c>lastName</c> and the flags
    /// <c>disabled</c>, <c>lockedOut</c>, <c>mustChangePassword</c>, <c>accountExpired</c>, <c>passwordExpired</c>
    /// and <c>readOnly</c>; "attributes" are applied after the named properties and may replace what they and the
    /// helper set, flags come last. Users, groups and entries are created first and memberships filled in
    /// afterwards, so the order within the file is free: a group may be named by a user, listed under "groups"
    /// and have members defined further down. A member or group is given by name or by DN: a member's name must
    /// be a user or group once everything is created, a member's DN is taken as it is, and a user's group follows
    /// the rules of <see cref="AddToGroup"/>. A membership stated twice is kept once. An attribute takes
    /// one value or a list; a value is a string, a number, a boolean or <c>{ "base64": "..." }</c>. Comments and
    /// trailing commas are allowed, and property names are read whatever their case.
    /// </summary>
    /// <exception cref="FormatException">The text is not JSON, has a property the format does not know, or
    /// describes something the directory refuses; the message says where (<c>$.users[1].mail</c>). A mistake in
    /// the file itself is found before anything is added. What only the directory can refuse, such as an entry
    /// that exists already, is found on the way: what came before it has been added by then.</exception>
    public static int AddJson(this InMemoryDirectory directory, string json) => JsonSeed.Load(directory, json);

    /// <summary>
    /// Adds a referral entry (RFC 3296): this part of the tree is held by the servers the LDAP URLs name, e.g.
    /// <c>AddReferral("ou=partners,dc=example,dc=com", "ldap://partners.example.com/ou=people,dc=partners,dc=com")</c>.
    /// A search that reaches the entry gets a reference to those servers in place of it, and any request that
    /// names the entry or something below it is answered with <c>referral</c> (10). The DN in a URL is the
    /// entry's name on the other server; a URL without one means the same name.
    /// </summary>
    public static DistinguishedName AddReferral(this InMemoryDirectory directory, string dn, params string[] urls)
    {
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentNullException.ThrowIfNull(urls);
        if (urls.Length == 0) throw new ArgumentException("A referral needs at least one LDAP URL.", nameof(urls));
        foreach (var url in urls) LdapUrl.Check(url);
        var entry = new Entry(DistinguishedName.Parse(dn));
        if (entry.Dn.IsRoot) throw new ArgumentException("The root cannot be a referral.", nameof(dn));
        entry.Set("objectClass", "top", "referral", "extensibleObject");
        foreach (var (type, value) in entry.Dn.Leaf!.Components) entry.Add(type, value);
        entry.Set("ref", urls);
        directory.Add(entry);
        return entry.Dn;
    }

    internal static DistinguishedName ResolveMember(this InMemoryDirectory directory, string member)
    {
        if (member.Contains('=')) return DistinguishedName.Parse(member);
        var user = directory.UserDn(member);
        var group = directory.GroupDn(member);
        return !directory.Exists(user) && directory.Exists(group) ? group : user;
    }
}

/// <summary>Fills in a user made by <c>WithUser</c> or <c>AddUser</c>: attributes, groups, account state.</summary>
public sealed class UserBuilder
{
    private readonly Entry _entry;
    private readonly DirectoryLayout _layout;

    internal UserBuilder(Entry entry, DirectoryLayout layout)
    {
        _entry = entry;
        _layout = layout;
    }

    internal List<string> Groups { get; } = [];
    internal bool IsReadOnly { get; private set; }

    /// <summary>
    /// The user may read but not write: Add, Modify, Delete and ModifyDN end with insufficientAccessRights.
    /// See <see cref="InMemoryDirectory.SetReadOnly"/>.
    /// </summary>
    public UserBuilder ReadOnly()
    {
        IsReadOnly = true;
        return this;
    }

    /// <summary>Sets <c>mail</c>.</summary>
    /// <param name="mail">The e-mail address.</param>
    /// <returns>This builder, for chaining.</returns>
    public UserBuilder Email(string mail) => Attribute("mail", mail);
    /// <summary>Sets <c>displayName</c>.</summary>
    /// <param name="name">The display name.</param>
    /// <returns>This builder, for chaining.</returns>
    public UserBuilder DisplayName(string name) => Attribute("displayName", name);
    /// <summary>Sets <c>givenName</c>.</summary>
    /// <param name="name">The first name.</param>
    /// <returns>This builder, for chaining.</returns>
    public UserBuilder FirstName(string name) => Attribute("givenName", name);
    /// <summary>Sets <c>sn</c>, replacing the default (the user name).</summary>
    /// <param name="name">The last name.</param>
    /// <returns>This builder, for chaining.</returns>
    public UserBuilder LastName(string name) => Attribute("sn", name);

    /// <summary>Sets any attribute, replacing existing values.</summary>
    public UserBuilder Attribute(string name, params string[] values)
    {
        _entry.Set(name, values);
        return this;
    }

    /// <summary>Sets any attribute to values given as bytes, replacing existing values.</summary>
    public UserBuilder AttributeBinary(string name, params byte[][] values)
    {
        _entry.SetBinary(name, values);
        return this;
    }

    /// <summary>
    /// Puts the user into groups, given by name or by DN. A group given by name is created when it is missing;
    /// one given by a DN has to exist (see <see cref="DirectorySeedExtensions.AddToGroup"/>).
    /// </summary>
    public UserBuilder MemberOf(params string[] groups)
    {
        Groups.AddRange(groups);
        return this;
    }

    /// <summary>Marks the account as disabled: the ACCOUNTDISABLE bit in AD, pwdAccountLockedTime otherwise. Binds are rejected.</summary>
    public UserBuilder Disabled()
    {
        if (_layout.IsActiveDirectory) SetControlBit(0x2);
        else _entry.Set("pwdAccountLockedTime", "000001010000Z");
        return this;
    }

    /// <summary>Locks the account out, as after too many wrong passwords. AD answers a bind with sub-code 775, even for the right password.</summary>
    public UserBuilder LockedOut()
    {
        var invariant = System.Globalization.CultureInfo.InvariantCulture;
        if (_layout.IsActiveDirectory)
        {
            // Remembered by its timestamp, so that this lockout does not run out after LockoutDuration the way
            // one from imported data does. Clearing or overwriting lockoutTime ends it.
            var now = DateTime.UtcNow.ToFileTimeUtc();
            _layout.PermanentLockouts[now] = 0;
            _entry.Set("lockoutTime", now.ToString(invariant));
        }
        else _entry.Set("pwdAccountLockedTime", DateTime.UtcNow.ToString("yyyyMMddHHmmss'Z'", invariant));
        return this;
    }

    /// <summary>"User must change password at next logon" (pwdLastSet = 0). AD answers a bind with sub-code 773. Active Directory flavour only.</summary>
    /// <exception cref="InvalidOperationException">The directory has the generic flavour.</exception>
    public UserBuilder MustChangePassword() => ActiveDirectoryOnly().Attribute("pwdLastSet", "0");

    /// <summary>The account's expiry date has passed. AD answers a bind with sub-code 701. Active Directory flavour only.</summary>
    /// <exception cref="InvalidOperationException">The directory has the generic flavour.</exception>
    public UserBuilder AccountExpired() =>
        ActiveDirectoryOnly().Attribute("accountExpires", DateTime.UtcNow.AddDays(-1).ToFileTimeUtc().ToString(System.Globalization.CultureInfo.InvariantCulture));

    /// <summary>The password is past its maximum age. AD answers a bind with sub-code 532. Active Directory flavour only.</summary>
    /// <exception cref="InvalidOperationException">The directory has the generic flavour.</exception>
    public UserBuilder PasswordExpired() => ActiveDirectoryOnly().SetControlBit(0x800000);

    // Adds one flag to userAccountControl and keeps the others, so Disabled().PasswordExpired() means both.
    private UserBuilder SetControlBit(int bit)
    {
        if (!long.TryParse(_entry.GetString("userAccountControl"), out var control)) control = 512;
        return Attribute("userAccountControl", (control | (long)bit).ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private UserBuilder ActiveDirectoryOnly([System.Runtime.CompilerServices.CallerMemberName] string? caller = null) =>
        _layout.IsActiveDirectory ? this : throw new InvalidOperationException($"{caller}() needs the Active Directory flavour: call AsActiveDirectory() first.");
}
