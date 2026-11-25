using System.Globalization;
using System.Numerics;
using System.Text;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

// Write operations with LDAP semantics: each returns the result code a real server would send.
// The server maps Add, Modify, Delete and ModifyDN requests onto these; nothing here knows about the wire.
public sealed partial class InMemoryDirectory
{
    private static readonly string[] ReferenceAttributes = ["member", "uniqueMember", "manager", "owner", "managedBy"];

    /// <summary>Renames or moves an entry together with everything below it.</summary>
    /// <exception cref="InvalidOperationException">The entry does not exist, the target exists, or the new parent is missing.</exception>
    /// <exception cref="ArgumentException">The target DN is empty.</exception>
    public void Move(DistinguishedName dn, DistinguishedName newDn)
    {
        if (newDn.IsRoot) throw new ArgumentException("The target DN is empty.", nameof(newDn));
        // A rename in place names no new parent, so a suffix entry (whose parent is not stored) can be renamed too.
        var newSuperior = newDn.Parent!.Equals(dn.Parent) ? null : newDn.Parent;
        var result = ApplyModifyDn(dn, newDn.Leaf!.ToString(), deleteOldRdn: true, newSuperior, allowBaseDn: true);
        if (result.Code != ResultCode.Success) throw new InvalidOperationException($"{result.Code}: {result.Message}");
    }

    internal LdapResult ApplyAdd(Entry entry)
    {
        lock (_gate)
        {
            var dn = entry.Dn;
            if (dn.IsRoot) return new LdapResult(ResultCode.NamingViolation, "The root DSE cannot be added.");
            if (_index.ContainsKey(dn.Normalized)) return new LdapResult(ResultCode.EntryAlreadyExists, $"Entry already exists: {dn}");
            // The parent must exist. The one entry that may sit at the top is the base DN itself: a DN with a
            // forgotten suffix ("uid=carol") must fail, not become a new naming context.
            if (!_index.ContainsKey(dn.Parent!.Normalized) && !dn.Equals(Layout.BaseDn)) return NoSuchObject(dn);

            // Attribute options (";binary", ";lang-en") are accepted and dropped: values are kept under the plain name.
            // The same value under two descriptions ("description;lang-en" and "description;lang-de") is legal and
            // is kept once; a value given twice under one description is not.
            var stored = new Entry(dn);
            foreach (var attribute in entry.Attributes)
            {
                var name = FilterEvaluator.StripOptions(attribute.Name);
                if (HasDuplicates(name, attribute.Values)) return DuplicateValue(attribute.Name);
                var present = Keys(name, stored.GetValues(name));
                foreach (var value in attribute.Values)
                    if (present.Add(FilterEvaluator.EqualityKey(name, value))) stored.AddBinary(name, value);
            }
            if (stored.GetValues("objectClass").Count == 0)
                return new LdapResult(ResultCode.ObjectClassViolation, "An entry needs at least one objectClass value.");
            foreach (var provider in _virtual)
            {
                if (!stored.Has(provider.AttributeName)) continue;
                // The entry's own name is harmless to send along; anything else computed (memberOf...) cannot be
                // set here, and saying "success" while dropping it would hide the mistake.
                if (!IsOwnName(provider.AttributeName)) return Computed(provider.AttributeName);
                stored.Remove(provider.AttributeName);
            }
            foreach (var (type, value) in dn.Leaf!.Components)
                if (!stored.GetValues(type).Any(v => FilterEvaluator.ValueEquals(type, v, Utf8.Bytes(value)))) stored.Add(type, value);

            // Before the server adds anything of its own: the checks are about what the client sent.
            foreach (var attribute in stored.Attributes)
            {
                if (CheckSyntax(attribute.Name, attribute.Values) is { } badValue) return badValue;
                if (CheckSingleValue(attribute.Name, attribute.Values.Count) is { } tooMany) return tooMany;
            }

            if (Layout.IsActiveDirectory)
            {
                if (stored.Has("unicodePwd"))
                {
                    if (DecodeUnicodePwd(stored.GetValues("unicodePwd")[0]) is not { } password) return BadUnicodePwd();
                    if (password.Length == 0) return EmptyUnicodePwd();
                    stored.Remove("unicodePwd");
                    stored.Set("userPassword", PasswordVerifier.Store(password));
                }
                ApplyActiveDirectoryDefaults(stored);
            }

            Store(stored);
            if (Layout.IsActiveDirectory && ActiveDirectory.NeedsDomainUsers(stored)) EnsureDomainUsers(stored);
            return LdapResult.Success;
        }
    }

    internal LdapResult ApplyDelete(DistinguishedName dn)
    {
        lock (_gate)
        {
            if (!_index.TryGetValue(dn.Normalized, out var entry)) return NoSuchObject(dn);
            // Not only direct children: an entry seeded without its parent still sits below this one.
            if (_entries.Any(e => !ReferenceEquals(e, entry) && e.Dn.IsWithin(dn)))
                return new LdapResult(ResultCode.NotAllowedOnNonLeaf, $"Entry has children: {dn}");
            _index.Remove(dn.Normalized);
            _entries.Remove(entry);
            _readOnly.Remove(dn.Normalized);
            Invalidate();
            // Active Directory keeps links consistent: a deleted object disappears from member lists.
            if (Layout.IsActiveDirectory) RewriteReferences(new Dictionary<string, DistinguishedName?> { [dn.Normalized] = null });
            return LdapResult.Success;
        }
    }

    internal LdapResult ApplyModify(DistinguishedName dn, IReadOnlyList<Modification> changes)
    {
        lock (_gate)
        {
            if (!_index.TryGetValue(dn.Normalized, out var entry)) return NoSuchObject(dn);
            var work = entry.Clone(); // all-or-nothing: the stored entry is replaced only when every change applied
            var passwordDeleted = false; // unicodePwd: a verified "delete old" that still waits for its "add new"
            var passwordSet = false;     // Active Directory flavour: this request gives the account a new password

            foreach (var change in changes)
            {
                // Keep the spelling the entry already uses: "replace TELEPHONENUMBER" must not rename telephoneNumber.
                // Options (";binary", ";lang-en") are dropped, as on Add.
                var name = StoredName(work, FilterEvaluator.StripOptions(change.Attribute.Name));
                var hasOption = change.Attribute.Name.Contains(';');
                var values = change.Attribute.Values;
                // Active Directory answers differently for linked attributes such as member.
                var adLink = Layout.IsActiveDirectory && ReferenceAttributes.Contains(name, StringComparer.OrdinalIgnoreCase);

                if (_virtual.Any(p => p.AttributeName.Equals(name, StringComparison.OrdinalIgnoreCase)) && !work.Has(name))
                    return Computed(name);

                if (Layout.IsActiveDirectory && name.Equals("unicodePwd", StringComparison.OrdinalIgnoreCase))
                {
                    if (ModifyUnicodePwd(work, change, ref passwordDeleted) is { } failure) return failure;
                    passwordSet |= change.Operation != ModificationType.Delete;
                    continue;
                }

                if (change.Operation is ModificationType.Add or ModificationType.Replace && CheckSyntax(name, values) is { } badValue)
                    return badValue;

                switch (change.Operation)
                {
                    case ModificationType.Add:
                        if (values.Count == 0) return new LdapResult(ResultCode.ProtocolError, $"add {name}: no values given.");
                        if (HasDuplicates(name, values)) return DuplicateValue(name);
                        var present = Keys(name, work.GetValues(name));
                        foreach (var value in values)
                        {
                            if (present.Add(FilterEvaluator.EqualityKey(name, value)))
                            {
                                work.AddBinary(name, value);
                                continue;
                            }
                            // With the option dropped, the value may be there from another description
                            // ("description;lang-de" after "description;lang-en"); that is not a clash.
                            if (hasOption) continue;
                            return adLink
                                ? new LdapResult(ResultCode.EntryAlreadyExists,
                                    "00000562: UpdErr: DSID-031A11E2, problem 6005 (ENTRY_EXISTS), data 0")
                                : new LdapResult(ResultCode.AttributeOrValueExists, $"{name}: value already exists.");
                        }
                        break;

                    case ModificationType.Delete:
                        if (!work.Has(name))
                        {
                            return adLink && values.Count > 0
                                ? NotAMember()
                                : new LdapResult(ResultCode.NoSuchAttribute, $"{name}: no such attribute.");
                        }
                        if (values.Count == 0)
                        {
                            work.Remove(name);
                            break;
                        }
                        var stored = Keys(name, work.GetValues(name));
                        var doomed = new HashSet<string>(StringComparer.Ordinal);
                        foreach (var value in values)
                        {
                            var key = FilterEvaluator.EqualityKey(name, value);
                            // not there, or named twice in this request
                            if (!stored.Contains(key) || !doomed.Add(key))
                                return adLink ? NotAMember() : new LdapResult(ResultCode.NoSuchAttribute, $"{name}: no such value.");
                        }
                        var remaining = work.GetValues(name).Where(v => !doomed.Contains(FilterEvaluator.EqualityKey(name, v))).ToArray();
                        work.SetBinary(name, remaining);
                        break;

                    case ModificationType.Replace:
                        if (HasDuplicates(name, values)) return DuplicateValue(name);
                        work.SetBinary(name, values.ToArray());
                        break;

                    case ModificationType.Increment:
                        if (!work.Has(name)) return new LdapResult(ResultCode.NoSuchAttribute, $"{name}: no such attribute.");
                        if (values.Count != 1 || work.GetValues(name).Count != 1
                            || !BigInteger.TryParse(Utf8.String(values[0]), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var delta)
                            || !BigInteger.TryParse(work.GetString(name), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var current))
                            return new LdapResult(ResultCode.ConstraintViolation, $"{name}: increment needs one integer value.");
                        work.Set(name, (current + delta).ToString(CultureInfo.InvariantCulture));
                        break;
                }
            }

            // Judged by what the request leaves behind, not step by step: "add the new value, delete the old" is fine.
            foreach (var touched in changes.Select(c => FilterEvaluator.StripOptions(c.Attribute.Name)).Distinct(StringComparer.OrdinalIgnoreCase))
                if (CheckSingleValue(touched, work.GetValues(touched).Count) is { } tooMany) return tooMany;

            // A Modify must not take away the value that names the entry. Entries seeded from code or LDIF need
            // not store that value at all; there is nothing to take away from those, so any change goes through.
            foreach (var (type, value) in dn.Leaf!.Components)
            {
                bool Names(Entry e) => e.GetValues(type).Any(v => FilterEvaluator.ValueEquals(type, v, Utf8.Bytes(value)));
                if (Names(entry) && !Names(work))
                    return new LdapResult(ResultCode.NotAllowedOnRdn, $"{type}={value} names the entry; rename it with ModifyDN instead.");
            }
            // The same goes for objectClass: only taking the last value away is an error.
            if (entry.Has("objectClass") && !work.Has("objectClass"))
                return new LdapResult(ResultCode.ObjectClassViolation, "An entry needs at least one objectClass value.");
            if (Layout.IsActiveDirectory)
            {
                bool Changes(Modification c, string attribute) => c.Operation != ModificationType.Delete
                    && FilterEvaluator.StripOptions(c.Attribute.Name).Equals(attribute, StringComparison.OrdinalIgnoreCase);
                // A password written through userPassword counts as set, like one written through unicodePwd,
                // but only if there still is one: "replace userPassword" without values removes it.
                passwordSet |= work.Has("userPassword") && changes.Any(c => Changes(c, "userPassword"));
                // A new password ends "must change at next logon", unless this very request asks for it
                // (reset and "pwdLastSet: 0" together, in either order).
                var mustChange = changes.Any(c => Changes(c, "pwdLastSet") && c.Attribute.Values is [var v] && Utf8.String(v) == "0");
                if (passwordSet) ActiveDirectory.PasswordWasSet(work, mustChange);
                ActiveDirectory.ResolvePwdLastSet(work);
            }
            if (passwordDeleted) return BadUnicodePwd("deleting the old password must be followed by adding the new one");

            ReplaceStored(entry, work);
            return LdapResult.Success;
        }
    }

    internal LdapResult ApplyModifyDn(DistinguishedName dn, string newRdnText, bool deleteOldRdn, DistinguishedName? newSuperior,
        bool allowBaseDn = false)
    {
        lock (_gate)
        {
            if (!_index.TryGetValue(dn.Normalized, out var entry)) return NoSuchObject(dn);
            dn = entry.Dn; // from here on the spelling the directory has, not the one the client typed
            var isBaseDn = dn.Equals(Layout.BaseDn);
            // Seed code may rename the base DN (see Move); a client may not, as on a real server.
            if (isBaseDn && !allowBaseDn)
                return new LdapResult(ResultCode.UnwillingToPerform, "The base DN of the directory cannot be renamed.");
            if (!DistinguishedName.TryParse(newRdnText, out var parsed) || parsed.Rdns.Count != 1)
                return new LdapResult(ResultCode.InvalidDnSyntax, $"Invalid new RDN '{newRdnText}'.");
            var newRdn = parsed.Leaf!;

            var parent = dn.Parent!;
            if (newSuperior is not null)
            {
                if (!_index.TryGetValue(newSuperior.Normalized, out var superior)) return NoSuchObject(newSuperior);
                if (newSuperior.IsWithin(dn)) return new LdapResult(ResultCode.UnwillingToPerform, "An entry cannot be moved below itself.");
                parent = superior.Dn;
            }
            var newDn = DistinguishedName.Join(newRdn, parent);
            if (!newDn.Equals(dn) && _index.ContainsKey(newDn.Normalized))
                return new LdapResult(ResultCode.EntryAlreadyExists, $"Entry already exists: {newDn}");

            // A rename writes the new name into the entry. Seed code (Move) is not held to the schema.
            if (!allowBaseDn)
            {
                foreach (var (type, value) in newRdn.Components)
                {
                    if (CheckSyntax(type, [Utf8.Bytes(value)]) is { } badValue) return badValue;
                    var kept = entry.GetValues(type).Where(v => !FilterEvaluator.ValueEquals(type, v, Utf8.Bytes(value))
                        && !(deleteOldRdn && dn.Leaf!.Components.Any(old => old.Type.Equals(type, StringComparison.OrdinalIgnoreCase)
                            && FilterEvaluator.ValueEquals(type, v, Utf8.Bytes(old.Value)))));
                    if (CheckSingleValue(type, kept.Count() + 1) is { } tooMany) return tooMany;
                }
            }

            // Every entry of the subtree gets a new DN; none of them may land on an entry that stays where it is.
            // (An orphan can sit below the target path even when the target itself is free.)
            foreach (var old in _entries)
            {
                if (!old.Dn.IsWithin(dn)) continue;
                var target = old.Dn.Rebase(dn, newDn);
                if (_index.TryGetValue(target.Normalized, out var occupant) && !occupant.Dn.IsWithin(dn))
                    return new LdapResult(ResultCode.EntryAlreadyExists, $"Entry already exists: {target}");
            }

            var moved = new Dictionary<string, DistinguishedName?>();
            var renamedEntries = new List<Entry>();
            for (var i = 0; i < _entries.Count; i++)
            {
                var old = _entries[i];
                if (!old.Dn.IsWithin(dn)) continue;
                var renamed = new Entry(old.Dn.Rebase(dn, newDn));
                foreach (var attribute in old.Attributes)
                {
                    // A stored copy of the entry's own name (AD exports carry distinguishedName) would keep saying
                    // the old DN; without it the name is computed again.
                    if (IsOwnName(attribute.Name)) continue;
                    renamed.AddBinary(attribute.Name, attribute.Values.ToArray());
                }

                if (ReferenceEquals(old, entry))
                {
                    if (deleteOldRdn)
                    {
                        foreach (var (type, value) in dn.Leaf!.Components)
                        {
                            var kept = renamed.GetValues(type).Where(v => !FilterEvaluator.ValueEquals(type, v, Utf8.Bytes(value))).ToArray();
                            renamed.SetBinary(StoredName(renamed, type), kept);
                        }
                    }
                    // "UID=alicia" still goes into the attribute the entry calls "uid", even when the old value just left it.
                    foreach (var (type, value) in newRdn.Components)
                        if (!renamed.GetValues(type).Any(v => FilterEvaluator.ValueEquals(type, v, Utf8.Bytes(value)))) renamed.Add(StoredName(old, type), value);
                    // In Active Directory "name" is always the RDN value.
                    if (Layout.IsActiveDirectory && renamed.Has("name")) renamed.Set(StoredName(renamed, "name"), newRdn.Value);
                }
                // objectCategory points into the schema below the base DN, so it follows a renamed base DN.
                if (isBaseDn && Layout.IsActiveDirectory && renamed.GetString("objectCategory") is { } category
                    && DistinguishedName.TryParse(category, out var categoryDn) && categoryDn.IsWithin(dn))
                    renamed.Set(StoredName(renamed, "objectCategory"), categoryDn.Rebase(dn, newDn).ToString());

                moved[old.Dn.Normalized] = renamed.Dn;
                _index.Remove(old.Dn.Normalized);
                _entries[i] = renamed;
                renamedEntries.Add(renamed);
            }
            // Index the new DNs only after all old ones are gone: within the subtree an old and a new DN can coincide.
            foreach (var renamed in renamedEntries) _index[renamed.Dn.Normalized] = renamed;
            // A read-only user stays read-only under the new name. Same order as above: all old marks go first.
            var marks = moved.Where(m => _readOnly.Remove(m.Key)).Select(m => m.Value!.Normalized).ToArray();
            _readOnly.UnionWith(marks);
            if (isBaseDn) Layout.RenameBase(newDn); // users and groups added later go below the new name
            Invalidate();
            // Active Directory keeps links consistent: member lists follow a renamed object.
            if (Layout.IsActiveDirectory) RewriteReferences(moved);
            return LdapResult.Success;
        }
    }

    /// <summary>Sets a new password the way the Password Modify extended operation does.</summary>
    internal LdapResult ApplySetPassword(DistinguishedName dn, string? oldPassword, string newPassword)
    {
        lock (_gate)
        {
            if (!_index.TryGetValue(dn.Normalized, out var entry)) return NoSuchObject(dn);
            if (oldPassword is not null && !PasswordVerifier.Verify(entry.GetValues("userPassword"), oldPassword))
                return new LdapResult(ResultCode.InvalidCredentials, "The old password is wrong.");
            // An empty password could never be used: a bind with an empty password is an unauthenticated bind.
            if (newPassword.Length == 0) return new LdapResult(ResultCode.ConstraintViolation, "The new password is empty.");
            entry.Set("userPassword", PasswordVerifier.Store(newPassword));
            if (Layout.IsActiveDirectory) ActiveDirectory.PasswordWasSet(entry);
            return LdapResult.Success;
        }
    }

    // ---- helpers ---------------------------------------------------------------------------------------------

    private LdapResult NoSuchObject(DistinguishedName dn)
    {
        var matched = "";
        for (var current = dn.Parent; current is { IsRoot: false }; current = current.Parent)
        {
            if (!_index.ContainsKey(current.Normalized)) continue;
            matched = current.ToString();
            break;
        }
        return new LdapResult(ResultCode.NoSuchObject, $"No such object: {dn}", matched);
    }

    /// <summary>The spelling the entry already uses for an attribute, or the given one when the entry does not have it.</summary>
    private static string StoredName(Entry entry, string name) =>
        entry.Attributes.FirstOrDefault(a => a.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Name ?? name;

    private static LdapResult Computed(string attribute) =>
        new(ResultCode.UnwillingToPerform, $"{attribute} is computed by the server and cannot be set.");

    private static LdapResult DuplicateValue(string attribute) =>
        new(ResultCode.AttributeOrValueExists, $"{attribute}: value provided more than once.");

    private static LdapResult NotAMember() =>
        new(ResultCode.UnwillingToPerform, "00000561: SvcErr: DSID-031A120C, problem 5003 (WILL_NOT_PERFORM), data 0");

    // Large groups arrive with thousands of values, so equal values are found through a set of keys, not by
    // comparing every pair.
    private static HashSet<string> Keys(string attribute, IReadOnlyList<byte[]> values)
    {
        var keys = new HashSet<string>(values.Count, StringComparer.Ordinal);
        foreach (var value in values) keys.Add(FilterEvaluator.EqualityKey(attribute, value));
        return keys;
    }

    private static bool HasDuplicates(string attribute, IReadOnlyList<byte[]> values) =>
        values.Count > 1 && Keys(attribute, values).Count != values.Count;

    /// <summary>distinguishedName or entryDN, where the directory computes it: the entry's own name as an attribute.</summary>
    private bool IsOwnName(string attribute) =>
        (attribute.Equals("distinguishedName", StringComparison.OrdinalIgnoreCase) || attribute.Equals("entryDN", StringComparison.OrdinalIgnoreCase))
        && _virtual.Any(p => p.AttributeName.Equals(attribute, StringComparison.OrdinalIgnoreCase));

    private void ReplaceStored(Entry old, Entry updated)
    {
        _index[old.Dn.Normalized] = updated;
        _entries[_entries.IndexOf(old)] = updated;
        Invalidate();
    }

    /// <summary>Rewrites DN-valued link attributes: a null target drops the value, anything else replaces it.</summary>
    private void RewriteReferences(Dictionary<string, DistinguishedName?> map)
    {
        foreach (var holder in _entries)
        {
            foreach (var attribute in ReferenceAttributes)
            {
                var values = holder.GetValues(attribute);
                if (values.Count == 0) continue;
                var changed = false;
                var rewritten = new List<byte[]>(values.Count);
                foreach (var value in values)
                {
                    if (DistinguishedName.TryParse(Utf8.String(value), out var target) && map.TryGetValue(target.Normalized, out var replacement))
                    {
                        changed = true;
                        if (replacement is not null) rewritten.Add(Utf8.Bytes(replacement.ToString()));
                    }
                    else
                    {
                        rewritten.Add(value);
                    }
                }
                if (changed) holder.SetBinary(attribute, rewritten.ToArray());
            }
        }
        Invalidate();
    }

    // Active Directory takes passwords through unicodePwd: the new password in double quotes, encoded as UTF-16LE.
    // It knows two forms. A single "replace" is an administrative reset. "delete old value" followed by "add new
    // value" is a user changing their own password; either half on its own is refused.
    private static LdapResult? ModifyUnicodePwd(Entry work, Modification change, ref bool oldPasswordDeleted)
    {
        var values = change.Attribute.Values;
        if (values.Count != 1 || DecodeUnicodePwd(values[0]) is not { } password) return BadUnicodePwd();
        switch (change.Operation)
        {
            case ModificationType.Delete:
                if (oldPasswordDeleted) return BadUnicodePwd("the old password was deleted twice");
                if (!PasswordVerifier.Verify(work.GetValues("userPassword"), password))
                {
                    return new LdapResult(ResultCode.ConstraintViolation,
                        "00000056: AtrErr: DSID-03191083, #1:\n\t0: 00000056: DSID-03191083, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 9005a (unicodePwd)");
                }
                oldPasswordDeleted = true;
                return null;
            case ModificationType.Add:
                if (!oldPasswordDeleted) return BadUnicodePwd("adding a password needs the old one deleted first; use replace to reset");
                oldPasswordDeleted = false;
                goto case ModificationType.Replace;
            case ModificationType.Replace:
                if (password.Length == 0) return EmptyUnicodePwd();
                work.Set("userPassword", PasswordVerifier.Store(password));
                return null;
            default:
                return BadUnicodePwd();
        }
    }

    private static string? DecodeUnicodePwd(byte[] value)
    {
        if (value.Length < 4 || value.Length % 2 != 0) return null;
        var text = Encoding.Unicode.GetString(value);
        return text.Length >= 2 && text[0] == '"' && text[^1] == '"' ? text[1..^1] : null;
    }

    internal static LdapResult BadUnicodePwd(string reason = "unicodePwd must be a quoted UTF-16LE string") => new(ResultCode.UnwillingToPerform,
        $"0000001F: SvcErr: DSID-031A12D2, problem 5003 (WILL_NOT_PERFORM), data 0 ({reason})");

    // What Active Directory answers when a password does not meet the password policy.
    private static LdapResult EmptyUnicodePwd() => new(ResultCode.UnwillingToPerform,
        "0000052D: SvcErr: DSID-031A12D2, problem 5003 (WILL_NOT_PERFORM), data 0 (the password is empty)");
}
