using System.Globalization;
using System.Text.Json;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>
/// Test data as JSON: users and groups described the way the fluent helpers take them (so the same file works
/// for both flavours), and raw entries.
/// <code>
/// {
///   "users": [
///     { "name": "alice", "password": "s3cret", "email": "alice@example.com", "groups": ["admins"],
///       "attributes": { "title": "Engineer", "telephoneNumber": ["+1 555 0100", "+1 555 0101"] } },
///     { "name": "bob", "password": "hunter2", "disabled": true }
///   ],
///   "groups": [ { "name": "staff", "members": ["alice", "admins"] } ],
///   "entries": [
///     { "dn": "ou=printers,dc=example,dc=com",
///       "attributes": { "objectClass": ["top", "organizationalUnit"], "ou": "printers" } }
///   ]
/// }
/// </code>
/// Users, groups and entries are created first, each list in its order; memberships are filled in afterwards.
/// So a group may name a member that the file defines further down, and a group a user names may also be listed
/// under "groups" or "entries". A value is a string, a number (stored as written), a boolean (TRUE or FALSE)
/// or <c>{ "base64": "..." }</c> for bytes; an attribute takes one value or a list. Comments and trailing commas
/// are allowed, and property names are read whatever their case. A property the format does not know is an
/// error, so a typo does not go unnoticed.
/// </summary>
internal static class JsonSeed
{
    private static readonly JsonDocumentOptions Options = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    public static int Load(InMemoryDirectory directory, string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json.TrimStart('\uFEFF'), Options); // a byte order mark that came along with a file's text
        }
        catch (Exception e) when (e is JsonException or ArgumentException)
        {
            throw new FormatException("Invalid JSON: " + e.Message, e);
        }
        using (document)
        {
            // Read everything before anything is added: a mistake in the file leaves the directory as it was.
            // Everything is created before any membership is filled in, so the order within the file is free.
            var create = new List<Action>();
            var link = new List<Action>();
            try
            {
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object) throw Bad("$", "an object with \"users\", \"groups\" and \"entries\" is expected");
                var known = Properties(root, "$", "users", "groups", "entries");
                // Whatever would land on the same DN is given twice: two users of one name, a user and a group of
                // one name where both live in one container (Active Directory), an entry that is also a user.
                var dns = new HashSet<string>(StringComparer.Ordinal);
                Each(known, "users", "$.users", (user, path) => User(directory, user, path, dns, create, link));
                Each(known, "groups", "$.groups", (group, path) => Group(directory, group, path, dns, create, link));
                Each(known, "entries", "$.entries", (entry, path) => RawEntry(directory, entry, path, dns, create));
            }
            catch (InvalidOperationException e)
            {
                // System.Text.Json on text it cannot turn into a string: half of a surrogate pair.
                throw new FormatException("Invalid JSON: " + e.Message, e);
            }
            foreach (var step in create) step();
            foreach (var step in link) step();
            return create.Count;
        }
    }

    private static readonly string[] ActiveDirectoryOnly = ["mustChangePassword", "accountExpired", "passwordExpired"];

    private static void User(InMemoryDirectory directory, JsonElement user, string path, HashSet<string> dns, List<Action> create, List<Action> link)
    {
        var p = Properties(user, path, "name", "password", "email", "displayName", "firstName", "lastName", "groups", "attributes",
            "disabled", "lockedOut", "mustChangePassword", "accountExpired", "passwordExpired", "readOnly");
        var name = Required(p, "name", path);
        Claim(dns, directory.UserDn(Name(name, $"{path}.name")), $"{path}.name");
        var password = Required(p, "password", path, allowEmpty: true); // as AddUser takes it
        var configure = new List<Action<UserBuilder>>();
        void Text(string property, Func<UserBuilder, string, UserBuilder> set)
        {
            if (!p.TryGetValue(property, out var value)) return;
            var text = NotEmpty(String(value, $"{path}.{property}"), $"{path}.{property}");
            configure.Add(u => set(u, text));
        }
        void Flag(string property, Func<UserBuilder, UserBuilder> set)
        {
            if (!p.TryGetValue(property, out var value)) return;
            if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw Bad($"{path}.{property}", "true or false is expected");
            if (!value.GetBoolean()) return;
            if (!directory.Layout.IsActiveDirectory && ActiveDirectoryOnly.Contains(property, StringComparer.OrdinalIgnoreCase))
                throw Bad($"{path}.{property}", "this needs the Active Directory flavour");
            configure.Add(u => set(u));
        }
        // In this order: the named properties, then "attributes" (which may replace what those and the helper
        // itself have set), then the flags.
        Text("email", (u, v) => u.Email(v));
        Text("displayName", (u, v) => u.DisplayName(v));
        Text("firstName", (u, v) => u.FirstName(v));
        Text("lastName", (u, v) => u.LastName(v));
        if (p.TryGetValue("attributes", out var attributes))
            foreach (var (attribute, values) in Attributes(attributes, $"{path}.attributes"))
                configure.Add(u => u.AttributeBinary(attribute, values));
        Flag("disabled", u => u.Disabled());
        Flag("lockedOut", u => u.LockedOut());
        Flag("mustChangePassword", u => u.MustChangePassword());
        Flag("accountExpired", u => u.AccountExpired());
        Flag("passwordExpired", u => u.PasswordExpired());
        Flag("readOnly", u => u.ReadOnly());
        var groups = p.TryGetValue("groups", out var list) ? Names(list, $"{path}.groups") : [];

        DistinguishedName? dn = null;
        create.Add(() => Run(path, () => dn = directory.AddUser(name, password, u => configure.ForEach(c => c(u)))));
        for (var i = 0; i < groups.Length; i++)
        {
            var (group, at) = (groups[i], $"{path}.groups[{i}]");
            link.Add(() => Run(at, () => directory.AddToGroup(group, dn!)));
        }
    }

    private static void Group(InMemoryDirectory directory, JsonElement group, string path, HashSet<string> dns, List<Action> create, List<Action> link)
    {
        var p = Properties(group, path, "name", "members");
        var name = Required(p, "name", path);
        Claim(dns, directory.GroupDn(Name(name, $"{path}.name")), $"{path}.name");
        var members = p.TryGetValue("members", out var list) ? Names(list, $"{path}.members") : [];

        DistinguishedName? dn = null;
        create.Add(() => Run(path, () => dn = directory.AddGroup(name)));
        for (var i = 0; i < members.Length; i++)
        {
            var (member, at) = (members[i], $"{path}.members[{i}]");
            link.Add(() => Run(at, () =>
            {
                // A DN is taken as it is, as with AddGroup. A name must be somebody: a typo would otherwise
                // become a member that does not exist.
                var resolved = directory.ResolveMember(member);
                if (!member.Contains('=') && !directory.Exists(resolved))
                    throw new InvalidOperationException($"There is no user or group named '{member}'.");
                directory.AddMember(dn!, resolved);
            }));
        }
    }

    private static void RawEntry(InMemoryDirectory directory, JsonElement entry, string path, HashSet<string> dns, List<Action> create)
    {
        var p = Properties(entry, path, "dn", "attributes");
        var text = Required(p, "dn", path);
        if (!DistinguishedName.TryParse(text, out var dn) || dn.IsRoot) throw Bad($"{path}.dn", $"'{text}' is not a DN");
        Claim(dns, dn, $"{path}.dn");
        var result = new Entry(dn);
        if (p.TryGetValue("attributes", out var attributes))
            foreach (var (attribute, values) in Attributes(attributes, $"{path}.attributes"))
                result.AddBinary(attribute, values);
        create.Add(() => Run(path, () => directory.Add(result)));
    }

    private static void Claim(HashSet<string> dns, DistinguishedName dn, string path)
    {
        if (!dns.Add(dn.Normalized)) throw Bad(path, $"'{dn}' is given twice in this file");
    }

    /// <summary>Where a user or group is referred to, text with "=" is read as a DN; a name must not look like one.</summary>
    private static string Name(string name, string path) =>
        name.Contains('=') ? throw Bad(path, "a name cannot contain '='; an entry with such a name goes under \"entries\"") : name;

    /// <summary>What the directory refuses (an entry that exists already, a member nobody is) is reported with its place in the file.</summary>
    private static void Run(string path, Action add)
    {
        try
        {
            add();
        }
        catch (Exception e) when (e is InvalidOperationException or ArgumentException or FormatException)
        {
            throw new FormatException($"JSON data, {path}: {e.Message}", e);
        }
    }

    private static List<(string Name, byte[][] Values)> Attributes(JsonElement attributes, string path)
    {
        if (attributes.ValueKind != JsonValueKind.Object) throw Bad(path, "an object of attribute names and values is expected");
        var result = new List<(string Name, byte[][] Values)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var attribute in attributes.EnumerateObject())
        {
            var at = $"{path}.{attribute.Name}";
            if (!seen.Add(attribute.Name)) throw Bad(at, "the attribute is given twice");
            // As in LDIF: options (";binary", ";lang-en") are dropped and the values kept under the plain name,
            // those of "description;lang-en" and "description;lang-de" together.
            var name = FilterEvaluator.StripOptions(attribute.Name);
            if (name.Length == 0 || !name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')) throw Bad(at, "this is not an attribute name");
            var values = attribute.Value.ValueKind == JsonValueKind.Array
                ? attribute.Value.EnumerateArray().Select((v, i) => Value(v, $"{at}[{i}]")).ToArray()
                : [Value(attribute.Value, at)];
            var index = result.FindIndex(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (index < 0) result.Add((name, values));
            else result[index] = (result[index].Name, [.. result[index].Values, .. values]);
        }
        return result;
    }

    private static byte[] Value(JsonElement value, string path)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                return Utf8.Bytes(value.GetString()!);
            case JsonValueKind.Number:
                return Utf8.Bytes(value.GetRawText()); // as written: 512 stays "512"
            case JsonValueKind.True:
                return Utf8.Bytes("TRUE");
            case JsonValueKind.False:
                return Utf8.Bytes("FALSE");
            case JsonValueKind.Object:
                var p = Properties(value, path, "base64");
                var text = Required(p, "base64", path, allowEmpty: true);
                try
                {
                    return Convert.FromBase64String(text);
                }
                catch (FormatException)
                {
                    throw Bad($"{path}.base64", "the value is not base64");
                }
            default:
                throw Bad(path, "a string, a number, true, false or { \"base64\": \"...\" } is expected");
        }
    }

    /// <summary>Users and groups by name or by DN; what has a "=" must be a DN.</summary>
    private static string[] Names(JsonElement list, string path)
    {
        if (list.ValueKind != JsonValueKind.Array) throw Bad(path, "a list of names is expected");
        return list.EnumerateArray().Select((item, i) =>
        {
            var at = $"{path}[{i}]";
            var name = NotEmpty(String(item, at), at);
            if (name.Contains('=') && (!DistinguishedName.TryParse(name, out var dn) || dn.IsRoot)) throw Bad(at, $"'{name}' is not a DN");
            return name;
        }).ToArray();
    }

    private static string NotEmpty(string text, string path) => text.Length > 0 ? text : throw Bad(path, "the value is empty");

    private static string String(JsonElement value, string path) =>
        value.ValueKind == JsonValueKind.String ? value.GetString()! : throw Bad(path, "a string is expected");

    private static string Required(Dictionary<string, JsonElement> properties, string name, string path, bool allowEmpty = false)
    {
        if (!properties.TryGetValue(name, out var value)) throw Bad(path, $"\"{name}\" is missing");
        var text = String(value, $"{path}.{name}");
        return text.Length > 0 || allowEmpty ? text : throw Bad($"{path}.{name}", "the value is empty");
    }

    private static void Each(Dictionary<string, JsonElement> properties, string name, string path, Action<JsonElement, string> read)
    {
        if (!properties.TryGetValue(name, out var list)) return;
        if (list.ValueKind != JsonValueKind.Array) throw Bad(path, "a list is expected");
        var index = 0;
        foreach (var item in list.EnumerateArray()) read(item, string.Create(CultureInfo.InvariantCulture, $"{path}[{index++}]"));
    }

    /// <summary>The properties of an object by name, whatever their case; one the format does not know, or one given twice, is an error.</summary>
    private static Dictionary<string, JsonElement> Properties(JsonElement element, string path, params string[] known)
    {
        if (element.ValueKind != JsonValueKind.Object) throw Bad(path, "an object is expected");
        var result = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in element.EnumerateObject())
        {
            if (!known.Contains(property.Name, StringComparer.OrdinalIgnoreCase))
                throw Bad($"{path}.{property.Name}", "unknown property; known here: " + string.Join(", ", known));
            if (!result.TryAdd(property.Name, property.Value)) throw Bad($"{path}.{property.Name}", "the property is given twice");
        }
        return result;
    }

    private static FormatException Bad(string path, string message) => new($"JSON data, {path}: {message}.");
}
