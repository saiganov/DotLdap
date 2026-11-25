using System.Security.Cryptography;
using System.Text;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

// The schema the server publishes. Unless SchemaChecks is on (see InMemoryDirectory.SchemaChecks.cs), nothing
// is checked against it: it is there for clients that will not work without one. ADSI (System.DirectoryServices) reads it to learn
// which attributes are numbers, dates or binary, and refuses attributes it cannot find there.
public sealed partial class InMemoryDirectory
{
    private static readonly string[] SubschemaOperational = ["attributeTypes", "objectClasses", "createTimeStamp", "modifyTimeStamp"];
    private static readonly DateTime SchemaTime = DateTime.UtcNow;

    private readonly Dictionary<string, AttributeType> _definedAttributes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _listedAttributes = new(StringComparer.OrdinalIgnoreCase); // to be listed, nothing else known
    private PublishedSchema? _schema; // rebuilt after the data has changed: attributes found in the data are part of it

    /// <summary>How often the schema has been put together, for tests that guard the paths which must not need it.</summary>
    internal int SchemaBuilds { get; private set; }

    /// <param name="Name">The RDN value of the subschema entry: its plain name and a hash of the content.</param>
    /// <param name="AttributeTypes">The attributeTypes values, as the flavour writes them.</param>
    /// <param name="ObjectClasses">The objectClasses values.</param>
    /// <param name="ByName">Every attribute type the schema lists, by name.</param>
    private sealed record PublishedSchema(
        string Name,
        string[] AttributeTypes,
        string[] ObjectClasses,
        Dictionary<string, AttributeType> ByName);

    /// <summary>
    /// Makes sure the published schema lists an attribute, even while no entry carries it: with the id and
    /// syntax the server knows for that name (in either flavour), or, when it knows nothing, the way it lists
    /// an attribute found in the data: as a multi-valued string, as binary once a value is not text. It takes
    /// nothing back: an attribute declared with a syntax keeps it. The schema already lists the well-known
    /// attributes of the directory's own flavour and every attribute found in the data.
    /// </summary>
    public InMemoryDirectory DefineAttribute(string name)
    {
        CheckAttributeName(name);
        lock (_gate)
        {
            if (_definedAttributes.ContainsKey(name) || _listedAttributes.Contains(name)) return this;
            if (SchemaCatalog.Find(name, Layout.IsActiveDirectory) is { } known) _definedAttributes[name] = known;
            else _listedAttributes.Add(name);
            _schema = null;
        }
        return this;
    }

    /// <summary>
    /// Declares an attribute for the published schema with the syntax given, when a client needs to know more
    /// than the server can tell by itself: that a custom attribute is a number or a date, say. An attribute found
    /// only in the data is published as a string, or as binary when a value is not text. For a name the server
    /// knows, this replaces the known syntax and the single-valued flag; the id stays. A number also sorts as
    /// a number. A generic directory has no word for Active Directory's own syntaxes and publishes the nearest
    /// standard one: an integer for <see cref="AttributeSyntax.LargeInteger"/>, for example.
    /// </summary>
    public InMemoryDirectory DefineAttribute(string name, AttributeSyntax syntax, bool singleValued = false)
    {
        CheckAttributeName(name);
        if (!Enum.IsDefined(syntax)) throw new ArgumentOutOfRangeException(nameof(syntax), syntax, "Unknown attribute syntax.");
        lock (_gate)
        {
            var known = SchemaCatalog.Find(name, Layout.IsActiveDirectory);
            _definedAttributes[name] = new AttributeType(name, known?.Oid ?? SchemaCatalog.PlaceholderOid(name), syntax, singleValued,
                known?.Operational ?? false, known?.UserModifiable ?? false);
            _listedAttributes.Remove(name);
            _schema = null;
        }
        return this;
    }

    private static void CheckAttributeName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (!SchemaCatalog.IsValidName(name))
            throw new ArgumentException($"'{name}' is not an attribute name: a letter, then letters, digits or hyphens, 255 characters at most.", nameof(name));
    }

    /// <summary>The syntax the published schema gives an attribute. Unknown attributes are strings.</summary>
    public AttributeSyntax SyntaxOf(string attributeName)
    {
        ArgumentNullException.ThrowIfNull(attributeName);
        lock (_gate)
            return Schema().ByName.GetValueOrDefault(FilterEvaluator.StripOptions(attributeName))?.Syntax ?? AttributeSyntax.DirectoryString;
    }

    /// <summary>
    /// Whether values of the attribute are numbers, for sorting. Only a declaration or the catalog can say so,
    /// which spares a sorted search the look at all the data that the published schema takes.
    /// </summary>
    internal bool IsNumber(string attributeName)
    {
        lock (_gate) return KnownAttribute(attributeName)?.Syntax is AttributeSyntax.Integer or AttributeSyntax.LargeInteger;
    }

    /// <summary>What a declaration or the catalog says about an attribute, without a look at the data.</summary>
    private AttributeType? KnownAttribute(string name) =>
        _definedAttributes.GetValueOrDefault(name) ?? SchemaCatalog.Find(name, Layout.IsActiveDirectory);

    /// <summary>
    /// Where the schema is published; the root DSE names it in subschemaSubentry. The name carries a hash of
    /// the schema's content and so changes with it. ADSI keeps a schema it has read on disk under this name,
    /// for all processes of the user; with a fixed name, two test servers with different custom attributes
    /// would be handed each other's schema.
    /// </summary>
    internal DistinguishedName SubschemaDn
    {
        get { lock (_gate) return SubschemaContainer.Child(Layout.IsActiveDirectory ? "CN" : "cn", Schema().Name); }
    }

    /// <summary>
    /// The subschema entry, when <paramref name="dn"/> names it: by its current name, by an earlier one a client
    /// may still hold, or by the plain name it has on a real server (CN=Aggregate,CN=Schema,CN=Configuration,...
    /// or cn=Subschema). Asked for by the plain name it answers under that name, the way a real server would;
    /// otherwise under the current one. An entry stored at that DN takes precedence.
    /// </summary>
    internal Entry? FindSubschema(DistinguishedName dn)
    {
        lock (_gate)
        {
            // The cheap checks first: this runs for every base search, and building the schema reads all the data.
            if (dn.IsRoot || dn.Leaf is not { Components.Count: 1 } leaf || !leaf.Type.Equals("cn", StringComparison.OrdinalIgnoreCase)) return null;
            if (!leaf.Value.Equals(SubschemaName, StringComparison.OrdinalIgnoreCase)
                && !leaf.Value.StartsWith(SubschemaName + "-", StringComparison.OrdinalIgnoreCase)) return null;
            if (!dn.Parent!.Equals(SubschemaContainer) || _index.ContainsKey(dn.Normalized)) return null;

            var schema = Schema();
            var name = leaf.Value.Equals(SubschemaName, StringComparison.OrdinalIgnoreCase) ? SubschemaName : schema.Name;
            var time = SchemaTime.ToString(Layout.IsActiveDirectory ? "yyyyMMddHHmmss'.0Z'" : "yyyyMMddHHmmss'Z'", System.Globalization.CultureInfo.InvariantCulture);
            return new Entry(SubschemaContainer.Child(Layout.IsActiveDirectory ? "CN" : "cn", name))
                .Set("objectClass", "top", Layout.IsActiveDirectory ? "subSchema" : "subschema")
                .Set("cn", name)
                .Set("attributeTypes", schema.AttributeTypes)
                .Set("objectClasses", schema.ObjectClasses)
                .Set("createTimeStamp", time)
                .Set("modifyTimeStamp", time);
        }
    }

    /// <summary>The schema itself is returned only when asked for by name or with "+", as on a real server.</summary>
    internal bool IsSubschemaOperational(string attributeName) =>
        SubschemaOperational.Contains(attributeName, StringComparer.OrdinalIgnoreCase) || IsOperational(attributeName);

    /// <summary>The computed attributes a search would add to an entry, for an entry that is not stored: the subschema entry.</summary>
    internal Entry WithComputedAttributes(Entry entry, IReadOnlyList<string> requested)
    {
        lock (_gate) return Materialize(entry, requested);
    }

    private string SubschemaName => Layout.IsActiveDirectory ? "Aggregate" : "Subschema";

    private DistinguishedName SubschemaContainer =>
        Layout.IsActiveDirectory ? DistinguishedName.Parse("CN=Schema,CN=Configuration," + Layout.BaseDn) : DistinguishedName.Root;

    private void Invalidate()
    {
        _groupsByMember = null;
        _schema = null;
    }

    private PublishedSchema Schema()
    {
        if (_schema is not null) return _schema;
        SchemaBuilds++;
        var ad = Layout.IsActiveDirectory;

        // Every definition gets a name and an id of its own. Names win over ids: an attribute that arrives with
        // an id already taken (Active Directory's unixHomeDirectory has the id of the standard homeDirectory)
        // keeps its name and gets a placeholder id.
        var attributes = new List<AttributeType>();
        var byName = new Dictionary<string, AttributeType>(StringComparer.OrdinalIgnoreCase);
        var usedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string UniqueId(string preferred, string name, string suffix)
        {
            if (usedIds.Add(preferred)) return preferred;
            // A placeholder made of the name. Even that may be taken: by an attribute called "x-class", say.
            var id = name + suffix;
            for (var n = 2; !usedIds.Add(id); n++) id = $"{name}-{n}{suffix}";
            return id;
        }
        // A computed attribute says itself whether it is operational, whatever a declaration or the catalog
        // holds under its name: that is what decides whether a search returns it to "*" (see IsOperational).
        var computed = new Dictionary<string, IVirtualAttributeProvider>(StringComparer.OrdinalIgnoreCase);
        foreach (var provider in _virtual) computed.TryAdd(provider.AttributeName, provider);
        void Publish(AttributeType attribute)
        {
            if (byName.ContainsKey(attribute.Name)) return;
            if (computed.TryGetValue(attribute.Name, out var provider)) attribute = attribute with { Operational = provider.IsOperational };
            attribute = attribute with { Oid = UniqueId(attribute.Oid, attribute.Name, "-oid") };
            byName.Add(attribute.Name, attribute);
            attributes.Add(attribute);
        }

        // What a test declares is published as declared.
        foreach (var attribute in SchemaCatalog.Attributes(ad))
            Publish(_definedAttributes.GetValueOrDefault(attribute.Name) ?? attribute);
        foreach (var attribute in _definedAttributes.Values.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase))
            Publish(attribute);

        // Whatever else the data holds. The result must not depend on the order of the entries: the same data
        // gives the same schema and so the same name. Of several spellings of a name the first in ordinal
        // order is published, and an unknown attribute is binary when any of its values is not text.
        var spellings = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var binary = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var classSpellings = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        static void Note(SortedDictionary<string, string> seen, string name)
        {
            if (!seen.TryGetValue(name, out var known) || string.CompareOrdinal(name, known) < 0) seen[name] = name;
        }
        foreach (var entry in _entries)
        {
            foreach (var attribute in entry.Attributes)
            {
                // Entries built in code may carry options ("photo;binary"); LDIF and the wire strip them.
                var name = FilterEvaluator.StripOptions(attribute.Name);
                if (name.Equals("objectClass", StringComparison.OrdinalIgnoreCase))
                    foreach (var value in attribute.Values)
                        if (Utf8.TryString(value, out var className) && SchemaCatalog.IsValidName(className)) Note(classSpellings, className);
                if (byName.ContainsKey(name) || !SchemaCatalog.IsValidName(name)) continue;
                Note(spellings, name);
                if (!attribute.Items.TrueForAll(v => Utf8.TryString(v, out _))) binary.Add(name);
            }
        }
        foreach (var name in computed.Keys)
            if (!byName.ContainsKey(name) && SchemaCatalog.IsValidName(name)) Note(spellings, name);
        foreach (var name in _listedAttributes)
            if (!byName.ContainsKey(name)) spellings[name] = name; // spelled the way the test declared it
        foreach (var name in spellings.Values)
            Publish(SchemaCatalog.Find(name, ad) // known from the other flavour: with its usual spelling
                ?? new AttributeType(name, SchemaCatalog.PlaceholderOid(name), binary.Contains(name) ? AttributeSyntax.OctetString : AttributeSyntax.DirectoryString, false));

        // Classes: the flavour's list, then those the data names, each with its superiors.
        var classes = new List<ObjectClassType>();
        var classNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void PublishClass(ObjectClassType type)
        {
            if (!classNames.Add(type.Name)) return;
            var superior = type.Superior;
            if (superior is not null && !classNames.Contains(superior))
            {
                // A class borrowed from the other flavour brings its superiors along; one nobody knows hangs below top.
                if (SchemaCatalog.FindClass(superior, ad) is { } parent) PublishClass(parent);
                else superior = "top";
            }
            // An attribute of the same name has the plain placeholder.
            classes.Add(type with { Oid = UniqueId(type.Oid, type.Name, "-class-oid"), Superior = superior });
        }
        foreach (var type in SchemaCatalog.Classes(ad)) PublishClass(type);
        foreach (var name in classSpellings.Values)
            PublishClass(SchemaCatalog.FindClass(name, ad) ?? new ObjectClassType(name, SchemaCatalog.PlaceholderOid(name), "top", "STRUCTURAL"));

        var attributeTypes = attributes.Select(a => Describe(a, ad)).ToArray();
        var objectClasses = classes.Select(c => Describe(c, ad)).ToArray();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', attributeTypes) + "\n\n" + string.Join('\n', objectClasses)));
        return _schema = new PublishedSchema($"{SubschemaName}-{Convert.ToHexString(hash, 0, 4)}", attributeTypes, objectClasses, byName);
    }

    // Active Directory writes its schema its own way: the syntax in quotes, the attribute lists without a space
    // after the bracket. Clients written for it (ADSI) are used to exactly that.
    private static string Describe(AttributeType attribute, bool ad)
    {
        var syntax = SchemaCatalog.SyntaxOid(attribute.Syntax, ad);
        var text = new StringBuilder($"( {attribute.Oid} NAME '{attribute.Name}' SYNTAX ").Append(ad ? $"'{syntax}'" : syntax);
        if (attribute.SingleValued) text.Append(" SINGLE-VALUE");
        if (attribute.Operational && !attribute.UserModifiable) text.Append(" NO-USER-MODIFICATION");
        if (attribute.Operational && !ad) text.Append(attribute.Name == "ref" ? " USAGE distributedOperation" : " USAGE directoryOperation"); // ref: RFC 3296 §2.2
        return text.Append(" )").ToString();
    }

    private static string Describe(ObjectClassType type, bool ad)
    {
        var text = new StringBuilder($"( {type.Oid} NAME '{type.Name}'");
        if (type.Superior is not null) text.Append(" SUP ").Append(type.Superior);
        text.Append(' ').Append(type.Kind);
        // The one thing the server does insist on.
        if (type.Superior is null) text.Append(ad ? " MUST (objectClass )" : " MUST objectClass");
        return text.Append(" )").ToString();
    }
}
