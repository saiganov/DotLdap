using System.Text;

namespace DotLdap.Testing.Protocol;

/// <summary>LDAP result codes (RFC 4511, appendix A): the ones this server sends, and the ones a test may want to send from an interceptor.</summary>
public enum ResultCode
{
    /// <summary>The operation succeeded.</summary>
    Success = 0,
    /// <summary>The server could not do it in the order asked, for example a SASL bind it did not expect.</summary>
    OperationsError = 1,
    /// <summary>The request was not well-formed LDAP.</summary>
    ProtocolError = 2,
    /// <summary>The time limit of a search ran out.</summary>
    TimeLimitExceeded = 3,
    /// <summary>A search found more entries than its size limit allows; the entries up to the limit were sent.</summary>
    SizeLimitExceeded = 4,
    /// <summary>A compare: the entry does not have the value.</summary>
    CompareFalse = 5,
    /// <summary>A compare: the entry has the value.</summary>
    CompareTrue = 6,
    /// <summary>The server does not speak the SASL mechanism asked for.</summary>
    AuthMethodNotSupported = 7,
    /// <summary>The operation needs a bound connection (an anonymous write, for example).</summary>
    StrongerAuthRequired = 8,
    /// <summary>Another server holds the name; see <see cref="LdapResult.Referrals"/>.</summary>
    Referral = 10,
    /// <summary>A limit of the server, not of the request, was reached.</summary>
    AdminLimitExceeded = 11,
    /// <summary>A control marked critical is one the server does not know.</summary>
    UnavailableCriticalExtension = 12,
    /// <summary>The operation needs an encrypted connection.</summary>
    ConfidentialityRequired = 13,
    /// <summary>A SASL bind goes on: the client is to send the next step.</summary>
    SaslBindInProgress = 14,
    /// <summary>The entry does not have the attribute or value to delete or compare.</summary>
    NoSuchAttribute = 16,
    /// <summary>The schema does not know the attribute.</summary>
    UndefinedAttributeType = 17,
    /// <summary>A value breaks a rule of the attribute, such as single-valued.</summary>
    ConstraintViolation = 19,
    /// <summary>The value to add is there already.</summary>
    AttributeOrValueExists = 20,
    /// <summary>A value does not have the syntax of its attribute.</summary>
    InvalidAttributeSyntax = 21,
    /// <summary>No entry has the name; <see cref="LdapResult.MatchedDn"/> says how far the name exists.</summary>
    NoSuchObject = 32,
    /// <summary>The text is no distinguished name.</summary>
    InvalidDnSyntax = 34,
    /// <summary>This kind of bind is not allowed, for example an unauthenticated one (a name without a password).</summary>
    InappropriateAuthentication = 48,
    /// <summary>The name or the password is wrong, or the account may not log in.</summary>
    InvalidCredentials = 49,
    /// <summary>The bound user may not do this.</summary>
    InsufficientAccessRights = 50,
    /// <summary>The server is too busy; try again.</summary>
    Busy = 51,
    /// <summary>The server is shutting down or cannot serve now.</summary>
    Unavailable = 52,
    /// <summary>The server will not do this, whatever the reason; the message says which.</summary>
    UnwillingToPerform = 53,
    /// <summary>The name breaks a naming rule, for example an RDN attribute the entry does not have.</summary>
    NamingViolation = 64,
    /// <summary>The entry breaks a rule of its object classes.</summary>
    ObjectClassViolation = 65,
    /// <summary>The entry has children, so it cannot be deleted or renamed.</summary>
    NotAllowedOnNonLeaf = 66,
    /// <summary>The change would remove a value the entry's name is made of.</summary>
    NotAllowedOnRdn = 67,
    /// <summary>An entry has the name already.</summary>
    EntryAlreadyExists = 68,
    /// <summary>The operation would span servers, such as a rename onto a name another server holds.</summary>
    AffectsMultipleDsas = 71,
    /// <summary>Anything else.</summary>
    Other = 80,
}

/// <summary>How far below its base a search looks.</summary>
public enum SearchScope
{
    /// <summary>The base entry only.</summary>
    BaseObject = 0,
    /// <summary>The children of the base entry, not the base itself.</summary>
    SingleLevel = 1,
    /// <summary>The base entry and everything below it.</summary>
    WholeSubtree = 2,
}

/// <summary>The outcome of an operation, as the server sends it (LDAPResult in RFC 4511).</summary>
/// <param name="Code">The result code.</param>
/// <param name="Message">The diagnostic message; Active Directory puts its error and data codes here.</param>
/// <param name="MatchedDn">For a name that does not exist, the part of it that does; for a referral, the referral entry.</param>
/// <param name="Referrals">
/// LDAP URLs of the servers to ask instead; they go with <see cref="ResultCode.Referral"/>. An interceptor can
/// send a client away with <c>new LdapResult(ResultCode.Referral, Referrals: ["ldap://other.example.com/dc=example,dc=com"])</c>.
/// </param>
public sealed record LdapResult(ResultCode Code, string Message = "", string MatchedDn = "", IReadOnlyList<string>? Referrals = null)
{
    /// <summary>Success, with no message.</summary>
    public static readonly LdapResult Success = new(ResultCode.Success);

    /// <summary>Two results are equal when they say the same, URL for URL.</summary>
    public bool Equals(LdapResult? other) =>
        other is not null && Code == other.Code && Message == other.Message && MatchedDn == other.MatchedDn
        && (Referrals ?? []).SequenceEqual(other.Referrals ?? []);

    /// <summary>A hash that agrees with <see cref="Equals(LdapResult?)"/>.</summary>
    public override int GetHashCode() => HashCode.Combine(Code, Message, MatchedDn, Referrals?.Count ?? 0);

    private bool PrintMembers(StringBuilder builder)
    {
        builder.Append("Code = ").Append(Code).Append(", Message = ").Append(Message).Append(", MatchedDn = ").Append(MatchedDn);
        if (Referrals is { Count: > 0 }) builder.Append(", Referrals = [").AppendJoin(", ", Referrals).Append(']');
        return true;
    }
}

/// <summary>A control sent with a request (RFC 4511 §4.1.11).</summary>
/// <param name="Oid">What the control is, by its object identifier.</param>
/// <param name="Critical">True when the client wants the operation refused if the server does not know the control.</param>
/// <param name="Value">The control's own data, BER-encoded, or null.</param>
internal sealed record LdapControl(string Oid, bool Critical = false, byte[]? Value = null);

/// <summary>A decoded LDAPMessage envelope sent by a client.</summary>
/// <param name="MessageId">The number the client gave the request; its answers carry the same.</param>
/// <param name="Request">The operation.</param>
/// <param name="Controls">The controls sent with it.</param>
internal sealed record LdapMessage(int MessageId, LdapRequest Request, IReadOnlyList<LdapControl> Controls);

/// <summary>An LDAP operation a client sent: one of the records in this namespace.</summary>
/// <remarks>
/// Record equality compares lists, arrays and byte values by reference, so two requests with the same content are
/// usually not equal. Assert on the properties instead, such as <c>search.Filter.ToString()</c> or <c>bind.Name</c>.
/// </remarks>
public abstract record LdapRequest
{
    /// <summary>Tag number of the response PDU ([APPLICATION n]), or null when the request has no response.</summary>
    internal abstract int? ResponseTag { get; }
}

/// <summary>
/// A bind. <see cref="SaslMechanism"/> is null for a simple bind; a SASL bind may carry
/// <see cref="SaslCredentials"/>, whose meaning is the mechanism's. Microsoft's pre-SASL NTLM bind ("Sicily"),
/// which Windows clients fall back to, is reported as the mechanism <see cref="Sicily"/>.
/// </summary>
public sealed record BindRequest : LdapRequest
{
    /// <summary>An empty BindRequest, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public BindRequest()
    {
    }

    internal BindRequest(int version, string name, string? password, string? saslMechanism, byte[]? saslCredentials = null)
    {
        Version = version;
        Name = name;
        Password = password;
        SaslMechanism = saslMechanism;
        SaslCredentials = saslCredentials;
    }

    /// <summary>The protocol version; 3.</summary>
    public int Version { get; init; } = 3;

    /// <summary>Who binds: a DN, or in Active Directory also a UPN or <c>DOMAIN\user</c>. Empty for anonymous.</summary>
    public string Name { get; init; } = "";

    /// <summary>The password of a simple bind; null for SASL.</summary>
    public string? Password { get; init; }

    /// <summary>The SASL mechanism, or null for a simple bind.</summary>
    public string? SaslMechanism { get; init; }

    /// <summary>What the SASL mechanism sends, if anything.</summary>
    public byte[]? SaslCredentials { get; init; }

    /// <summary>The mechanism name given to Microsoft's NTLM bind outside SASL, which this server refuses.</summary>
    public const string Sicily = "NTLM (Sicily)";

    /// <summary>
    /// The one SASL mechanism the server speaks, in the generic flavour (RFC 4616): a name and a password, as
    /// in a simple bind.
    /// </summary>
    public const string Plain = "PLAIN";

    /// <summary>True for a simple bind (a name and a password), false for SASL.</summary>
    public bool IsSimple => SaslMechanism is null;
    internal override int? ResponseTag => 1;
    /// <summary>One line for the request log: who binds and how, never the password.</summary>
    public override string ToString() => IsSimple
        ? $"Bind {(Name.Length == 0 ? "(anonymous)" : OnOneLine(Name))}"
        : $"Bind {OnOneLine(SaslName() ?? (Name.Length == 0 ? "(no name)" : Name))} SASL {OnOneLine(SaslMechanism!)}";

    /// <summary>
    /// Who a PLAIN bind logs in, for the request log. Only from credentials of the shape the mechanism asks
    /// for, read with the code the server reads them with: of anything else no part is shown, because nobody
    /// can tell which part is the password.
    /// </summary>
    private string? SaslName() =>
        string.Equals(SaslMechanism, Plain, StringComparison.OrdinalIgnoreCase) && SaslCredentials is { } credentials
        && TryReadPlain(credentials, out _, out var name, out _)
            ? name
            : null;

    /// <summary>
    /// What a client sent, fit for one line of a log: line breaks, other control characters and the invisible
    /// characters that reorder text are replaced, so that a name cannot make up log lines of its own.
    /// </summary>
    private static string OnOneLine(string text) => string.Create(text.Length, text, static (span, source) =>
    {
        for (var i = 0; i < span.Length; i++)
            span[i] = char.GetUnicodeCategory(source[i]) is System.Globalization.UnicodeCategory.Control
                or System.Globalization.UnicodeCategory.Format
                or System.Globalization.UnicodeCategory.LineSeparator
                or System.Globalization.UnicodeCategory.ParagraphSeparator
                ? '?'
                : source[i];
    });

    /// <summary>
    /// Reads PLAIN credentials (RFC 4616): "[authzid] NUL authcid NUL password", exactly three parts of text, a
    /// name and a password that are not empty.
    /// </summary>
    internal static bool TryReadPlain(byte[] credentials, out string authorization, out string name, out string password)
    {
        authorization = name = password = "";
        var first = Array.IndexOf(credentials, (byte)0);
        var second = first < 0 ? -1 : Array.IndexOf(credentials, (byte)0, first + 1);
        return second >= 0 && Array.IndexOf(credentials, (byte)0, second + 1) < 0
            && Utf8.TryString(credentials[..first], out authorization)
            && Utf8.TryString(credentials[(first + 1)..second], out name)
            && Utf8.TryString(credentials[(second + 1)..], out password)
            && name.Length > 0 && password.Length > 0;
    }
}

/// <summary>The client says it is leaving. It has no answer.</summary>
public sealed record UnbindRequest : LdapRequest
{
    internal override int? ResponseTag => null;
    /// <summary>One line for the request log.</summary>
    public override string ToString() => "Unbind";
}

/// <summary>A search (RFC 4511 §4.5.1).</summary>
public sealed record SearchRequest : LdapRequest
{
    /// <summary>An empty SearchRequest, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public SearchRequest()
    {
    }

    internal SearchRequest(string baseDn, SearchScope scope, int sizeLimit, int timeLimit, bool typesOnly, LdapFilter filter, IReadOnlyList<string> attributes)
    {
        BaseDn = baseDn;
        Scope = scope;
        SizeLimit = sizeLimit;
        TimeLimit = timeLimit;
        TypesOnly = typesOnly;
        Filter = filter;
        Attributes = attributes;
    }

    /// <summary>Where the search starts.</summary>
    public string BaseDn { get; init; } = "";

    /// <summary>How far below the base it looks.</summary>
    public SearchScope Scope { get; init; } = SearchScope.WholeSubtree;

    /// <summary>The most entries the client wants; 0 for no limit.</summary>
    public int SizeLimit { get; init; }

    /// <summary>The most seconds the client wants it to take; 0 for no limit.</summary>
    public int TimeLimit { get; init; }

    /// <summary>True when the client wants attribute names without values.</summary>
    public bool TypesOnly { get; init; }

    /// <summary>Which entries match.</summary>
    public LdapFilter Filter { get; init; } = new LdapFilter.Present("objectClass");

    /// <summary>The attributes to return; empty or <c>*</c> for all user attributes, <c>+</c> for operational ones.</summary>
    public IReadOnlyList<string> Attributes { get; init; } = [];

    internal override int? ResponseTag => 5;
    /// <summary>One line for the request log.</summary>
    public override string ToString() =>
        $"Search base=\"{BaseDn}\" scope={Scope} filter={Filter} attrs=[{string.Join(",", Attributes)}]";
}

/// <summary>A compare: does the entry have this value?</summary>
public sealed record CompareRequest : LdapRequest
{
    /// <summary>An empty CompareRequest, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public CompareRequest()
    {
    }

    internal CompareRequest(string dn, string attribute, byte[] value)
    {
        Dn = dn;
        Attribute = attribute;
        Value = value;
    }

    /// <summary>The entry.</summary>
    public string Dn { get; init; } = "";

    /// <summary>The attribute.</summary>
    public string Attribute { get; init; } = "";

    /// <summary>The value, as the client sent it.</summary>
    public byte[] Value { get; init; } = [];

    internal override int? ResponseTag => 15;
    /// <summary>One line for the request log: the entry and the attribute, not the value.</summary>
    public override string ToString() => $"Compare {Dn} {Attribute}";
}

/// <summary>The client gives up on an earlier request. It has no answer.</summary>
public sealed record AbandonRequest : LdapRequest
{
    /// <summary>An empty AbandonRequest, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public AbandonRequest()
    {
    }

    internal AbandonRequest(int messageId)
    {
        MessageId = messageId;
    }

    /// <summary>The message id of the request to give up on.</summary>
    public int MessageId { get; init; }

    internal override int? ResponseTag => null;
    /// <summary>One line for the request log.</summary>
    public override string ToString() => $"Abandon {MessageId}";
}

/// <summary>An extended operation, such as StartTLS, Who am I? or Password Modify.</summary>
public sealed record ExtendedRequest : LdapRequest
{
    /// <summary>An empty ExtendedRequest, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public ExtendedRequest()
    {
    }

    internal ExtendedRequest(string oid, byte[]? value)
    {
        Oid = oid;
        Value = value;
    }

    /// <summary>Which operation, by its object identifier.</summary>
    public string Oid { get; init; } = "";

    /// <summary>The operation's own data, BER-encoded, or null.</summary>
    public byte[]? Value { get; init; }

    /// <summary>StartTLS (RFC 4511 §4.14).</summary>
    public const string StartTls = "1.3.6.1.4.1.1466.20037";
    /// <summary>"Who am I?" (RFC 4532).</summary>
    public const string WhoAmI = "1.3.6.1.4.1.4203.1.11.3";
    /// <summary>Password Modify (RFC 3062).</summary>
    public const string PasswordModify = "1.3.6.1.4.1.4203.1.11.1";
    internal override int? ResponseTag => 24;
    /// <summary>One line for the request log.</summary>
    public override string ToString() => $"Extended {Oid}";
}

/// <summary>An attribute description with its values, as carried by Add and Modify.</summary>
public sealed record PartialAttribute
{
    /// <summary>An empty PartialAttribute, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public PartialAttribute()
    {
    }

    internal PartialAttribute(string name, IReadOnlyList<byte[]> values)
    {
        Name = name;
        Values = values;
    }

    /// <summary>The attribute description.</summary>
    public string Name { get; init; } = "";

    /// <summary>The values, as bytes.</summary>
    public IReadOnlyList<byte[]> Values { get; init; } = [];

    /// <summary>The values read as UTF-8.</summary>
    public IEnumerable<string> StringValues => Values.Select(v => Utf8.String(v));
    /// <summary>One line for the request log.</summary>
    public override string ToString() => $"{Name}={string.Join("|", StringValues)}";
}

/// <summary>An add: a new entry with its attributes.</summary>
public sealed record AddRequest : LdapRequest
{
    /// <summary>An empty AddRequest, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public AddRequest()
    {
    }

    internal AddRequest(string dn, IReadOnlyList<PartialAttribute> attributes)
    {
        Dn = dn;
        Attributes = attributes;
    }

    /// <summary>The name of the new entry.</summary>
    public string Dn { get; init; } = "";

    /// <summary>Its attributes.</summary>
    public IReadOnlyList<PartialAttribute> Attributes { get; init; } = [];

    internal override int? ResponseTag => 9;
    /// <summary>One line for the request log: the name and the attribute names, no values.</summary>
    public override string ToString() => $"Add {Dn} [{string.Join(", ", Attributes.Select(a => a.Name))}]";
}

/// <summary>A delete of one entry without children.</summary>
public sealed record DeleteRequest : LdapRequest
{
    /// <summary>An empty DeleteRequest, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public DeleteRequest()
    {
    }

    internal DeleteRequest(string dn)
    {
        Dn = dn;
    }

    /// <summary>The entry.</summary>
    public string Dn { get; init; } = "";

    internal override int? ResponseTag => 11;
    /// <summary>One line for the request log.</summary>
    public override string ToString() => $"Delete {Dn}";
}

/// <summary>What one change of a modify does to its attribute.</summary>
public enum ModificationType
{
    /// <summary>Adds the values.</summary>
    Add = 0,
    /// <summary>Removes the values, or the whole attribute when none are given.</summary>
    Delete = 1,
    /// <summary>Replaces all values with these; none removes the attribute.</summary>
    Replace = 2,
    /// <summary>Adds a number to an integer value (RFC 4525).</summary>
    Increment = 3,
}

/// <summary>One change of a modify.</summary>
public sealed record Modification
{
    /// <summary>An empty Modification, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public Modification()
    {
    }

    internal Modification(ModificationType operation, PartialAttribute attribute)
    {
        Operation = operation;
        Attribute = attribute;
    }

    /// <summary>What the change does.</summary>
    public ModificationType Operation { get; init; }

    /// <summary>The attribute and the values it is done with.</summary>
    public PartialAttribute Attribute { get; init; } = new();

    /// <summary>One line for the request log: the operation and the attribute name, no values.</summary>
    public override string ToString() => $"{Operation.ToString().ToLowerInvariant()} {Attribute.Name}";
}

/// <summary>A modify: changes to one entry, made together or not at all.</summary>
public sealed record ModifyRequest : LdapRequest
{
    /// <summary>An empty ModifyRequest, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public ModifyRequest()
    {
    }

    internal ModifyRequest(string dn, IReadOnlyList<Modification> changes)
    {
        Dn = dn;
        Changes = changes;
    }

    /// <summary>The entry.</summary>
    public string Dn { get; init; } = "";

    /// <summary>The changes, in order.</summary>
    public IReadOnlyList<Modification> Changes { get; init; } = [];

    internal override int? ResponseTag => 7;
    /// <summary>One line for the request log.</summary>
    public override string ToString() => $"Modify {Dn} [{string.Join(", ", Changes)}]";
}

/// <summary>A rename or move of an entry.</summary>
public sealed record ModifyDnRequest : LdapRequest
{
    /// <summary>An empty ModifyDnRequest, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public ModifyDnRequest()
    {
    }

    internal ModifyDnRequest(string dn, string newRdn, bool deleteOldRdn, string? newSuperior)
    {
        Dn = dn;
        NewRdn = newRdn;
        DeleteOldRdn = deleteOldRdn;
        NewSuperior = newSuperior;
    }

    /// <summary>The entry.</summary>
    public string Dn { get; init; } = "";

    /// <summary>Its new relative name.</summary>
    public string NewRdn { get; init; } = "";

    /// <summary>True to remove the old RDN's values from the entry.</summary>
    public bool DeleteOldRdn { get; init; }

    /// <summary>The new parent, or null to stay under the same one.</summary>
    public string? NewSuperior { get; init; }

    internal override int? ResponseTag => 13;
    /// <summary>One line for the request log.</summary>
    public override string ToString() => $"ModifyDN {Dn} -> {NewRdn}{(NewSuperior is null ? "" : "," + NewSuperior)}";
}

internal sealed class LdapProtocolException(string message, Exception? inner = null) : Exception(message, inner);

internal static class Utf8
{
    public static string String(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(bytes);

    /// <summary>Decodes the bytes only when they are well-formed UTF-8.</summary>
    public static bool TryString(ReadOnlySpan<byte> bytes, out string value)
    {
        // checked first rather than caught: binary values are common, and an exception per value is slow
        var valid = System.Text.Unicode.Utf8.IsValid(bytes);
        value = valid ? Encoding.UTF8.GetString(bytes) : "";
        return valid;
    }
    public static byte[] Bytes(string value) => Encoding.UTF8.GetBytes(value);
}
