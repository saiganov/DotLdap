using System.Formats.Asn1;
using System.Globalization;
using System.Net.Sockets;
using System.Text;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing.Tests.Fuzzing;

/// <summary>
/// How long and from which seed the fuzz tests run. The defaults are fixed, so a CI run is repeatable.
/// For a longer hunt: <c>DOTLDAP_FUZZ_SCALE=50 DOTLDAP_FUZZ_SEED=12345 dotnet test --project tests/DotLdap.Testing.Tests --filter-namespace DotLdap.Testing.Tests.Fuzzing</c>.
/// </summary>
internal static class FuzzSettings
{
    public static int Seed { get; } = Read("DOTLDAP_FUZZ_SEED", 20261125, text =>
        int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seed) ? seed : null);

    private static double Scale { get; } = Read("DOTLDAP_FUZZ_SCALE", 1.0, text =>
        double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var scale) && scale > 0 && scale <= 10_000 ? scale : null);

    // A value that is set but does not parse fails loudly: silently running the default seed would mislead a reproduction.
    private static T Read<T>(string name, T fallback, Func<string, T?> parse) where T : struct
    {
        var text = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(text)) return fallback;
        return parse(text.Trim()) ?? throw new InvalidOperationException($"{name}='{text}' is not a valid value.");
    }

    public static int Iterations(int count) => (int)Math.Max(1, Math.Min(int.MaxValue, count * Scale));

    /// <summary>Enough to run the failing case again: the seed, the step and the input itself.</summary>
    public static string Describe(string target, int iteration, ReadOnlySpan<byte> input, Exception? e = null)
    {
        var hex = Convert.ToHexString(input.Length > 2048 ? input[..2048] : input);
        return $"{target}: seed {Seed}, iteration {iteration}, {input.Length} bytes: {hex}{(input.Length > 2048 ? "..." : "")}"
               + (e is null ? "" : Environment.NewLine + e);
    }
}

/// <summary>Encodes requests the way a client would: the counterpart of <see cref="LdapDecoder"/>, kept in the tests.</summary>
internal static class ClientEncoder
{
    private static Asn1Tag App(int n, bool constructed = true) => new(TagClass.Application, n, constructed);
    private static Asn1Tag Ctx(int n, bool constructed = false) => new(TagClass.ContextSpecific, n, constructed);
    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    public static byte[] Encode(LdapMessage message) => Encode(message.MessageId, message.Request, message.Controls);

    public static byte[] Encode(int id, LdapRequest request, IReadOnlyList<LdapControl>? controls = null)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            w.WriteInteger(id);
            WriteRequest(w, request);
            if (controls is { Count: > 0 })
            {
                using (w.PushSequence(Ctx(0, true)))
                {
                    foreach (var control in controls)
                    {
                        using (w.PushSequence())
                        {
                            w.WriteOctetString(Bytes(control.Oid));
                            if (control.Critical) w.WriteBoolean(true);
                            if (control.Value is not null) w.WriteOctetString(control.Value);
                        }
                    }
                }
            }
        }
        return w.Encode();
    }

    public static byte[] PagedResults(int size, byte[] cookie)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            w.WriteInteger(size);
            w.WriteOctetString(cookie);
        }
        return w.Encode();
    }

    public static byte[] SortRequest(params (string Attribute, string? Rule, bool Reverse)[] keys)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            foreach (var (attribute, rule, reverse) in keys)
            {
                using (w.PushSequence())
                {
                    w.WriteOctetString(Bytes(attribute));
                    if (rule is not null) w.WriteOctetString(Bytes(rule), Ctx(0));
                    if (reverse) w.WriteBoolean(true, Ctx(1));
                }
            }
        }
        return w.Encode();
    }

    /// <summary>A bind with one of Microsoft's "Sicily" authentication choices: [9], [10] or [11].</summary>
    public static byte[] SicilyBind(int id, int choice, string name, byte[] token)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            w.WriteInteger(id);
            using (w.PushSequence(App(0)))
            {
                w.WriteInteger(3);
                w.WriteOctetString(Bytes(name));
                w.WriteOctetString(token, Ctx(choice));
            }
        }
        return w.Encode();
    }

    public static byte[] PasswordModify(string? user, string? oldPassword, string? newPassword)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            if (user is not null) w.WriteOctetString(Bytes(user), Ctx(0));
            if (oldPassword is not null) w.WriteOctetString(Bytes(oldPassword), Ctx(1));
            if (newPassword is not null) w.WriteOctetString(Bytes(newPassword), Ctx(2));
        }
        return w.Encode();
    }

    private static void WriteRequest(AsnWriter w, LdapRequest request)
    {
        switch (request)
        {
            case BindRequest bind:
                using (w.PushSequence(App(0)))
                {
                    w.WriteInteger(bind.Version);
                    w.WriteOctetString(Bytes(bind.Name));
                    if (bind.SaslMechanism is null) w.WriteOctetString(Bytes(bind.Password ?? ""), Ctx(0));
                    else if (bind.SaslMechanism == BindRequest.Sicily) w.WriteOctetString([], Ctx(10)); // the NTLM bind of Windows clients
                    else
                    {
                        using (w.PushSequence(Ctx(3, true)))
                        {
                            w.WriteOctetString(Bytes(bind.SaslMechanism));
                            if (bind.SaslCredentials is not null) w.WriteOctetString(bind.SaslCredentials);
                        }
                    }
                }
                break;
            case UnbindRequest:
                w.WriteNull(App(2, false));
                break;
            case SearchRequest search:
                using (w.PushSequence(App(3)))
                {
                    w.WriteOctetString(Bytes(search.BaseDn));
                    w.WriteEnumeratedValue(search.Scope);
                    w.WriteEnumeratedValue(SearchScope.BaseObject); // derefAliases: never
                    w.WriteInteger(search.SizeLimit);
                    w.WriteInteger(search.TimeLimit);
                    w.WriteBoolean(search.TypesOnly);
                    WriteFilter(w, search.Filter);
                    using (w.PushSequence())
                    {
                        foreach (var attribute in search.Attributes) w.WriteOctetString(Bytes(attribute));
                    }
                }
                break;
            case ModifyRequest modify:
                using (w.PushSequence(App(6)))
                {
                    w.WriteOctetString(Bytes(modify.Dn));
                    using (w.PushSequence())
                    {
                        foreach (var change in modify.Changes)
                        {
                            using (w.PushSequence())
                            {
                                w.WriteEnumeratedValue(change.Operation);
                                WriteAttribute(w, change.Attribute);
                            }
                        }
                    }
                }
                break;
            case AddRequest add:
                using (w.PushSequence(App(8)))
                {
                    w.WriteOctetString(Bytes(add.Dn));
                    using (w.PushSequence())
                    {
                        foreach (var attribute in add.Attributes) WriteAttribute(w, attribute);
                    }
                }
                break;
            case DeleteRequest delete:
                w.WriteOctetString(Bytes(delete.Dn), App(10, false));
                break;
            case ModifyDnRequest rename:
                using (w.PushSequence(App(12)))
                {
                    w.WriteOctetString(Bytes(rename.Dn));
                    w.WriteOctetString(Bytes(rename.NewRdn));
                    w.WriteBoolean(rename.DeleteOldRdn);
                    if (rename.NewSuperior is not null) w.WriteOctetString(Bytes(rename.NewSuperior), Ctx(0));
                }
                break;
            case CompareRequest compare:
                using (w.PushSequence(App(14)))
                {
                    w.WriteOctetString(Bytes(compare.Dn));
                    using (w.PushSequence())
                    {
                        w.WriteOctetString(Bytes(compare.Attribute));
                        w.WriteOctetString(compare.Value);
                    }
                }
                break;
            case AbandonRequest abandon:
                w.WriteInteger(abandon.MessageId, App(16, false));
                break;
            case ExtendedRequest extended:
                using (w.PushSequence(App(23)))
                {
                    w.WriteOctetString(Bytes(extended.Oid), Ctx(0));
                    if (extended.Value is not null) w.WriteOctetString(extended.Value, Ctx(1));
                }
                break;
            default:
                throw new NotSupportedException(request.GetType().Name);
        }
    }

    private static void WriteAttribute(AsnWriter w, PartialAttribute attribute)
    {
        using (w.PushSequence())
        {
            w.WriteOctetString(Bytes(attribute.Name));
            using (w.PushSetOf())
            {
                foreach (var value in attribute.Values) w.WriteOctetString(value);
            }
        }
    }

    private static void WriteFilter(AsnWriter w, LdapFilter filter)
    {
        switch (filter)
        {
            case LdapFilter.And and:
                using (w.PushSequence(Ctx(0, true)))
                {
                    foreach (var inner in and.Filters) WriteFilter(w, inner);
                }
                break;
            case LdapFilter.Or or:
                using (w.PushSequence(Ctx(1, true)))
                {
                    foreach (var inner in or.Filters) WriteFilter(w, inner);
                }
                break;
            case LdapFilter.Not not:
                using (w.PushSequence(Ctx(2, true))) WriteFilter(w, not.Filter);
                break;
            case LdapFilter.Equality f:
                WriteAssertion(w, 3, f.Attribute, f.Value);
                break;
            case LdapFilter.GreaterOrEqual f:
                WriteAssertion(w, 5, f.Attribute, f.Value);
                break;
            case LdapFilter.LessOrEqual f:
                WriteAssertion(w, 6, f.Attribute, f.Value);
                break;
            case LdapFilter.Approx f:
                WriteAssertion(w, 8, f.Attribute, f.Value);
                break;
            case LdapFilter.Present f:
                w.WriteOctetString(Bytes(f.Attribute), Ctx(7));
                break;
            case LdapFilter.Substrings f:
                using (w.PushSequence(Ctx(4, true)))
                {
                    w.WriteOctetString(Bytes(f.Attribute));
                    using (w.PushSequence())
                    {
                        if (f.Initial is not null) w.WriteOctetString(f.Initial, Ctx(0));
                        foreach (var any in f.Any) w.WriteOctetString(any, Ctx(1));
                        if (f.Final is not null) w.WriteOctetString(f.Final, Ctx(2));
                    }
                }
                break;
            case LdapFilter.Extensible f:
                using (w.PushSequence(Ctx(9, true)))
                {
                    if (f.MatchingRule is not null) w.WriteOctetString(Bytes(f.MatchingRule), Ctx(1));
                    if (f.Attribute is not null) w.WriteOctetString(Bytes(f.Attribute), Ctx(2));
                    w.WriteOctetString(f.Value, Ctx(3));
                    if (f.DnAttributes) w.WriteBoolean(true, Ctx(4));
                }
                break;
            default:
                throw new NotSupportedException(filter.GetType().Name);
        }
    }

    private static void WriteAssertion(AsnWriter w, int choice, string attribute, byte[] value)
    {
        using (w.PushSequence(Ctx(choice, true)))
        {
            w.WriteOctetString(Bytes(attribute));
            w.WriteOctetString(value);
        }
    }
}

/// <summary>
/// Makes requests that are well-formed LDAP but hostile in what they say: DNs that do not parse, attribute names
/// with stray options, values that are almost a SID, a GUID, a number or a password.
/// </summary>
internal sealed class FuzzGenerator(Random random, IReadOnlyList<string> knownDns)
{
    private static readonly string[] AttributeNames =
    [
        "objectClass", "cn", "sn", "uid", "mail", "member", "memberOf", "uniqueMember", "userPassword", "unicodePwd",
        "sAMAccountName", "userPrincipalName", "objectSid", "objectGUID", "objectCategory", "userAccountControl",
        "pwdLastSet", "lockoutTime", "accountExpires", "primaryGroupID", "primaryGroupToken", "tokenGroups",
        "distinguishedName", "dn", "entryDN", "entryUUID", "createTimestamp", "modifyTimestamp", "whenCreated",
        "whenChanged", "hasSubordinates", "subschemaSubentry", "namingContexts", "description", "ou", "dc", "name",
        "pwdAccountLockedTime", "badPwdCount", "displayName", "groupType", "sAMAccountType", "msDS-User-Account-Control-Computed",
        "attributeTypes", "objectClasses", "modifyTimeStamp",
        "*", "+", "1.1", "2.5.4.3",
    ];

    private static readonly string[] AttributeOptions =
    [
        ";binary", ";lang-en", ";range=0-*", ";range=0-1", ";range=2-1", ";range=5-*", ";range=-1-*", ";range=1-0",
        ";range=99999999999-*", ";range=2147483647-*", ";range=0-2147483647", ";range=", ";range=a-b", ";", ";;x",
        ";range=0-*;range=1-*", ";RANGE=1-1", ";binary;range=0-0",
    ];

    private static readonly string[] OddNames = ["", " ", "=", "a=b", "cn,dc", "имя", "\0", "cn\n", ";range=0-*", "(cn", "c n", "*x"];

    private static readonly string[] Numbers =
    [
        "0", "1", "-1", "2", "512", "514", "544", "66048", "8388608", "2147483647", "2147483648", "4294967295",
        "-2147483648", "-2147483649", "9223372036854775807", "9223372036854775808", "-9223372036854775808",
        "99999999999999999999999", "1e5", "0x10", " 5 ", "+5", "TRUE", "FALSE", "133000000000000000",
        "20260101000000Z", "20260101000000.0Z", "99991231235959Z", "garbage",
    ];

    private static readonly string[] ObjectClasses =
    [
        "top", "person", "user", "group", "computer", "organizationalUnit", "organizationalPerson", "inetOrgPerson",
        "groupOfNames", "domain", "container", "foreignSecurityPrincipal", "nonsense", "",
    ];

    private static readonly string[] Names =
    [
        "alice", "bob", "fuzzer", "Developers", "Engineering", "Domain Users", "alice@example.com", "ALICE", "al", "ice",
        "fuzz0", "fuzz1", "fuzz2", "fuzz3", "unit0", "example", "Users", "",
    ];

    private static readonly string[] Passwords =
    [
        "", "secret", "password", "fuzzer-secret", "alice-secret", "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "{MD5}X03MO1qnZdYdgyfeuILPmQ==",
        "{SSHA256}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "{SHA512}AAAA", "{SSHA384}", "{SHA384}=", "{SASL}alice@EXAMPLE.COM", "{SSHA}", "{SSHA}!!!", "{SSHA}AAAA", "{SHA}", "{MD5}AAAA", "{SMD5}AA==",
        "{CRYPT}x", "{PBKDF2}x", "{SSHA512}", "{SHA256}" + "A", "{", "{}", "{x}y", "}{", "{ssha}W6ph5Mm5Pz8GgiULbPgzG37mj9g=",
    ];

    private static readonly string[] TextOddities =
    [
        "*", "(", ")", "\\", "\0", "a*b", "*)(uid=*", " lead", "trail ", "#hash", "a,b+c=d", "\"", "<", ">", ";",
        "Ünïcödé", "名前", "😀", "\r\n", "a\\2ab", "\\zz",
    ];

    private static readonly string[] MalformedDns =
    [
        "=", "cn", "cn=", ",", "cn=a,", "cn=a,,dc=b", "cn=a\\", "cn=a+", "+=,", "cn=a;dc=b", "OID.2.5.4.3=a", "OID.=a",
        "1.2.3=#04024869", "cn=\"quoted,dn\",dc=example,dc=com", "cn=a\\0", "cn=a\\0g", " cn = a , dc = b ", "cn=#", "=a",
        "<", "<>", "<=>", "<GUID=>", "<GUID=zz>", "<GUID=00000000000000000000000000000000>", "<GUID=00000000-0000-0000-0000-000000000000>",
        "<GUID={00000000-0000-0000-0000-000000000000}>", "<SID=>", "<SID=S-1>", "<SID=S-1-5-32-544>", "<SID=S-1-5-21-1-2-3-513>",
        "<SID=S-1-5-21-99999999999-1-1-1>", "<SID=010500000000000515000000>", "<WKGUID=a,b>", "<SID =S-1-5-32-544 >", "<sid=s-1-5-32-544>",
        "alice", "alice@example.com", "EXAMPLE\\alice", "\\", "@", "a@b@c", "CORP\\", "\\alice",
    ];

    private static readonly string[] MatchingRules =
    [
        "1.2.840.113556.1.4.803", "1.2.840.113556.1.4.804", "1.2.840.113556.1.4.1941", "2.5.13.2", "caseIgnoreMatch",
        "caseExactMatch", "", "garbage", "1.2.840.113556.1.4.1941 ",
    ];

    private static readonly string[] ExtendedOids =
    [
        ExtendedRequest.StartTls, ExtendedRequest.WhoAmI, ExtendedRequest.PasswordModify, ExtendedRequest.PasswordModify,
        "1.3.6.1.4.1.1466.20036", "1.2.3", "", "not an oid",
    ];

    private static readonly string[] ControlOids =
    [
        "1.2.840.113556.1.4.801", "1.2.840.113556.1.4.473", "2.16.840.1.113730.3.4.2", "1.2.840.113556.1.4.417", "", "x",
    ];

    private static readonly int[] Limits = [0, 0, 0, 1, 2, 5, 1000, int.MaxValue, -1, int.MinValue];

    private T Pick<T>(IReadOnlyList<T> items) => items[random.Next(items.Count)];
    private bool Chance(double probability) => random.NextDouble() < probability;
    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    public LdapMessage Message() => new(MessageId(), Request(), Controls());

    private int MessageId() => random.Next(20) switch
    {
        0 => 0,
        1 => int.MaxValue,
        _ => random.Next(1, 1000),
    };

    public LdapRequest Request() => random.Next(100) switch
    {
        < 35 => Search(),
        < 50 => Modify(),
        < 62 => Add(),
        < 70 => Compare(),
        < 78 => ModifyDn(),
        < 84 => new DeleteRequest(TargetDn()),
        < 90 => Bind(),
        < 96 => Extended(),
        < 98 => new AbandonRequest(Pick(Limits)),
        _ => new UnbindRequest(),
    };

    /// <summary>
    /// An attribute together with a value of the kind it holds: a SID for objectSid, a DN for member. Random
    /// pairs alone almost never get past the first check of the code that reads these attributes.
    /// </summary>
    private (string Name, Func<byte[]> Value) Pair() => random.Next(16) switch
    {
        0 => ("objectSid", Sid),
        1 => ("objectGUID", Guid),
        2 => ("userAccountControl", Number),
        3 => (Pick<string>(["pwdLastSet", "lockoutTime", "accountExpires", "badPwdCount", "primaryGroupID", "uidNumber", "groupType"]), Number),
        4 or 5 => (Pick<string>(["member", "memberOf", "uniqueMember", "distinguishedName", "manager", "objectCategory"]), () => Bytes(TargetDn())),
        6 => ("unicodePwd", UnicodePassword),
        7 or 8 => ("userPassword", () => Bytes(Pick(Passwords))),
        9 or 10 => ("objectClass", () => Bytes(Pick(ObjectClasses))),
        11 => ("objectCategory", () => Bytes(Pick<string>(["person", "group", "computer", "organizationalUnit", "nonsense", ""]))),
        _ => (Pick<string>(["cn", "uid", "sAMAccountName", "userPrincipalName", "mail", "name", "description", "displayName", "ou"]), () => Bytes(Pick(Names))),
    };

    private byte[] Number() => Bytes(Pick(Numbers));

    /// <summary>An attribute and a value to compare it with, for filters and Compare.</summary>
    private (string Name, byte[] Value) Assertion()
    {
        if (Chance(0.4)) return (AttributeName(), Value());
        var (name, value) = Pair();
        if (Chance(0.1)) name += Pick(AttributeOptions);
        return (Chance(0.2) ? name.ToUpperInvariant() : name, value());
    }

    public string AttributeName()
    {
        if (Chance(0.06)) return Pick(OddNames);
        if (Chance(0.01)) return new string('a', 5000);
        var name = Pick(AttributeNames);
        if (Chance(0.3)) name = Chance(0.5) ? name.ToUpperInvariant() : name.ToLowerInvariant();
        return Chance(0.2) ? name + Pick(AttributeOptions) : name;
    }

    /// <summary>A DN that is there, or was at the start, or that an earlier Add of this run may have created.</summary>
    private string ExistingDn() => Chance(0.75) ? Pick(knownDns) : $"cn=fuzz{random.Next(12)},{Pick(knownDns)}";

    /// <summary>What an operation is aimed at: an entry that is there most of the time, anything at all otherwise.</summary>
    private string TargetDn() => Chance(0.7) ? Pick(knownDns) : Dn();

    /// <summary>A DN whose parent is likely to exist: the place for an Add or the target of a rename.</summary>
    private string NewDn() => $"{RdnText()},{ExistingDn()}";

    public string Dn()
    {
        switch (random.Next(100))
        {
            case < 55:
                return ExistingDn();
            case < 70:
                return NewDn();
            case < 73:
                return $"{RdnText()},{RdnText()},{Pick(knownDns)}";
            case < 77:
                return "";
            case < 81:
                return Pick(knownDns).ToUpperInvariant();
            case < 83:
                return string.Concat(Enumerable.Repeat("dc=a,", random.Next(1, 400))) + Pick(knownDns);
            case < 84:
                return "cn=" + new string('a', 10_000);
            default:
                return Pick(MalformedDns);
        }
    }

    private string RdnText() => random.Next(12) switch
    {
        < 6 => $"cn=fuzz{random.Next(12)}",
        6 => $"ou=unit{random.Next(4)}",
        7 => $"uid=fuzz{random.Next(4)}",
        8 => $"cn=a{random.Next(3)}+sn=b",
        9 => $"cn=x\\,y{random.Next(3)}",
        10 => "cn=" + Pick(TextOddities),
        _ => $"{AttributeName()}={Pick(Numbers)}",
    };

    public byte[] Value()
    {
        switch (random.Next(100))
        {
            case < 18: return Bytes(Pick(Numbers));
            case < 30: return Bytes(Dn());
            case < 38: return Bytes(Pick(ObjectClasses));
            case < 46: return Bytes(Pick(Passwords));
            case < 52: return Bytes(Pick(TextOddities));
            case < 60: return Sid();
            case < 64: return Guid();
            case < 72: return UnicodePassword();
            case < 73: return [];
            case < 76: return Pick<byte[]>([[0xFF], [0xC0, 0x80], [0xED, 0xA0, 0x80], [0xF8, 0x88, 0x80, 0x80, 0x80], [0xE2, 0x82], [0x00]]);
            case < 77 when Chance(0.2): return RandomBytes(random.Next(10_000, 30_000));
            case < 77: return Bytes($"fuzz{random.Next(12)}");
            case < 90: return RandomBytes(random.Next(0, 40));
            default: return Bytes($"fuzz{random.Next(12)}");
        }
    }

    private byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }

    private byte[] Sid()
    {
        if (Chance(0.4)) return Bytes(Pick<string>(["S-1-5-21-1-2-3-513", "S-1-5-32-544", "S-1", "S-", "s-1-5-21-1-2-3-1104", "S-1-5-21-99999999999-1-1-1", "S-1-5-", "S-1-5-21-1-2-3-", "S-1-5--21", "S-1-" + string.Join("-", Enumerable.Repeat("5", 300))]));
        var subAuthorities = random.Next(0, 7);
        var sid = new List<byte> { 1, (byte)subAuthorities, 0, 0, 0, 0, 0, 5 };
        for (var i = 0; i < subAuthorities; i++) sid.AddRange(BitConverter.GetBytes(i == 0 ? 21u : (uint)random.Next(0, 2000)));
        switch (random.Next(6))
        {
            case 0: sid[1] = (byte)random.Next(256); break;            // count that does not match the length
            case 2: sid.RemoveRange(random.Next(sid.Count), random.Next(2)); break;                // maybe one byte short
            case 4: { var keep = random.Next(sid.Count); sid.RemoveRange(keep, sid.Count - keep); break; } // cut off
            case 3: sid[0] = (byte)random.Next(256); break;            // revision
        }
        return sid.ToArray();
    }

    private byte[] Guid() => random.Next(4) switch
    {
        0 => RandomBytes(15),
        1 => RandomBytes(17),
        2 => Bytes(System.Guid.Empty.ToString()),
        _ => RandomBytes(16),
    };

    private byte[] UnicodePassword()
    {
        var quoted = Encoding.Unicode.GetBytes($"\"{Pick(Passwords)}\"");
        return random.Next(6) switch
        {
            0 => quoted[..^1],                               // odd length
            1 => Encoding.Unicode.GetBytes(Pick(Passwords)), // no quotes
            2 => Encoding.Unicode.GetBytes("\""),
            3 => [.. quoted, 0x00, 0xD8],                    // a lone surrogate after the closing quote
            _ => quoted,
        };
    }

    private PartialAttribute Attribute(int maxValues = 3)
    {
        var (name, value) = Chance(0.55) ? Pair() : (AttributeName(), Value);
        var values = new List<byte[]>();
        var count = Chance(0.004) ? 2000 : Chance(0.06) ? 0 : random.Next(1, maxValues + 1);
        for (var i = 0; i < count; i++) values.Add(value());
        if (count > 1 && Chance(0.2)) values.Add(values[0]); // a duplicate
        return new PartialAttribute(name, values);
    }

    private SearchRequest Search()
    {
        var attributes = new List<string>();
        for (var i = random.Next(0, 5); i > 0; i--) attributes.Add(AttributeName());
        // Now and then everything there is, so that sorting and paging get more than an entry or two to work on.
        if (Chance(0.1)) return new SearchRequest(Pick(knownDns), SearchScope.WholeSubtree, 0, 0, false, new LdapFilter.Present("objectClass"), attributes);
        return new SearchRequest(TargetDn(), (SearchScope)random.Next(3), Pick(Limits), Pick(Limits), Chance(0.1), Filter(0), attributes);
    }

    public LdapFilter Filter(int depth)
    {
        var kind = random.Next(depth >= 4 ? 3 : 0, 13);
        switch (kind)
        {
            case 0:
            case 1:
            {
                var inner = new List<LdapFilter>();
                for (var i = random.Next(0, 4); i > 0; i--) inner.Add(Filter(depth + 1));
                return kind == 0 ? new LdapFilter.And(inner) : new LdapFilter.Or(inner);
            }
            case 2:
                return new LdapFilter.Not(Filter(depth + 1));
            case 3:
            case 4:
            case 5:
                return Comparison(kind);
            case 6:
                return new LdapFilter.Present(Chance(0.5) ? "objectClass" : AttributeName());
            case 7:
            {
                var any = new List<byte[]>();
                for (var i = random.Next(0, 3); i > 0; i--) any.Add(Piece());
                var attribute = Chance(0.6) ? Pick<string>(["cn", "uid", "sAMAccountName", "member", "objectSid", "distinguishedName", "mail"]) : AttributeName();
                return new LdapFilter.Substrings(attribute, Chance(0.5) ? Piece() : null, any, Chance(0.5) ? Piece() : null);
            }
            case 8:
            case 9:
            case 10:
                return Comparison(kind);
            default:
            {
                var (name, value) = Assertion();
                return new LdapFilter.Extensible(Chance(0.85) ? Pick(MatchingRules) : null, Chance(0.85) ? name : null, value, Chance(0.2));
            }
        }
    }

    private LdapFilter Comparison(int kind)
    {
        var (name, value) = Assertion();
        return kind switch
        {
            8 => new LdapFilter.GreaterOrEqual(name, value),
            9 => new LdapFilter.LessOrEqual(name, value),
            10 => new LdapFilter.Approx(name, value),
            _ => new LdapFilter.Equality(name, value),
        };
    }

    /// <summary>A piece of a substring filter: often a real fragment of a name, so that matching gets somewhere.</summary>
    private byte[] Piece() => Chance(0.6) ? Bytes(Pick<string>(["a", "al", "ice", "b", "o", "fuzz", "e", "D", "cn=", ",dc=", "S-1-5", ""])) : Value();

    private CompareRequest Compare()
    {
        var (name, value) = Assertion();
        return new CompareRequest(TargetDn(), name, value);
    }

    private ModifyRequest Modify()
    {
        var changes = new List<Modification>();
        for (var i = random.Next(0, 5); i > 0; i--) changes.Add(new Modification((ModificationType)random.Next(4), Attribute()));
        return new ModifyRequest(TargetDn(), changes);
    }

    private AddRequest Add()
    {
        var attributes = new List<PartialAttribute>();
        if (Chance(0.85)) attributes.Add(new PartialAttribute("objectClass", [Bytes(Pick(ObjectClasses)), Bytes(Pick(ObjectClasses))]));
        for (var i = random.Next(0, 6); i > 0; i--) attributes.Add(Attribute());
        return new AddRequest(Chance(0.75) ? NewDn() : Dn(), attributes);
    }

    private ModifyDnRequest ModifyDn()
    {
        var newRdn = random.Next(10) switch
        {
            < 6 => RdnText(),
            6 => "",
            7 => Pick(MalformedDns),
            8 => "cn=a,dc=b",
            _ => Pick(TextOddities),
        };
        return new ModifyDnRequest(TargetDn(), newRdn, Chance(0.5), Chance(0.6) ? null : Chance(0.7) ? ExistingDn() : Dn());
    }

    private BindRequest Bind()
    {
        var version = Chance(0.9) ? 3 : Pick<int>([2, 0, 4, -1, int.MaxValue]);
        if (Chance(0.3))
        {
            // somebody who is really there, under every name a server may accept
            var user = Pick<string>(["alice", "bob"]);
            var dn = knownDns.FirstOrDefault(known => known.Contains("=" + user + ",", StringComparison.OrdinalIgnoreCase)) ?? user;
            return new BindRequest(version, Pick<string>([dn, dn.ToUpperInvariant(), user, user + "@example.com", "EXAMPLE\\" + user, "example.com\\" + user]), user + "-secret", null);
        }
        var name = Chance(0.7) ? TargetDn() : Pick(MalformedDns);
        if (Chance(0.05)) return new BindRequest(version, name, null, BindRequest.Sicily);
        if (Chance(0.1))
        {
            // SASL PLAIN: sound, with the parts mixed up, cut short, or without credentials at all
            string[] names = ["alice", "u:bob", "dn:" + TargetDn(), TargetDn(), "", "u:", "dn:", Pick(MalformedDns), Pick(TextOddities)];
            // Half the time somebody who is really there with the right password, alone or acting for somebody.
            var user = Pick<string>(["alice", "bob", "fuzzer"]);
            string[] forms = [user, "u:" + user, "U:" + user.ToUpperInvariant()];
            byte[]? credentials = random.Next(12) switch
            {
                0 => null,
                1 => [],
                2 => RandomBytes(random.Next(0, 20)),
                3 => Bytes(Pick(names) + "\0" + Pick(Passwords)),
                4 or 5 => Bytes((Chance(0.3) ? Pick(names) : "") + "\0" + Pick(names) + "\0" + Pick(Passwords)),
                6 => Bytes("\0" + Pick(forms) + "\0" + user + "-secret\0"),
                7 or 8 => Bytes((Chance(0.5) ? Pick(forms) : Pick(names)) + "\0" + Pick(forms) + "\0" + user + "-secret"),
                _ => Bytes("\0" + Pick(forms) + "\0" + user + "-secret"),
            };
            return new BindRequest(version, Chance(0.8) ? "" : name, null, Chance(0.9) ? "PLAIN" : "plain", credentials);
        }
        return Chance(0.9)
            ? new BindRequest(version, name, Pick(Passwords), null)
            : new BindRequest(version, name, null, Pick<string>(["GSSAPI", "EXTERNAL", "DIGEST-MD5", "", "GSS-SPNEGO"]));
    }

    private ExtendedRequest Extended()
    {
        var oid = Pick(ExtendedOids);
        byte[]? value = random.Next(8) switch
        {
            0 => null,
            1 => RandomBytes(random.Next(0, 20)),
            _ => ClientEncoder.PasswordModify(
                Chance(0.6) ? (Chance(0.5) ? "dn:" : "") + (Chance(0.7) ? ExistingDn() : Dn()) : null,
                Chance(0.6) ? Pick(Passwords) : null,
                Chance(0.8) ? Pick(Passwords) : null),
        };
        return new ExtendedRequest(oid, value);
    }

    private List<LdapControl> Controls()
    {
        var controls = new List<LdapControl>();
        if (Chance(0.25))
        {
            var cookie = Pick<string>(["", "", "0", "1", "2", "5", "-1", "abc", "99999999999", "2147483647", " 1", "1 ", "\0"]);
            controls.Add(new LdapControl(LdapEncoder.PagedResultsOid, Chance(0.5), ClientEncoder.PagedResults(Pick(Limits), Bytes(cookie))));
        }
        if (Chance(0.05)) controls.Add(new LdapControl(LdapEncoder.PagedResultsOid, Chance(0.5), Chance(0.3) ? null : RandomBytes(random.Next(0, 12))));
        if (Chance(0.05)) controls.Add(new LdapControl(Pick(ControlOids), Chance(0.3), Chance(0.5) ? null : RandomBytes(random.Next(0, 12))));
        if (Chance(0.15))
        {
            // Mostly a few keys; sometimes more than the server sorts by (8) or reads at all (16).
            var keys = Enumerable.Range(0, Chance(0.1) ? random.Next(4, 20) : random.Next(0, 4))
                .Select(_ => (AttributeName(), Chance(0.2) ? Pick(MatchingRules) : null, Chance(0.3)))
                .ToArray();
            controls.Add(new LdapControl(LdapEncoder.SortRequestOid, Chance(0.5), ClientEncoder.SortRequest(keys)));
        }
        return controls;
    }
}

/// <summary>Breaks encoded messages the way a bad client, a wrong port or line noise would.</summary>
internal sealed class Mutator(Random random)
{
    private static readonly byte[] Interesting = [0x00, 0x01, 0x7F, 0x80, 0x81, 0x82, 0x84, 0xFF, 0x30, 0x04, 0x0A, 0x02, 0x01, 0xA0, 0x60, 0x63, 0x24, 0x1F, 0x9F];
    private const int MaxLength = 64 * 1024;

    public byte[] Mutate(byte[] input, byte[]? other = null)
    {
        var data = new List<byte>(input);
        for (var rounds = 1 + random.Next(4); rounds > 0; rounds--) MutateOnce(data, other);
        if (data.Count > MaxLength) data.RemoveRange(MaxLength, data.Count - MaxLength);
        var result = data.ToArray();
        // Most of the time the outer length is repaired, so that the damage reaches the decoder and not only the frame reader.
        return random.Next(10) < 7 ? WithOuterLength(result) : result;
    }

    private void MutateOnce(List<byte> data, byte[]? other)
    {
        if (data.Count == 0)
        {
            data.Add((byte)random.Next(256));
            return;
        }
        var at = random.Next(data.Count);
        switch (random.Next(12))
        {
            case 0:
                data[at] ^= (byte)(1 << random.Next(8));
                break;
            case 1:
                data[at] = Interesting[random.Next(Interesting.Length)];
                break;
            case 2:
                data[at] = (byte)random.Next(256);
                break;
            case 3:
                data[at] = (byte)(data[at] + (random.Next(2) == 0 ? 1 : -1));
                break;
            case 4:
                data.RemoveRange(at, Math.Min(data.Count - at, 1 + random.Next(8)));
                break;
            case 5:
                data.RemoveRange(at, data.Count - at); // truncate
                break;
            case 6:
            {
                var length = Math.Min(data.Count - at, 1 + random.Next(16));
                var copies = random.Next(20) == 0 ? 200 : 1;
                var chunk = data.GetRange(at, length);
                for (var i = 0; i < copies; i++) data.InsertRange(at, chunk);
                break;
            }
            case 7:
            {
                var noise = new byte[1 + random.Next(8)];
                random.NextBytes(noise);
                data.InsertRange(at, noise);
                break;
            }
            case 8:
                data.Insert(at, Interesting[random.Next(Interesting.Length)]);
                break;
            case 9 when other is { Length: > 0 }:
            {
                var from = random.Next(other.Length);
                data.RemoveRange(at, data.Count - at);
                data.AddRange(other.AsSpan(from).ToArray()); // splice the tail of another message
                break;
            }
            case 10:
            {
                // turn a definite length into the indefinite form, or a short length into a long one
                data[at] = random.Next(2) == 0 ? (byte)0x80 : (byte)0x84;
                break;
            }
            default:
            {
                // wrap a stretch in one more constructed element, many times over now and then
                var depth = random.Next(30) == 0 ? 500 : 1;
                var tag = Interesting[random.Next(Interesting.Length)] | 0x20;
                for (var i = 0; i < depth; i++)
                {
                    data.Insert(at, 0x80);
                    data.Insert(at, (byte)tag);
                }
                break;
            }
        }
    }

    /// <summary>Rewrites the header of the outer SEQUENCE so that it covers everything that follows it.</summary>
    public static byte[] WithOuterLength(byte[] data)
    {
        if (data.Length < 2) return data;
        var headerLength = data[1] < 0x80 ? 2 : 2 + (data[1] & 0x7F);
        if (headerLength > data.Length) headerLength = 2;
        var content = data.AsSpan(headerLength);
        var w = new AsnWriter(AsnEncodingRules.BER);
        w.WriteOctetString(content, new Asn1Tag(TagClass.Application, 0)); // any one-byte tag: it is replaced just below
        var result = w.Encode();
        result[0] = data[0]; // the first byte stays as the mutation left it
        return result;
    }
}

/// <summary>The same idea for the text formats: filters, DNs and LDIF.</summary>
internal sealed class TextMutator(Random random)
{
    private const string Alphabet = "()&|!=~<>:*\\+,;#\" \n\r\t\0-09afAFzé名:=dn";

    public string Mutate(string input)
    {
        var text = new StringBuilder(input);
        for (var rounds = 1 + random.Next(4); rounds > 0; rounds--)
        {
            var at = random.Next(text.Length + 1);
            switch (random.Next(6))
            {
                case 0:
                    text.Insert(at, Alphabet[random.Next(Alphabet.Length)]);
                    break;
                case 1 when at < text.Length:
                    text.Remove(at, Math.Min(text.Length - at, 1 + random.Next(4)));
                    break;
                case 2 when at < text.Length:
                    text[at] = Alphabet[random.Next(Alphabet.Length)];
                    break;
                case 3 when at < text.Length:
                {
                    var chunk = text.ToString(at, Math.Min(text.Length - at, 1 + random.Next(12)));
                    var copies = random.Next(20) == 0 ? 100 : 1;
                    for (var i = 0; i < copies; i++) text.Insert(at, chunk);
                    break;
                }
                case 4 when at < text.Length:
                    text.Length = at; // truncate
                    break;
                default:
                    text.Insert(at, (char)random.Next(char.MaxValue + 1)); // any UTF-16 unit, lone surrogates included
                    break;
            }
        }
        return text.ToString();
    }
}

/// <summary>One answer from the server, reduced to what the fuzz tests check.</summary>
internal sealed record RawResponse(int MessageId, int Operation, int? ResultCode, string Message)
{
    /// <summary>The cookie of the paged results control, or null when the response carries none.</summary>
    public byte[]? PagingCookie { get; init; }
}

/// <summary>A bare socket to the server: no LDAP library between the test and the bytes.</summary>
internal sealed class RawClient : IDisposable
{
    private readonly TcpClient _client;
    private readonly NetworkStream _stream;

    public RawClient(string host, int port)
    {
        _client = new TcpClient(host, port) { NoDelay = true };
        _stream = _client.GetStream();
    }

    public void Dispose() => _client.Dispose();

    /// <returns>false when the server had already closed the connection.</returns>
    public bool Send(ReadOnlySpan<byte> bytes)
    {
        try
        {
            _stream.Write(bytes);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
    }

    public void FinishSending()
    {
        try
        {
            _client.Client.Shutdown(SocketShutdown.Send);
        }
        catch (SocketException)
        {
            // the server closed first
        }
    }

    /// <summary>The next PDU, or null once the server has closed the connection.</summary>
    /// <exception cref="TimeoutException">Nothing arrived in time: the server hangs.</exception>
    public RawResponse? Read(TimeSpan timeout)
    {
        using var deadline = new CancellationTokenSource(timeout);
        byte[]? frame;
        try
        {
            frame = LdapFrameReader.ReadAsync(_stream, 64 * 1024 * 1024, deadline.Token).AsTask().GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException($"The server sent nothing for {timeout.TotalSeconds:0} s.");
        }
        catch (IOException)
        {
            return null;
        }
        if (frame is null) return null;

        var message = new AsnReader(frame, AsnEncodingRules.BER).ReadSequence();
        Assert.True(message.TryReadInt32(out var id));
        var tag = message.PeekTag();
        Assert.Equal(TagClass.Application, tag.TagClass);
        var operation = message.ReadSequence(tag);
        if (tag.TagValue == 4) return new RawResponse(id, 4, null, "");
        var code = (int)new System.Numerics.BigInteger(operation.ReadEnumeratedBytes().Span, isUnsigned: false, isBigEndian: true);
        operation.ReadOctetString();
        var text = Encoding.UTF8.GetString(operation.ReadOctetString());

        byte[]? cookie = null;
        if (message.HasData)
        {
            var controls = message.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
            while (controls.HasData)
            {
                var control = controls.ReadSequence();
                var oid = Encoding.UTF8.GetString(control.ReadOctetString());
                if (control.HasData && control.PeekTag() == Asn1Tag.Boolean) control.ReadBoolean();
                if (oid == LdapEncoder.PagedResultsOid && control.HasData) cookie = LdapEncoder.ReadPagedResultsControl(control.ReadOctetString()).Cookie;
            }
        }
        return new RawResponse(id, tag.TagValue, code, text) { PagingCookie = cookie };
    }

    /// <summary>Reads until the server closes the connection, whatever it sends before that.</summary>
    /// <exception cref="TimeoutException">The server kept the connection open.</exception>
    public void WaitForClose(TimeSpan timeout)
    {
        try
        {
            _client.ReceiveTimeout = (int)timeout.TotalMilliseconds;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.InvalidArgument)
        {
            return; // macOS refuses socket options on a connection the server has already reset: it is closed
        }
        var buffer = new byte[4096];
        try
        {
            while (_stream.Read(buffer) > 0)
            {
            }
        }
        catch (IOException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.TimedOut })
        {
            throw new TimeoutException($"The server kept the connection open for {timeout.TotalSeconds:0} s.");
        }
        catch (IOException)
        {
            // reset by the server: closed as well
        }
    }

    /// <summary>Sends one request and reads up to its final response; search entries on the way are skipped.</summary>
    public RawResponse? Exchange(ReadOnlySpan<byte> request, TimeSpan timeout) => Exchange(request, timeout, out _);

    /// <summary>The same, and says how many search entries came before the final response.</summary>
    public RawResponse? Exchange(ReadOnlySpan<byte> request, TimeSpan timeout, out int entries)
    {
        entries = 0;
        if (!Send(request)) return null;
        while (true)
        {
            var response = Read(timeout);
            if (response is null || response.Operation != 4) return response;
            entries++;
        }
    }
}
