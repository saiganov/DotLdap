using System.Globalization;
using System.Numerics;
using System.Text.RegularExpressions;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

// The strict mode: what a client writes is held against the schema the server publishes.
public sealed partial class InMemoryDirectory
{
    /// <summary>
    /// Hold what clients write (Add, Modify, ModifyDN) against the schema. Off by default: the directory then
    /// takes any value for any attribute. When on, a write is refused if it
    /// <list type="bullet">
    /// <item>leaves a single-valued attribute with more than one value (constraintViolation), or</item>
    /// <item>gives an attribute a value its syntax does not allow: text for a number, something that is no DN for
    /// <c>member</c>, a date that is none (invalidAttributeSyntax).</item>
    /// </list>
    /// Only the attributes a request writes are looked at, and only those the server knows something about: the
    /// well-known ones of either flavour and those declared with
    /// <see cref="DefineAttribute(string, AttributeSyntax, bool)"/>. An attribute it knows nothing about takes
    /// anything, as before; so does data loaded from code or LDIF, which may be as wrong as a test needs it.
    /// Which attributes an object class requires or allows is not checked.
    /// </summary>
    public bool SchemaChecks { get; set; }

    /// <summary>The attribute as the checks see it; null when checks are off or nothing is known about it.</summary>
    private AttributeType? Checked(string name) => SchemaChecks ? KnownAttribute(FilterEvaluator.StripOptions(name)) : null;

    /// <summary>Whether every value fits the attribute's syntax.</summary>
    private LdapResult? CheckSyntax(string name, IReadOnlyList<byte[]> values)
    {
        if (Checked(name) is not { } type) return null;
        for (var i = 0; i < values.Count; i++)
        {
            if (FitsSyntax(type.Syntax, values[i], Layout.IsActiveDirectory)) continue;
            // The Active Directory text is the one a domain controller gives for a value it cannot convert.
            return new LdapResult(ResultCode.InvalidAttributeSyntax, Layout.IsActiveDirectory
                ? "00000057: LdapErr: DSID-0C090D8A, comment: Error in attribute conversion operation, data 0, v2580"
                : $"{type.Name}: value #{i} invalid per syntax");
        }
        return null;
    }

    /// <summary>
    /// Whether the attribute may have this many values. Active Directory answers constraintViolation however the
    /// values got there (MS-ADTS 3.1.1.5.1.1); the Windows error behind it is ERROR_DS_SINGLE_VALUE_CONSTRAINT (0x2081).
    /// </summary>
    private LdapResult? CheckSingleValue(string name, int count)
    {
        if (count <= 1 || Checked(name) is not { SingleValued: true } type) return null;
        return new LdapResult(ResultCode.ConstraintViolation, Layout.IsActiveDirectory
            ? $"00002081: AtrErr: DSID-03151D9D, #1:\n\t0: 00002081: DSID-03151D9D, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 0 ({type.Name})"
            : $"{type.Name}: attribute cannot have multiple values");
    }

    // [0-9] and \z on purpose: to .NET, \d is any Unicode digit and $ also matches before a final line feed.
    private static readonly Regex GeneralizedTime = new(@"^([0-9]{4})([0-9][0-9])([0-9][0-9])([0-9][0-9])(?:([0-9][0-9])([0-9][0-9])?)?(?:[.,][0-9]+)?(?:Z|[+-][0-9][0-9](?:[0-9][0-9])?)\z", RegexOptions.CultureInvariant);
    private static readonly Regex UtcTime = new(@"^([0-9][0-9])([0-9][0-9])([0-9][0-9])([0-9][0-9])([0-9][0-9])([0-9][0-9])?(?:Z|[+-][0-9]{4})\z", RegexOptions.CultureInvariant);
    private static readonly Regex Integer = new(@"^(?:0|-?[1-9][0-9]*)\z", RegexOptions.CultureInvariant);
    private static readonly Regex NumericOid = new(@"^[0-2](?:\.(?:0|[1-9][0-9]*))+\z", RegexOptions.CultureInvariant);
    private static readonly Regex DnWithPart = new(@"^([BS]):([0-9]+):([^:]*):(.*)\z", RegexOptions.CultureInvariant | RegexOptions.Singleline);
    private const string PrintableCharacters = " '()+,-./:=?";

    /// <summary>
    /// The value rules of RFC 4517, as far as a test server needs them. A generic directory reads Active
    /// Directory's own syntaxes as what it publishes them as: a large integer as an integer, the rest as strings.
    /// </summary>
    internal static bool FitsSyntax(AttributeSyntax syntax, byte[] value, bool activeDirectory)
    {
        if (syntax is AttributeSyntax.OctetString or AttributeSyntax.SecurityDescriptor) return true;
        if (!Utf8.TryString(value, out var text)) return false;
        switch (syntax)
        {
            case AttributeSyntax.Integer:
            case AttributeSyntax.LargeInteger:
                if (!Integer.IsMatch(text)) return false;
                if (!activeDirectory) return true;
                // Active Directory stores 32 or 64 bits.
                var number = BigInteger.Parse(text, CultureInfo.InvariantCulture);
                return syntax == AttributeSyntax.Integer
                    ? number >= int.MinValue && number <= int.MaxValue
                    : number >= long.MinValue && number <= long.MaxValue;
            case AttributeSyntax.Boolean:
                return text is "TRUE" or "FALSE";
            case AttributeSyntax.GeneralizedTime:
                return GeneralizedTime.Match(text) is { Success: true } g && IsTime(g, 2, 3, 4, 5, 6) && g.Groups[1].Value != "0000";
            case AttributeSyntax.UtcTime:
                return UtcTime.Match(text) is { Success: true } u && IsTime(u, 2, 3, 4, 5, 6);
            case AttributeSyntax.DistinguishedName:
                return DistinguishedName.TryParse(text, out _);
            case AttributeSyntax.Oid:
                return NumericOid.IsMatch(text) || SchemaCatalog.IsValidName(text);
            case AttributeSyntax.IA5String:
                return text.All(char.IsAscii);
            case AttributeSyntax.PrintableString:
                return text.Length > 0 && text.All(c => char.IsAsciiLetterOrDigit(c) || PrintableCharacters.Contains(c));
            case AttributeSyntax.NumericString:
                return text.Length > 0 && text.All(c => char.IsAsciiDigit(c) || c == ' ');
            case AttributeSyntax.DnWithBinary or AttributeSyntax.DnWithString when activeDirectory:
                // B:<number of hex digits>:<hex digits>:<DN> and S:<number of characters>:<characters>:<DN>
                return DnWithPart.Match(text) is { Success: true } d
                    && d.Groups[1].Value == (syntax == AttributeSyntax.DnWithBinary ? "B" : "S")
                    && int.TryParse(d.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var length)
                    && d.Groups[3].Length == length
                    && (syntax == AttributeSyntax.DnWithString || (length % 2 == 0 && d.Groups[3].Value.All(char.IsAsciiHexDigit)))
                    && DistinguishedName.TryParse(d.Groups[4].Value, out _);
            default:
                return text.Length > 0; // a string of any kind: text, and not empty
        }
    }

    private static bool IsTime(Match match, int month, int day, int hour, int minute, int second)
    {
        int Part(int group, int otherwise) => match.Groups[group].Success ? int.Parse(match.Groups[group].Value, CultureInfo.InvariantCulture) : otherwise;
        return Part(month, 1) is >= 1 and <= 12 && Part(day, 1) is >= 1 and <= 31 && Part(hour, 0) <= 23 && Part(minute, 0) <= 59
            && Part(second, 0) <= 60; // a leap second is a second
    }
}
