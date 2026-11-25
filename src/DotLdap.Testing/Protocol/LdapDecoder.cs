using System.Formats.Asn1;

namespace DotLdap.Testing.Protocol;

/// <summary>Decodes client PDUs (RFC 4511) from BER.</summary>
internal static class LdapDecoder
{
    private const int MaxFilterDepth = 64;

    private static Asn1Tag App(int n, bool constructed = true) => new(TagClass.Application, n, constructed);
    private static Asn1Tag Ctx(int n, bool constructed = false) => new(TagClass.ContextSpecific, n, constructed);

    public static LdapMessage Decode(ReadOnlyMemory<byte> data)
    {
        try
        {
            var reader = new AsnReader(data, AsnEncodingRules.BER);
            var message = reader.ReadSequence();
            if (reader.HasData) throw new LdapProtocolException("Unexpected bytes after the LDAPMessage.");
            if (!message.TryReadInt32(out var id) || id < 0) throw new LdapProtocolException("Invalid messageID.");

            var tag = message.PeekTag();
            if (tag.TagClass != TagClass.Application) throw new LdapProtocolException($"Unexpected protocolOp tag {tag}.");

            LdapRequest request = tag.TagValue switch
            {
                0 => ReadBind(message),
                2 => ReadUnbind(message),
                3 => ReadSearch(message),
                6 => ReadModify(message),
                8 => ReadAdd(message),
                10 => new DeleteRequest(ReadString(message, App(10, false))),
                12 => ReadModifyDn(message),
                14 => ReadCompare(message),
                16 => ReadAbandon(message),
                23 => ReadExtended(message),
                _ => throw new LdapProtocolException($"Unknown protocolOp [APPLICATION {tag.TagValue}]."),
            };

            var controls = message.HasData ? ReadControls(message) : [];
            return new LdapMessage(id, request, controls);
        }
        catch (AsnContentException e)
        {
            throw new LdapProtocolException("Malformed LDAP message: " + e.Message, e);
        }
    }

    private static string ReadString(AsnReader reader, Asn1Tag? tag = null) => Utf8.String(reader.ReadOctetString(tag));

    private static PartialAttribute ReadPartialAttribute(AsnReader reader)
    {
        var attribute = reader.ReadSequence();
        var name = ReadString(attribute);
        var values = new List<byte[]>();
        var set = attribute.ReadSetOf();
        while (set.HasData) values.Add(set.ReadOctetString());
        return new PartialAttribute(name, values);
    }

    private static AddRequest ReadAdd(AsnReader message)
    {
        var add = message.ReadSequence(App(8));
        var dn = ReadString(add);
        var attributes = new List<PartialAttribute>();
        var list = add.ReadSequence();
        while (list.HasData) attributes.Add(ReadPartialAttribute(list));
        return new AddRequest(dn, attributes);
    }

    private static ModifyRequest ReadModify(AsnReader message)
    {
        var modify = message.ReadSequence(App(6));
        var dn = ReadString(modify);
        var changes = new List<Modification>();
        var list = modify.ReadSequence();
        while (list.HasData)
        {
            var change = list.ReadSequence();
            var operation = change.ReadEnumeratedValue<ModificationType>();
            if (!Enum.IsDefined(operation)) throw new LdapProtocolException($"Unknown modify operation {(int)operation}.");
            changes.Add(new Modification(operation, ReadPartialAttribute(change)));
        }
        return new ModifyRequest(dn, changes);
    }

    private static ModifyDnRequest ReadModifyDn(AsnReader message)
    {
        var rename = message.ReadSequence(App(12));
        var dn = ReadString(rename);
        var newRdn = ReadString(rename);
        var deleteOldRdn = rename.ReadBoolean();
        var newSuperior = rename.HasData ? ReadString(rename, Ctx(0)) : null;
        return new ModifyDnRequest(dn, newRdn, deleteOldRdn, newSuperior);
    }

    /// <summary>Decodes the value of a Password Modify extended request (RFC 3062). All three fields are optional.</summary>
    public static (string? UserIdentity, string? OldPassword, string? NewPassword) ReadPasswordModify(byte[]? value)
    {
        if (value is null) return (null, null, null);
        try
        {
            string? user = null, oldPassword = null, newPassword = null;
            var seq = new AsnReader(value, AsnEncodingRules.BER).ReadSequence();
            while (seq.HasData)
            {
                var tag = seq.PeekTag();
                var text = ReadString(seq, Ctx(tag.TagValue));
                switch (tag.TagValue)
                {
                    case 0: user = text; break;
                    case 1: oldPassword = text; break;
                    case 2: newPassword = text; break;
                    default: throw new LdapProtocolException("Unknown Password Modify field.");
                }
            }
            return (user, oldPassword, newPassword);
        }
        catch (AsnContentException e)
        {
            throw new LdapProtocolException("Malformed Password Modify request.", e);
        }
    }

    private static BindRequest ReadBind(AsnReader message)
    {
        var bind = message.ReadSequence(App(0));
        if (!bind.TryReadInt32(out var version)) throw new LdapProtocolException("Invalid bind version.");
        var name = ReadString(bind);
        var auth = bind.PeekTag();
        var request = ReadAuthentication(bind, version, name, auth);
        bind.ThrowIfNotEmpty(); // one authentication choice and nothing after it
        return request;
    }

    private static BindRequest ReadAuthentication(AsnReader bind, int version, string name, Asn1Tag auth)
    {
        if (auth.TagClass == TagClass.ContextSpecific && auth.TagValue == 0)
            return new BindRequest(version, name, ReadString(bind, Ctx(0)), null);
        if (auth.TagClass == TagClass.ContextSpecific && auth.TagValue == 3)
        {
            var sasl = bind.ReadSequence(Ctx(3, true));
            var mechanism = ReadString(sasl);
            var credentials = sasl.HasData ? sasl.ReadOctetString() : null;
            sasl.ThrowIfNotEmpty();
            return new BindRequest(version, name, null, mechanism, credentials);
        }
        // Microsoft's "Sicily" choices: [9] package discovery, [10] NTLM negotiate, [11] NTLM response. A Windows
        // client sends them when it wants integrated authentication and the server offers no SASL mechanism.
        if (auth.TagClass == TagClass.ContextSpecific && auth.TagValue is 9 or 10 or 11)
        {
            bind.ReadOctetString(Ctx(auth.TagValue));
            return new BindRequest(version, name, null, BindRequest.Sicily);
        }
        throw new LdapProtocolException($"Unknown authentication choice {auth}.");
    }

    private static UnbindRequest ReadUnbind(AsnReader message)
    {
        message.ReadNull(App(2, false));
        return new UnbindRequest();
    }

    private static AbandonRequest ReadAbandon(AsnReader message)
    {
        if (!message.TryReadInt32(out var id, App(16, false))) throw new LdapProtocolException("Invalid abandon id.");
        return new AbandonRequest(id);
    }

    private static SearchRequest ReadSearch(AsnReader message)
    {
        var search = message.ReadSequence(App(3));
        var baseDn = ReadString(search);
        var scope = search.ReadEnumeratedValue<SearchScope>();
        if (!Enum.IsDefined(scope)) throw new LdapProtocolException($"Unknown search scope {(int)scope}.");
        search.ReadEnumeratedBytes(); // derefAliases: the in-memory directory has no aliases
        if (!search.TryReadInt32(out var sizeLimit) || !search.TryReadInt32(out var timeLimit))
            throw new LdapProtocolException("Invalid search limits.");
        var typesOnly = search.ReadBoolean();
        var filter = ReadFilter(search, 0);
        var attributes = new List<string>();
        var list = search.ReadSequence();
        while (list.HasData) attributes.Add(ReadString(list));
        return new SearchRequest(baseDn, scope, sizeLimit, timeLimit, typesOnly, filter, attributes);
    }

    private static CompareRequest ReadCompare(AsnReader message)
    {
        var compare = message.ReadSequence(App(14));
        var dn = ReadString(compare);
        var ava = compare.ReadSequence();
        return new CompareRequest(dn, ReadString(ava), ava.ReadOctetString());
    }

    private static ExtendedRequest ReadExtended(AsnReader message)
    {
        var extended = message.ReadSequence(App(23));
        var oid = ReadString(extended, Ctx(0));
        var value = extended.HasData ? extended.ReadOctetString(Ctx(1)) : null;
        return new ExtendedRequest(oid, value);
    }

    private static List<LdapControl> ReadControls(AsnReader message)
    {
        var result = new List<LdapControl>();
        var controls = message.ReadSequence(Ctx(0, true));
        while (controls.HasData)
        {
            var control = controls.ReadSequence();
            var oid = ReadString(control);
            var critical = false;
            byte[]? value = null;
            if (control.HasData && control.PeekTag() == Asn1Tag.Boolean) critical = control.ReadBoolean();
            if (control.HasData) value = control.ReadOctetString();
            result.Add(new LdapControl(oid, critical, value));
        }
        return result;
    }

    private static LdapFilter ReadFilter(AsnReader reader, int depth)
    {
        if (depth > MaxFilterDepth) throw new LdapProtocolException("Filter is nested too deeply.");
        var tag = reader.PeekTag();
        if (tag.TagClass != TagClass.ContextSpecific) throw new LdapProtocolException($"Unexpected filter tag {tag}.");
        switch (tag.TagValue)
        {
            case 0:
            case 1:
            {
                var set = reader.ReadSequence(Ctx(tag.TagValue, true));
                var filters = new List<LdapFilter>();
                while (set.HasData) filters.Add(ReadFilter(set, depth + 1));
                return tag.TagValue == 0 ? new LdapFilter.And(filters) : new LdapFilter.Or(filters);
            }
            case 2:
            {
                var not = reader.ReadSequence(Ctx(2, true));
                var inner = ReadFilter(not, depth + 1);
                not.ThrowIfNotEmpty();
                return new LdapFilter.Not(inner);
            }
            case 3:
            case 5:
            case 6:
            case 8:
            {
                var ava = reader.ReadSequence(Ctx(tag.TagValue, true));
                var attribute = ReadString(ava);
                var value = ava.ReadOctetString();
                return tag.TagValue switch
                {
                    3 => new LdapFilter.Equality(attribute, value),
                    5 => new LdapFilter.GreaterOrEqual(attribute, value),
                    6 => new LdapFilter.LessOrEqual(attribute, value),
                    _ => new LdapFilter.Approx(attribute, value),
                };
            }
            case 4:
            {
                var sub = reader.ReadSequence(Ctx(4, true));
                var attribute = ReadString(sub);
                byte[]? initial = null, final = null;
                var any = new List<byte[]>();
                var parts = sub.ReadSequence();
                while (parts.HasData)
                {
                    var part = parts.PeekTag();
                    var value = parts.ReadOctetString(Ctx(part.TagValue));
                    switch (part.TagValue)
                    {
                        case 0: initial = value; break;
                        case 1: any.Add(value); break;
                        case 2: final = value; break;
                        default: throw new LdapProtocolException("Unknown substring choice.");
                    }
                }
                return new LdapFilter.Substrings(attribute, initial, any, final);
            }
            case 7:
                return new LdapFilter.Present(ReadString(reader, Ctx(7)));
            case 9:
            {
                var ext = reader.ReadSequence(Ctx(9, true));
                string? rule = null, attribute = null;
                byte[] value = [];
                var dnAttributes = false;
                while (ext.HasData)
                {
                    var part = ext.PeekTag();
                    switch (part.TagValue)
                    {
                        case 1: rule = ReadString(ext, Ctx(1)); break;
                        case 2: attribute = ReadString(ext, Ctx(2)); break;
                        case 3: value = ext.ReadOctetString(Ctx(3)); break;
                        case 4: dnAttributes = ext.ReadBoolean(Ctx(4)); break;
                        default: throw new LdapProtocolException("Unknown extensible match component.");
                    }
                }
                return new LdapFilter.Extensible(rule, attribute, value, dnAttributes);
            }
            default:
                throw new LdapProtocolException($"Unknown filter choice [{tag.TagValue}].");
        }
    }
}
