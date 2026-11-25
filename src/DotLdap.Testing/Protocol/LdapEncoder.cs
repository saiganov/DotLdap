using System.Formats.Asn1;

namespace DotLdap.Testing.Protocol;

/// <summary>Encodes server PDUs (RFC 4511) to BER.</summary>
internal static class LdapEncoder
{
    public const string PagedResultsOid = "1.2.840.113556.1.4.319";
    public const string SortRequestOid = "1.2.840.113556.1.4.473";
    public const string SortResponseOid = "1.2.840.113556.1.4.474";

    /// <summary>ManageDsaIT (RFC 3296): treat referral entries as ordinary entries.</summary>
    public const string ManageDsaItOid = "2.16.840.1.113730.3.4.2";

    /// <summary>Active Directory's LDAP_SERVER_DOMAIN_SCOPE_OID: a search that wants no references to other servers.</summary>
    public const string DomainScopeOid = "1.2.840.113556.1.4.1339";

    /// <summary>
    /// More sort keys than this in one request are not read at all: a protocol error. The server sorts by fewer
    /// still (eight, or one as Active Directory) and answers a longer list the way RFC 2891 says.
    /// </summary>
    internal const int MaxSortKeysRead = 16;

    private static Asn1Tag App(int n) => new(TagClass.Application, n, true);
    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n);

    /// <summary>Any response that is a bare LDAPResult: BindResponse (1), SearchResultDone (5), CompareResponse (15), ...</summary>
    public static byte[] Result(int messageId, int responseTag, LdapResult result, IReadOnlyList<LdapControl>? controls = null) =>
        Envelope(messageId, w =>
        {
            using (w.PushSequence(App(responseTag))) WriteResult(w, result);
        }, controls);

    public static byte[] SearchResultEntry(int messageId, string dn, IEnumerable<(string Name, IReadOnlyList<byte[]> Values)> attributes) =>
        Envelope(messageId, w =>
        {
            using (w.PushSequence(App(4)))
            {
                w.WriteOctetString(Utf8.Bytes(dn));
                using (w.PushSequence())
                {
                    foreach (var (name, values) in attributes)
                    {
                        using (w.PushSequence())
                        {
                            w.WriteOctetString(Utf8.Bytes(name));
                            using (w.PushSetOf())
                            {
                                foreach (var value in values) w.WriteOctetString(value);
                            }
                        }
                    }
                }
            }
        });

    /// <summary>SearchResultReference: a part of the search another server has to do.</summary>
    public static byte[] SearchResultReference(int messageId, IReadOnlyList<string> urls) =>
        Envelope(messageId, w =>
        {
            using (w.PushSequence(App(19)))
            {
                foreach (var url in urls) w.WriteOctetString(Utf8.Bytes(url));
            }
        });

    public static byte[] ExtendedResponse(int messageId, LdapResult result, string? oid = null, byte[]? value = null) =>
        Envelope(messageId, w =>
        {
            using (w.PushSequence(App(24)))
            {
                WriteResult(w, result);
                if (oid is not null) w.WriteOctetString(Utf8.Bytes(oid), Ctx(10));
                if (value is not null) w.WriteOctetString(value, Ctx(11));
            }
        });

    public static LdapControl PagedResultsControl(byte[] cookie)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            w.WriteInteger(0);
            w.WriteOctetString(cookie);
        }
        return new LdapControl(PagedResultsOid, false, w.Encode());
    }

    public static (int Size, byte[] Cookie) ReadPagedResultsControl(byte[] value)
    {
        try
        {
            var seq = new AsnReader(value, AsnEncodingRules.BER).ReadSequence();
            if (!seq.TryReadInt32(out var size)) throw new LdapProtocolException("Invalid page size.");
            return (size, seq.ReadOctetString());
        }
        catch (AsnContentException e)
        {
            throw new LdapProtocolException("Malformed paged results control.", e);
        }
    }

    /// <summary>Reads a server-side sort request (RFC 2891): the keys to sort by, most significant first.</summary>
    public static IReadOnlyList<(string Attribute, string? OrderingRule, bool Reverse)> ReadSortRequestControl(byte[]? value)
    {
        if (value is null) throw new LdapProtocolException("The sort request control has no value.");
        try
        {
            var keys = new List<(string, string?, bool)>();
            var reader = new AsnReader(value, AsnEncodingRules.BER);
            var list = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            while (list.HasData)
            {
                var key = list.ReadSequence();
                var attribute = Utf8.String(key.ReadOctetString());
                string? rule = null;
                var reverse = false;
                if (key.HasData && key.PeekTag() == Ctx(0)) rule = Utf8.String(key.ReadOctetString(Ctx(0)));
                if (key.HasData && key.PeekTag() == Ctx(1)) reverse = key.ReadBoolean(Ctx(1));
                key.ThrowIfNotEmpty();
                keys.Add((attribute, rule, reverse));
                if (keys.Count > MaxSortKeysRead) throw new LdapProtocolException($"A sort request with more than {MaxSortKeysRead} keys.");
            }
            if (keys.Count == 0) throw new LdapProtocolException("A sort request needs at least one key.");
            return keys;
        }
        catch (AsnContentException e)
        {
            throw new LdapProtocolException("Malformed sort request control.", e);
        }
    }

    /// <summary>The sort response control: 0 for success, otherwise an LDAP result code.</summary>
    public static LdapControl SortResponseControl(ResultCode result = ResultCode.Success)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence()) w.WriteEnumeratedValue(result);
        return new LdapControl(SortResponseOid, false, w.Encode());
    }

    private static void WriteResult(AsnWriter w, LdapResult result)
    {
        w.WriteEnumeratedValue(result.Code);
        w.WriteOctetString(Utf8.Bytes(result.MatchedDn));
        w.WriteOctetString(Utf8.Bytes(result.Message));
        if (result.Referrals is { Count: > 0 } urls)
        {
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, true)))
            {
                foreach (var url in urls) w.WriteOctetString(Utf8.Bytes(url));
            }
        }
    }

    private static byte[] Envelope(int messageId, Action<AsnWriter> writeOp, IReadOnlyList<LdapControl>? controls = null)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            w.WriteInteger(messageId);
            writeOp(w);
            if (controls is { Count: > 0 })
            {
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    foreach (var control in controls)
                    {
                        using (w.PushSequence())
                        {
                            w.WriteOctetString(Utf8.Bytes(control.Oid));
                            if (control.Critical) w.WriteBoolean(true);
                            if (control.Value is not null) w.WriteOctetString(control.Value);
                        }
                    }
                }
            }
        }
        return w.Encode();
    }
}
