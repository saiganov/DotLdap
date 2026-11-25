namespace DotLdap.Testing.Protocol;

/// <summary>Cuts a byte stream into complete LDAPMessage PDUs using the outer BER tag and definite length.</summary>
internal static class LdapFrameReader
{
    /// <returns>The complete PDU, or null when the peer closed the connection between messages.</returns>
    public static async ValueTask<byte[]?> ReadAsync(Stream stream, int maxMessageSize, CancellationToken ct)
    {
        var header = new byte[6];
        var read = await stream.ReadAtLeastAsync(header.AsMemory(0, 2), 2, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        if (read == 0) return null;
        if (read < 2) throw new EndOfStreamException();
        if (header[0] != 0x30) throw new LdapProtocolException("LDAP message must start with a SEQUENCE tag.");

        var headerLength = 2;
        int length = header[1];
        if (length >= 0x80)
        {
            var lengthBytes = length & 0x7F;
            if (lengthBytes is 0 or > 4) throw new LdapProtocolException("Unsupported BER length encoding.");
            await stream.ReadExactlyAsync(header.AsMemory(2, lengthBytes), ct).ConfigureAwait(false);
            headerLength += lengthBytes;
            long value = 0;
            for (var i = 0; i < lengthBytes; i++) value = (value << 8) | header[2 + i];
            if (value > maxMessageSize) throw new LdapProtocolException("LDAP message is too large.");
            length = (int)value;
        }
        if (length > maxMessageSize) throw new LdapProtocolException("LDAP message is too large.");

        var message = new byte[headerLength + length];
        header.AsSpan(0, headerLength).CopyTo(message);
        await stream.ReadExactlyAsync(message.AsMemory(headerLength, length), ct).ConfigureAwait(false);
        return message;
    }
}
