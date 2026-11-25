using DotLdap.Testing.Protocol;

namespace DotLdap.Testing.Tests.Fuzzing;

/// <summary>One test for each defect the fuzz tests found, so that it stays fixed whatever the seed.</summary>
public class FuzzFindingsTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    private static SearchRequest Everyone(LdapTestServer server) =>
        new(server.Directory.Layout.UsersDn.ToString(), SearchScope.SingleLevel, 0, 0, false, new LdapFilter.Present("uid"), ["uid"]);

    private static RawClient Bound(LdapTestServer server)
    {
        var client = new RawClient(server.Host, server.Port);
        var bind = new BindRequest(3, server.Directory.UserDn("alice").ToString(), "alice-secret", null);
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(1, bind), Patience)?.ResultCode);
        return client;
    }

    [Theory]
    [InlineData("(cn=\\-f)")] // Convert.ToByte("-f", 16) throws ArgumentException, not FormatException
    [InlineData("(cn=\\+f)")]
    [InlineData("(cn=\\0x)")]
    [InlineData("(cn=\\ 1)")]
    [InlineData("(cn=\\zz)")]
    [InlineData("(cn=\\4)")]
    public void Filter_escape_that_is_not_two_hex_digits_is_a_format_error(string text) =>
        Assert.Throws<FormatException>(() => LdapFilter.Parse(text));

    [Theory]
    [InlineData("OID.=a")]         // nothing is left of the type once the prefix is gone
    [InlineData("OID.OID.=a")]
    [InlineData("OID. =a,dc=x")]
    public void Dn_with_only_the_oid_prefix_for_a_type_is_refused(string text) =>
        Assert.False(DistinguishedName.TryParse(text, out _));

    [Theory]
    [InlineData("OID.2.5.4.3=a,dc=x", "2.5.4.3=a,dc=x")]
    [InlineData("OID.OID.2.5.4.3=a,dc=x", "2.5.4.3=a,dc=x")]   // printed and parsed again, this used to become a different name
    [InlineData("oid.\t2.5.4.3=a,dc=x", "2.5.4.3=a,dc=x")]
    public void Dn_oid_prefix_is_dropped_whole(string text, string expected)
    {
        var dn = DistinguishedName.Parse(text);
        Assert.Equal(expected, dn.ToString());
        Assert.Equal(dn, DistinguishedName.Parse(dn.ToString()));
    }

    [Fact]
    public void Dn_value_with_a_lone_surrogate_still_ends_at_the_comma()
    {
        // The unpaired half used to take the comma with it into the value.
        Assert.True(DistinguishedName.TryParse("cn=a\ud83d,dc=x", out var dn));
        Assert.Equal(2, dn.Rdns.Count);
    }

    [Fact]
    public void Bytes_after_the_message_are_a_protocol_error()
    {
        var unbind = ClientEncoder.Encode(1, new UnbindRequest());
        Assert.IsType<UnbindRequest>(LdapDecoder.Decode(unbind).Request);
        Assert.Throws<LdapProtocolException>(() => LdapDecoder.Decode(unbind.Append((byte)0x00).ToArray()));
    }

    [Fact]
    public void Malformed_paging_control_gets_an_answer_and_the_connection_stays()
    {
        using var server = LdapTestServer.Create().WithUser("alice", "alice-secret").Start();
        using var client = Bound(server);
        var broken = new LdapControl(LdapEncoder.PagedResultsOid, true, [0x8B, 0xAA, 0xB2]);

        var refused = client.Exchange(ClientEncoder.Encode(2, Everyone(server), [broken]), Patience);
        Assert.Equal((int)ResultCode.ProtocolError, refused?.ResultCode);
        Assert.Empty(server.ProtocolErrors); // the message was sound; only connections dropped for garbage are listed there

        var served = client.Exchange(ClientEncoder.Encode(3, Everyone(server)), Patience, out var entries);
        Assert.Equal(0, served?.ResultCode);
        Assert.Equal(1, entries);
    }

    [Fact]
    public void Page_size_of_int_max_on_a_later_page_returns_the_rest()
    {
        using var server = LdapTestServer.Create()
            .WithUser("alice", "alice-secret").WithUser("bob", "b").WithUser("carol", "c").WithUser("dave", "d").WithUser("erin", "e")
            .Start();
        using var client = Bound(server);

        LdapControl Page(int size, string cookie) =>
            new(LdapEncoder.PagedResultsOid, true, ClientEncoder.PagedResults(size, System.Text.Encoding.UTF8.GetBytes(cookie)));

        var first = client.Exchange(ClientEncoder.Encode(2, Everyone(server), [Page(2, "")]), Patience, out var firstPage);
        Assert.Equal(0, first?.ResultCode);
        Assert.Equal(2, firstPage);
        Assert.Equal("2", System.Text.Encoding.UTF8.GetString(first!.PagingCookie!));

        // Offset 2 plus int.MaxValue used to overflow into a negative end of page. The entries still came, but with
        // a cookie that says "there is more" and that the server itself refuses on the next request.
        var rest = client.Exchange(ClientEncoder.Encode(3, Everyone(server), [Page(int.MaxValue, "2")]), Patience, out var restPage);
        Assert.Equal(0, rest?.ResultCode);
        Assert.Equal(3, restPage);
        Assert.Empty(rest!.PagingCookie!);
    }

    [Fact]
    public void Interceptor_that_throws_becomes_an_answer_and_an_internal_error()
    {
        using var server = LdapTestServer.Create().WithUser("alice", "alice-secret").Start();
        using var client = new RawClient(server.Host, server.Port);
        using (server.Intercept(context => context.Request is ExtendedRequest ? throw new InvalidOperationException("boom") : null))
        {
            // This used to end the connection without a word, and the exception was lost.
            var failed = client.Exchange(ClientEncoder.Encode(7, new ExtendedRequest(ExtendedRequest.WhoAmI, null)), Patience);

            Assert.Equal((int)ResultCode.Other, failed?.ResultCode);
            Assert.Contains("boom", failed!.Message);
            Assert.Equal("boom", Assert.IsType<InvalidOperationException>(Assert.Single(server.InternalErrors)).Message);
            Assert.Equal(ResultCode.Other, server.Requests[^1].Result?.Code);
        }

        // The connection survived and works as before.
        var whoAmI = client.Exchange(ClientEncoder.Encode(8, new ExtendedRequest(ExtendedRequest.WhoAmI, null)), Patience);
        Assert.Equal(0, whoAmI?.ResultCode);
    }
}
