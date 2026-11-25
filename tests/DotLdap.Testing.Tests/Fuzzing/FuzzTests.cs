using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing.Tests.Fuzzing;

/// <summary>
/// Throws broken input at everything that reads bytes or text from outside: the frame reader, the BER decoder,
/// the request handlers behind a real socket, and the filter, DN and LDIF parsers. Whatever arrives, the answer
/// is a documented exception or an LDAP error, never a crash, a hang or a dropped connection without a reason.
/// The runs are seeded (see <see cref="FuzzSettings"/>), so a failure names the input that caused it.
/// </summary>
public class FuzzTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    private static readonly string[] SampleDns =
    [
        "dc=example,dc=com", "ou=users,dc=example,dc=com", "uid=alice,ou=users,dc=example,dc=com", "cn=admins,ou=groups,dc=example,dc=com",
    ];

    // ---- Decoder ---------------------------------------------------------------------------------------------

    [Fact]
    public void Decoder_rejects_broken_messages_with_a_protocol_error_only()
    {
        var random = new Random(FuzzSettings.Seed);
        var generator = new FuzzGenerator(random, SampleDns);
        var mutator = new Mutator(random);
        var previous = Array.Empty<byte>();

        for (var i = 0; i < FuzzSettings.Iterations(40_000); i++)
        {
            var original = ClientEncoder.Encode(generator.Message());
            var intact = i % 5 == 0;
            var input = intact ? original : mutator.Mutate(original, previous);
            previous = original;

            try
            {
                LdapMessage message;
                try
                {
                    message = LdapDecoder.Decode(input);
                }
                catch (LdapProtocolException) when (!intact)
                {
                    continue;
                }

                // What was decoded can be printed (the request log does that) and encoded again. An intact message
                // comes back byte for byte; a damaged one that still decodes settles after one round.
                _ = message.Request.ToString();
                var encoded = ClientEncoder.Encode(message);
                var expected = intact ? original : ClientEncoder.Encode(LdapDecoder.Decode(encoded));
                Assert.True(expected.AsSpan().SequenceEqual(encoded), "The message changed between decoding and encoding.");
            }
            catch (Exception e)
            {
                Assert.Fail(FuzzSettings.Describe(intact ? "decoder, intact message" : "decoder", i, input, e));
            }
        }
    }

    [Theory]
    [InlineData("30050201014200", true)]                 // unbind
    [InlineData("300C020101600702010304008000", true)]   // bind: version 3, empty name, empty password
    [InlineData("308002010142000000", true)]             // unbind in a message of indefinite length (the frame reader refuses that one)
    [InlineData("3000", false)]                          // an empty LDAPMessage
    [InlineData("3003020101", false)]                    // a message id and nothing else
    [InlineData("30050201FF4200", false)]                // a negative message id
    [InlineData("3005020101420000", false)]              // a byte after the end of the message
    [InlineData("300A02010163050400000000", false)]      // a search that ends after its base DN
    [InlineData("3005020101410000", false)]              // [APPLICATION 1] is a response, not a request
    public void Decoder_takes_or_refuses_handmade_messages(string hex, bool decodes)
    {
        var input = Convert.FromHexString(hex);
        if (decodes) Assert.NotNull(LdapDecoder.Decode(input).Request.ToString());
        else Assert.Throws<LdapProtocolException>(() => LdapDecoder.Decode(input));
    }

    [Fact]
    public void Search_with_an_unknown_scope_is_a_protocol_error()
    {
        var valid = ClientEncoder.Encode(1, new SearchRequest("", SearchScope.WholeSubtree, 0, 0, false, new LdapFilter.Present("cn"), []));
        var broken = ClientEncoder.Encode(1, new SearchRequest("", (SearchScope)99, 0, 0, false, new LdapFilter.Present("cn"), []));

        Assert.IsType<SearchRequest>(LdapDecoder.Decode(valid).Request);
        Assert.Throws<LdapProtocolException>(() => LdapDecoder.Decode(broken));
    }

    [Fact]
    public void Filter_nested_deeper_than_the_limit_is_a_protocol_error()
    {
        LdapFilter filter = new LdapFilter.Present("cn");
        for (var i = 0; i < 200; i++) filter = new LdapFilter.Not(filter);
        var input = ClientEncoder.Encode(1, new SearchRequest("", SearchScope.BaseObject, 0, 0, false, filter, []));

        Assert.Throws<LdapProtocolException>(() => LdapDecoder.Decode(input));
    }

    // ---- Frame reader ----------------------------------------------------------------------------------------

    [Fact]
    public async Task Frame_reader_cuts_the_same_frames_however_the_bytes_arrive()
    {
        const int limit = 4096;
        var random = new Random(FuzzSettings.Seed);
        var generator = new FuzzGenerator(random, SampleDns);
        var mutator = new Mutator(random);

        for (var i = 0; i < FuzzSettings.Iterations(20_000); i++)
        {
            var first = ClientEncoder.Encode(generator.Message());
            var second = ClientEncoder.Encode(generator.Message());
            byte[] input;
            switch (random.Next(4))
            {
                case 0:
                    input = new byte[random.Next(0, 40)];
                    random.NextBytes(input);
                    if (input.Length > 0 && random.Next(2) == 0) input[0] = 0x30;
                    break;
                case 1:
                    input = [.. first, .. second];
                    break;
                case 2:
                    input = [.. mutator.Mutate(first), .. second];
                    break;
                default:
                    input = mutator.Mutate(first, second);
                    break;
            }

            try
            {
                var atOnce = await Frames(new MemoryStream(input), input, limit);
                var trickled = await Frames(new TrickleStream(input, random), input, limit);
                Assert.Equal(atOnce, trickled);
            }
            catch (Exception e)
            {
                Assert.Fail(FuzzSettings.Describe("frame reader", i, input, e));
            }
        }
    }

    /// <summary>Reads frames to the end of the stream and says how it ended.</summary>
    private static async Task<string> Frames(Stream stream, byte[] input, int limit)
    {
        var summary = new StringBuilder();
        var offset = 0;
        try
        {
            while (true)
            {
                var frame = await LdapFrameReader.ReadAsync(stream, limit, CancellationToken.None);
                if (frame is null) return summary.Append("end").ToString();
                Assert.True(frame.Length <= limit + 6, "The frame is larger than the limit.");
                Assert.True(input.AsSpan(offset, frame.Length).SequenceEqual(frame), "The frame is not what was sent.");
                offset += frame.Length;
                summary.Append(frame.Length).Append(' ');
            }
        }
        catch (EndOfStreamException)
        {
            return summary.Append("cut off").ToString();
        }
        catch (LdapProtocolException e)
        {
            return summary.Append("refused: ").Append(e.Message).ToString();
        }
    }

    /// <summary>Hands the bytes out a few at a time, as a slow network would.</summary>
    private sealed class TrickleStream(byte[] data, Random random) : Stream
    {
        private int _position;

        public override int Read(byte[] buffer, int offset, int count)
        {
            var take = Math.Min(Math.Min(count, data.Length - _position), 1 + random.Next(3));
            Array.Copy(data, _position, buffer, offset, take);
            _position += take;
            return take;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    // ---- Text parsers ----------------------------------------------------------------------------------------

    private static readonly string[] FilterSamples =
    [
        "(objectClass=*)", "(&(objectClass=person)(|(uid=a*)(mail=*@example.com)))", "(!(cn=x))", "(cn~=smith)",
        "(uidNumber>=1000)", "(uidNumber<=2000)", "(cn=a*b*c)", "(cn=*a*)", "(cn=)", "(&)", "(|)", "uid=bare",
        "(memberOf:1.2.840.113556.1.4.1941:=cn=g,dc=example,dc=com)", "(userAccountControl:1.2.840.113556.1.4.803:=2)",
        "(cn:dn:caseIgnoreMatch:=x)", "(:dn:2.5.13.2:=x)", "(cn=\\28escaped\\29\\2a\\5c\\00)", "(cn=\\ff\\fe)",
    ];

    [Fact]
    public void Filter_parser_refuses_broken_text_with_a_format_error_only()
    {
        var random = new Random(FuzzSettings.Seed);
        var mutator = new TextMutator(random);
        var generator = new FuzzGenerator(random, SampleDns);

        for (var i = 0; i < FuzzSettings.Iterations(40_000); i++)
        {
            var text = random.Next(4) == 0 ? generator.Filter(0).ToString() : FilterSamples[random.Next(FilterSamples.Length)];
            if (i >= FilterSamples.Length) text = mutator.Mutate(text);
            else text = FilterSamples[i]; // every sample goes through unchanged first

            try
            {
                LdapFilter filter;
                try
                {
                    filter = LdapFilter.Parse(text);
                }
                catch (FormatException) when (i >= FilterSamples.Length)
                {
                    continue;
                }
                // The text form of a parsed filter is itself a filter, and the same one.
                var printed = filter.ToString();
                Assert.Equal(printed, LdapFilter.Parse(printed).ToString());
            }
            catch (Exception e)
            {
                Assert.Fail(FuzzSettings.Describe("filter parser", i, Encoding.Unicode.GetBytes(text), e) + Environment.NewLine + text);
            }
        }
    }

    private static readonly string[] DnSamples =
    [
        "", "dc=example,dc=com", "uid=alice,ou=users,dc=example,dc=com", "CN=Smith\\, John,CN=Users,DC=corp,DC=example,DC=com",
        "cn=a+sn=b,dc=example,dc=com", "cn=\\#hash,dc=x", "cn=\\ lead\\ ,dc=x", "cn=a\\2Cb,dc=x", "OID.2.5.4.3=a,dc=x",
        "cn = spaced , dc = x", "cn=a;dc=x", "cn=\"quoted\",dc=x", "cn=Ünïcödé 名前,dc=x", "cn=a\\00b,dc=x", "cn=,dc=x", "cn=a=b,dc=x",
    ];

    [Fact]
    public void Dn_parser_never_throws_and_prints_what_it_parsed()
    {
        var random = new Random(FuzzSettings.Seed);
        var mutator = new TextMutator(random);

        for (var i = 0; i < FuzzSettings.Iterations(40_000); i++)
        {
            var text = i < DnSamples.Length ? DnSamples[i] : mutator.Mutate(DnSamples[random.Next(DnSamples.Length)]);
            try
            {
                var parsed = DistinguishedName.TryParse(text, out var dn);
                Assert.True(parsed || i >= DnSamples.Length, "A sample DN was refused.");
                if (!parsed) continue;

                // Printing and parsing again gives the same name: this is how DNs travel to clients and back.
                var printed = dn.ToString();
                Assert.True(DistinguishedName.TryParse(printed, out var again), $"'{printed}' was printed but does not parse.");
                Assert.Equal(dn.Normalized, again.Normalized);
                Assert.Equal(printed, again.ToString());
                Assert.Equal(dn.Rdns.Count, again.Rdns.Count);
            }
            catch (Exception e)
            {
                Assert.Fail(FuzzSettings.Describe("DN parser", i, Encoding.Unicode.GetBytes(text), e) + Environment.NewLine + text);
            }
        }
    }

    private const string LdifSample = """
        version: 1

        dn: dc=example,dc=com
        objectClass: domain
        dc: example

        # a comment
        dn: uid=alice,ou=users,dc=example,dc=com
        objectClass: inetOrgPerson
        cn:: QWxpY2U=
        description: folded
          line
        userCertificate;binary:: AQID

        dn:: dWlkPWJvYixkYz1leGFtcGxlLGRjPWNvbQ==
        objectClass: person
        sn: Bob

        """;

    [Fact]
    public void Ldif_reader_refuses_broken_text_with_a_format_error_only()
    {
        var random = new Random(FuzzSettings.Seed);
        var mutator = new TextMutator(random);
        Assert.Equal(3, LdifReader.Parse(LdifSample).Count);

        for (var i = 0; i < FuzzSettings.Iterations(20_000); i++)
        {
            var text = mutator.Mutate(LdifSample);
            try
            {
                foreach (var entry in LdifReader.Parse(text)) _ = entry.Dn.ToString();
            }
            catch (Exception e) when (e is FormatException or NotSupportedException)
            {
                // the two documented ways to refuse a file
            }
            catch (Exception e)
            {
                Assert.Fail(FuzzSettings.Describe("LDIF reader", i, Encoding.Unicode.GetBytes(text), e) + Environment.NewLine + text);
            }
        }
    }

    // ---- The server behind a socket --------------------------------------------------------------------------

    private static LdapTestServer StartServer(DirectoryFlavor flavor, Random random) => LdapTestServer.Create()
        .WithFlavor(flavor)
        .WithUser("fuzzer", "fuzzer-secret")
        .WithUser("alice", "alice-secret", u => u.MemberOf("Developers").Email("alice@example.com"))
        .WithUser("bob", "bob-secret")
        .WithGroup("Engineering", "Developers")
        .WithEntry("ou=unit0,dc=example,dc=com", e => e.Set("objectClass", "organizationalUnit"))
        .AllowAnonymousSearch(random.Next(2) == 0)
        .WithMaxSearchResults(random.Next(3) == 0 ? 3 : 0)
        .WithOptions(o =>
        {
            o.ExposeUserPassword = random.Next(2) == 0;
            o.MaxValuesPerAttribute = random.Next(3) == 0 ? 2 : null;
            o.RequireTlsForUnicodePwd = random.Next(4) == 0;
        })
        .WithSchemaChecks(random.Next(2) == 0)
        .Start();

    /// <summary>
    /// The DNs the generator aims at: what is in the directory right now, so that most requests reach an entry,
    /// and a few names from the start of the round, which may be gone by now.
    /// </summary>
    private static void RefreshKnownDns(LdapTestServer server, List<string> known)
    {
        var directory = server.Directory;
        known.Clear();
        known.AddRange([server.BaseDn.ToString(), directory.UserDn("alice").ToString(), directory.GroupDn("Engineering").ToString()]);
        known.Add(directory.SubschemaDn.ToString()); // not an entry of the directory, but the server answers for it
        known.AddRange(directory.Search(DistinguishedName.Root, SearchScope.WholeSubtree, new LdapFilter.Present("objectClass"))
            .Select(entry => entry.Dn.ToString())
            .Where(dn => !dn.Contains("fuzzer", StringComparison.OrdinalIgnoreCase)) // the account the test itself binds as
            .Take(60));
    }

    private static string State(LdapTestServer server) =>
        Environment.NewLine + "Protocol errors: " + string.Join("; ", server.ProtocolErrors)
        + Environment.NewLine + "Internal errors: " + string.Join(Environment.NewLine, server.InternalErrors);

    /// <summary>A connection bound as the fuzzer's own account, or null when that account no longer accepts the bind.</summary>
    private static RawClient? ConnectAndBind(LdapTestServer server)
    {
        var client = new RawClient(server.Host, server.Port);
        if (Rebind(client, server)) return client;
        client.Dispose();
        return null;
    }

    private static bool Rebind(RawClient client, LdapTestServer server)
    {
        var bind = new BindRequest(3, server.Directory.UserDn("fuzzer").ToString(), "fuzzer-secret", null);
        return client.Exchange(ClientEncoder.Encode(1, bind), Patience)?.ResultCode == 0;
    }

    private static void AssertStillServes(LdapTestServer server)
    {
        using var client = new RawClient(server.Host, server.Port);
        var rootDse = new SearchRequest("", SearchScope.BaseObject, 0, 0, false, new LdapFilter.Present("objectClass"), []);
        var response = client.Exchange(ClientEncoder.Encode(1, rootDse), Patience);
        Assert.True(response is { ResultCode: 0 }, "After the fuzzing the server no longer answers a new client." + State(server));
    }

    [Theory]
    [InlineData(DirectoryFlavor.Generic)]
    [InlineData(DirectoryFlavor.ActiveDirectory)]
    public void Server_answers_every_request_it_can_decode(DirectoryFlavor flavor)
    {
        var random = new Random(FuzzSettings.Seed + (int)flavor);
        var mutator = new Mutator(random);

        for (var round = 0; round < FuzzSettings.Iterations(15); round++)
        {
            using var server = StartServer(flavor, random);
            var known = new List<string>();
            var generator = new FuzzGenerator(random, known);
            var client = ConnectAndBind(server);
            Assert.NotNull(client);
            try
            {
                for (var step = 0; step < 200 && client is not null; step++)
                {
                    if (step % 10 == 0) RefreshKnownDns(server, known);
                    var input = ClientEncoder.Encode(generator.Message());
                    if (random.Next(3) == 0) input = DecodableMutant(mutator, input) ?? input;
                    var message = LdapDecoder.Decode(input);
                    string Where() => FuzzSettings.Describe($"{flavor} server, round {round}", step, input) + Environment.NewLine + message.Request + State(server);

                    // Now and then the fuzzer's own account is read-only for a while: nothing it sends may get written.
                    var self = server.Directory.UserDn("fuzzer");
                    if (random.Next(20) == 0 && server.Directory.Exists(self)) server.Directory.SetReadOnly(self, random.Next(3) == 0);
                    var readOnly = server.Directory.IsReadOnly(self);

                    try
                    {
                        if (message.Request is UnbindRequest)
                        {
                            client.Send(input);
                            client.WaitForClose(Patience);
                            client.Dispose();
                            client = ConnectAndBind(server);
                            continue;
                        }
                        if (message.Request is AbandonRequest)
                        {
                            Assert.True(client.Send(input), "The server had dropped the connection. " + Where());
                            continue;
                        }

                        var response = client.Exchange(input, Patience);
                        Assert.True(response is not null, "The server dropped the connection. " + Where());
                        Assert.True(server.InternalErrors.Count == 0, "The server hit an exception it did not expect. " + Where());
                        Assert.True(server.ProtocolErrors.Count == 0, "The server called a decodable request malformed. " + Where());
                        Assert.True(response.MessageId == message.MessageId && response.Operation == message.Request.ResponseTag,
                            $"The answer [{response.Operation}] #{response.MessageId} does not belong to the request. " + Where());
                        Assert.True(response.ResultCode != (int)ResultCode.Other, $"The server answered 'other': {response.Message}. " + Where());

                        if (readOnly && IsPlainWrite(message.Request, flavor))
                            Assert.True(response.ResultCode != (int)ResultCode.Success, "A read-only user got something written. " + Where());

                        // A bind from the fuzzer changes who the connection is; go back to an account that may write.
                        if (message.Request is BindRequest && !Rebind(client, server))
                        {
                            client.Dispose();
                            client = null; // the fuzzing changed or removed that account: the round is over
                        }
                    }
                    catch (TimeoutException e)
                    {
                        Assert.Fail(e.Message + " " + Where());
                    }
                }
            }
            finally
            {
                client?.Dispose();
            }
            Assert.True(server.InternalErrors.Count == 0, $"{flavor} server, round {round}." + State(server));
            AssertStillServes(server);
        }
    }

    /// <summary>
    /// A write other than the one a read-only user may send: in the Active Directory flavour the password change
    /// that proves the old password (delete unicodePwd, add unicodePwd, nothing else).
    /// </summary>
    private static bool IsPlainWrite(LdapRequest request, DirectoryFlavor flavor)
    {
        static bool IsUnicodePwd(Modification change) =>
            FilterEvaluator.StripOptions(change.Attribute.Name).Equals("unicodePwd", StringComparison.OrdinalIgnoreCase);
        return request is AddRequest or DeleteRequest or ModifyDnRequest
            || request is ModifyRequest modify && !(flavor == DirectoryFlavor.ActiveDirectory
                && modify.Changes is [{ Operation: ModificationType.Delete } delete, { Operation: ModificationType.Add } add]
                && IsUnicodePwd(delete) && IsUnicodePwd(add));
    }

    private static byte[]? DecodableMutant(Mutator mutator, byte[] input)
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var mutant = mutator.Mutate(input);
            try
            {
                LdapDecoder.Decode(mutant);
                return mutant;
            }
            catch (LdapProtocolException)
            {
                // try another one
            }
        }
        return null;
    }

    [Fact]
    public async Task Server_drops_garbage_and_keeps_serving()
    {
        var random = new Random(FuzzSettings.Seed);
        var mutator = new Mutator(random);
        var generator = new FuzzGenerator(random, SampleDns);
        using var server = LdapTestServer.Create().WithUser("fuzzer", "fuzzer-secret").WithTls().Start();

        byte[] Noise(int length)
        {
            var bytes = new byte[length];
            random.NextBytes(bytes);
            return bytes;
        }

        for (var i = 0; i < FuzzSettings.Iterations(300); i++)
        {
            byte[] payload = random.Next(9) switch
            {
                0 => Noise(random.Next(1, 200)),
                1 => "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"u8.ToArray(),
                2 => [0x16, 0x03, 0x01, 0x00, 0x2E, 0x01, 0x00, 0x00, 0x2A, 0x03, 0x03, .. Noise(40)], // the start of a TLS handshake
                3 => [0x80, 0x2E, 0x01, 0x00, 0x02, 0x00, 0x15, 0x00, 0x00, 0x00, 0x10, .. Noise(37)], // an SSLv2 hello
                4 => [0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, .. Noise(20)],                               // "2 GB follow"
                5 => [0x30, 0x84, 0x00, 0x3F, 0xFF, 0xFF, .. Noise(100)],                              // just under the limit, then silence
                6 => [],
                _ => mutator.Mutate(ClientEncoder.Encode(generator.Message())),
            };
            var entry = random.Next(3); // plain, ldaps, plain after StartTLS
            string Where() => FuzzSettings.Describe($"garbage on {(entry == 0 ? "ldap" : entry == 1 ? "ldaps" : "StartTLS")}", i, payload) + State(server);

            using var client = new RawClient(server.Host, entry == 1 ? server.LdapsPort!.Value : server.Port);
            if (entry == 2)
            {
                var started = client.Exchange(ClientEncoder.Encode(1, new ExtendedRequest(ExtendedRequest.StartTls, null)), Patience);
                Assert.True(started is { ResultCode: 0 }, "StartTLS was refused. " + Where());
            }
            client.Send(payload);
            client.FinishSending();
            try
            {
                client.WaitForClose(Patience);
            }
            catch (TimeoutException e)
            {
                Assert.Fail(e.Message + " " + Where());
            }
            Assert.True(server.InternalErrors.Count == 0, "The server hit an exception it did not expect. " + Where());
        }

        AssertStillServes(server);

        // The TLS listener took the same abuse and still completes a real handshake.
        using var tcp = new TcpClient(server.Host, server.LdapsPort!.Value);
        using var tls = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync("localhost");
        await tls.WriteAsync(ClientEncoder.Encode(1, new ExtendedRequest(ExtendedRequest.WhoAmI, null)), TestContext.Current.CancellationToken);
        var answer = await LdapFrameReader.ReadAsync(tls, 1 << 20, TestContext.Current.CancellationToken);
        Assert.NotNull(answer);
    }
}
