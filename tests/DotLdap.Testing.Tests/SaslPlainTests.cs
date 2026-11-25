using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using DotLdap.Testing.Protocol;
using DotLdap.Testing.Tests.Fuzzing;
using Novell.Directory.Ldap.Sasl;
using BindRequest = DotLdap.Testing.Protocol.BindRequest;
using ExtendedRequest = DotLdap.Testing.Protocol.ExtendedRequest;
using ResultCode = DotLdap.Testing.Protocol.ResultCode;

namespace DotLdap.Testing.Tests;

/// <summary>
/// SASL PLAIN (RFC 4616): the name and password of a simple bind in another wrapping, which is what some
/// clients outside .NET send by default.
/// </summary>
public class SaslPlainTests
{
    private const string AliceDn = "uid=alice,ou=users,dc=example,dc=com";
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(10);

    private static LdapTestServerBuilder Generic() => LdapTestServer.Create()
        .WithUser("alice", "alice-secret")
        .WithUser("bob", "bob-secret")
        .WithUser("mallory", "mallory-secret", u => u.Disabled());

    private static byte[] Credentials(string authorization, string name, string password) =>
        Encoding.UTF8.GetBytes($"{authorization}\0{name}\0{password}");

    /// <summary>Binds and returns the result code and who the connection is afterwards.</summary>
    private static (ResultCode Code, string? BoundAs) Bind(LdapTestServer server, RawClient client, byte[]? credentials, string mechanism = "PLAIN", string name = "")
    {
        var response = client.Exchange(ClientEncoder.Encode(1, new BindRequest(3, name, null, mechanism, credentials)), Patience);
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(2, new ExtendedRequest(ExtendedRequest.WhoAmI, null)), Patience)?.ResultCode);
        return ((ResultCode)response!.ResultCode!.Value, server.Requests[^1].BoundDn?.ToString());
    }

    [Fact]
    public void A_managed_client_logs_in_with_SASL_PLAIN()
    {
        using var server = Generic().Start();
        using var connection = new Novell.Directory.Ldap.LdapConnection();
        connection.Connect(server.Host, server.Port);

        connection.Bind(new SaslPlainRequest("alice", "alice-secret"));

        Assert.True(connection.Bound);
        var results = connection.Search("dc=example,dc=com", Novell.Directory.Ldap.LdapConnection.ScopeSub, "(uid=bob)", ["uid"], false);
        Assert.True(results.HasMore());
        Assert.Equal("uid=bob,ou=users,dc=example,dc=com", results.Next().Dn);
        var bind = Assert.IsType<BindRequest>(server.Requests.First(r => r.Request is BindRequest { SaslMechanism: "PLAIN" }).Request);
        Assert.DoesNotContain("alice-secret", bind.ToString()); // the request log does not show passwords
        Assert.Empty(server.ProtocolErrors);
        Assert.Empty(server.InternalErrors);
    }

    [Fact]
    public void A_managed_client_with_a_wrong_password_is_refused()
    {
        using var server = Generic().Start();
        using var connection = new Novell.Directory.Ldap.LdapConnection();
        connection.Connect(server.Host, server.Port);

        Assert.ThrowsAny<Novell.Directory.Ldap.LdapException>(() => connection.Bind(new SaslPlainRequest("alice", "wrong")));

        // The client reports its own code for a failed SASL bind; what the server said is in its log.
        Assert.False(connection.Bound);
        Assert.Equal(ResultCode.InvalidCredentials, server.Requests.Last(r => r.Request is BindRequest).Result?.Code);
    }

    [Theory]
    [InlineData("alice")]
    [InlineData("u:alice")]
    [InlineData("U:ALICE")]
    [InlineData(AliceDn)]
    [InlineData("dn:" + AliceDn)]
    [InlineData("DN:UID=Alice, OU=users, DC=example, DC=com")]
    public void The_name_is_a_user_name_or_a_DN(string name)
    {
        using var server = Generic().Start();
        using var client = new RawClient(server.Host, server.Port);

        Assert.Equal((ResultCode.Success, AliceDn), Bind(server, client, Credentials("", name, "alice-secret")));
        // The name field of the bind request itself means nothing in a SASL bind.
        Assert.Equal((ResultCode.Success, AliceDn), Bind(server, client, Credentials("", name, "alice-secret"), "plain", "uid=bob,ou=users,dc=example,dc=com"));
    }

    [Fact]
    public void A_name_of_one_character_is_a_name()
    {
        using var server = Generic().WithUser("a", "a-secret").Start();
        using var client = new RawClient(server.Host, server.Port);

        Assert.Equal((ResultCode.Success, "uid=a,ou=users,dc=example,dc=com"), Bind(server, client, Credentials("", "a", "a-secret")));
        Assert.Equal("#1 Bind a SASL PLAIN => Success", server.Requests[^2].ToString());
    }

    [Theory]
    [InlineData("alice", "wrong")]
    [InlineData("nobody", "alice-secret")]
    [InlineData("u:" + AliceDn, "alice-secret")]     // a DN where a user name was announced
    [InlineData("dn:alice", "alice-secret")]         // and the other way round
    [InlineData("dn:", "alice-secret")]
    [InlineData("u:", "alice-secret")]
    [InlineData("mallory", "mallory-secret")]        // right password, disabled account
    [InlineData("uid=*", "alice-secret")]
    public void Wrong_credentials_are_invalid_credentials_and_leave_the_connection_anonymous(string name, string password)
    {
        using var server = Generic().Start();
        using var client = new RawClient(server.Host, server.Port);
        Assert.Equal((ResultCode.Success, "uid=bob,ou=users,dc=example,dc=com"), Bind(server, client, Credentials("", "bob", "bob-secret")));

        Assert.Equal((ResultCode.InvalidCredentials, null), Bind(server, client, Credentials("", name, password)));
    }

    [Fact]
    public void A_user_name_two_entries_share_logs_nobody_in()
    {
        using var server = Generic()
            .WithEntry("uid=alice,ou=groups,dc=example,dc=com", e => e.Set("objectClass", "account").Set("uid", "alice").Set("userPassword", "alice-secret"))
            .Start();
        using var client = new RawClient(server.Host, server.Port);

        Assert.Equal((ResultCode.InvalidCredentials, null), Bind(server, client, Credentials("", "alice", "alice-secret")));
        Assert.Equal((ResultCode.Success, AliceDn), Bind(server, client, Credentials("", "dn:" + AliceDn, "alice-secret")));
    }

    [Fact]
    public void Credentials_that_are_not_three_parts_are_refused()
    {
        using var server = Generic().Start();
        using var client = new RawClient(server.Host, server.Port);

        foreach (var broken in new[]
                 {
                     "alice-secret", "alice\0alice-secret", "\0alice\0alice-secret\0", "\0\0alice-secret", "\0alice\0", "\0\0", "\0",
                 })
            Assert.Equal((ResultCode.InvalidCredentials, null), Bind(server, client, Encoding.UTF8.GetBytes(broken)));
        Assert.Equal((ResultCode.InvalidCredentials, null), Bind(server, client, [0, 0xFF, 0xFE, 0, (byte)'x']));
        Assert.Empty(server.ProtocolErrors);
        Assert.Empty(server.InternalErrors);
    }

    [Fact]
    public void Each_part_of_the_credentials_is_checked_for_itself()
    {
        // Users whose data would let a sloppy check through: a password with a NUL in it, text that is what
        // broken UTF-8 decodes to, and an empty password.
        using var server = Generic()
            .WithUser("nul", "x\0y")
            .WithUser("a\uFFFD", "a-secret")
            .WithUser("odd", "p\uFFFD")
            .WithEntry("uid=empty,ou=users,dc=example,dc=com", e => e.Set("objectClass", "account").Set("uid", "empty").Set("userPassword", ""))
            .Start();
        using var client = new RawClient(server.Host, server.Port);
        byte[] Parts(byte[] authorization, byte[] name, byte[] password) => [.. authorization, 0, .. name, 0, .. password];

        Assert.Equal((ResultCode.InvalidCredentials, null), Bind(server, client, Parts([], "nul"u8.ToArray(), "x\0y"u8.ToArray())));              // a fourth part
        Assert.Equal((ResultCode.InvalidCredentials, null), Bind(server, client, Parts([0xFF], "alice"u8.ToArray(), "alice-secret"u8.ToArray()))); // authzid is not text
        Assert.Equal((ResultCode.InvalidCredentials, null), Bind(server, client, Parts([], [(byte)'a', 0xFF], "a-secret"u8.ToArray())));           // name is not text
        Assert.Equal((ResultCode.InvalidCredentials, null), Bind(server, client, Parts([], "odd"u8.ToArray(), [(byte)'p', 0xFF])));                // password is not text
        Assert.Equal((ResultCode.InvalidCredentials, null), Bind(server, client, Parts([], "empty"u8.ToArray(), [])));                             // no password, no login
        Assert.Equal((ResultCode.Success, "uid=odd,ou=users,dc=example,dc=com"), Bind(server, client, Credentials("", "odd", "p\uFFFD")));
    }

    [Fact]
    public void The_request_log_names_who_logged_in_and_never_the_password()
    {
        using var server = Generic().Start();
        using var client = new RawClient(server.Host, server.Port);
        string Logged(byte[]? credentials, string mechanism = "PLAIN")
        {
            Bind(server, client, credentials, mechanism);
            return server.Requests[^2].ToString();
        }

        Assert.Equal("#1 Bind u:alice SASL PLAIN => Success", Logged(Credentials("", "u:alice", "alice-secret")));
        Assert.Equal("#1 Bind alice SASL plain => Success", Logged(Credentials("u:alice", "alice", "alice-secret"), "plain"));
        Assert.Equal("#1 Bind (no name) SASL PLAIN => SaslBindInProgress", Logged(null));
        // Of credentials the server does not take, no part is shown: any of them may be the password.
        foreach (var broken in new[] { "alice-secret", "alice\0alice-secret", "alice\0alice-secret\0", "\0alice-secret\0", "\0\0alice-secret", "\0alice\0alice-secret\0" })
            Assert.Equal("#1 Bind (no name) SASL PLAIN => InvalidCredentials", Logged(Encoding.UTF8.GetBytes(broken)));
        Assert.Equal("#1 Bind (no name) SASL PLAIN => InvalidCredentials", Logged([0, (byte)'a', 0xFF, 0, (byte)'x']));
        Assert.Equal("#1 Bind (no name) SASL GSSAPI => AuthMethodNotSupported", Logged(Credentials("", "alice", "alice-secret"), "GSSAPI"));
        // The AD flavour and a wrong protocol version aside, a refusal for another reason still names who asked.
        Assert.Equal("#1 Bind nobody SASL PLAIN => InvalidCredentials", Logged(Credentials("", "nobody", "x")));
        // Nothing a client sends can make up log lines of its own: not the PLAIN name, the bind's name or the mechanism.
        const string forged = "al\r\n#9 Bind\u2028admin\u202E => Success";
        const string shown = "al??#9 Bind?admin? => Success";
        Assert.Equal($"#1 Bind {shown} SASL PLAIN => InvalidCredentials", Logged(Credentials("", forged, "x")));
        client.Exchange(ClientEncoder.Encode(1, new BindRequest(3, forged, null, "PLAIN")), Patience);
        Assert.Equal($"#1 Bind {shown} SASL PLAIN => SaslBindInProgress", server.Requests[^1].ToString());
        client.Exchange(ClientEncoder.Encode(1, new BindRequest(3, "cn=x", null, forged)), Patience);
        Assert.Equal($"#1 Bind cn=x SASL {shown} => AuthMethodNotSupported", server.Requests[^1].ToString());
        client.Exchange(ClientEncoder.Encode(1, new BindRequest(3, forged, "x", null)), Patience);
        Assert.Equal($"#1 Bind {shown} => InvalidCredentials", server.Requests[^1].ToString());
        Assert.DoesNotContain(server.Requests, r => r.ToString().Contains("secret"));

        // A simple bind is logged as before.
        using var simple = new RawClient(server.Host, server.Port);
        simple.Exchange(ClientEncoder.Encode(1, new BindRequest(3, "", "", null)), Patience);
        simple.Exchange(ClientEncoder.Encode(2, new BindRequest(3, AliceDn, "alice-secret", null)), Patience);
        Assert.Equal(["#2 Bind (anonymous) => Success", $"#2 Bind {AliceDn} => Success"], server.Requests.TakeLast(2).Select(r => r.ToString()));
    }

    [Fact]
    public void A_bind_resets_who_the_connection_is_whatever_becomes_of_it()
    {
        LdapResult? answer = null;
        var explode = false;
        using var server = Generic().Start();
        server.Intercept(context =>
        {
            if (context.Request is not BindRequest) return null;
            return explode ? throw new InvalidOperationException("boom") : answer;
        });
        using var client = new RawClient(server.Host, server.Port);
        var bob = Credentials("", "bob", "bob-secret");
        void LogInAsAlice()
        {
            (answer, explode) = (null, false);
            Assert.Equal((ResultCode.Success, AliceDn), Bind(server, client, Credentials("", "alice", "alice-secret")));
        }

        LogInAsAlice();
        answer = new LdapResult(ResultCode.Busy, "try later");
        Assert.Equal((ResultCode.Busy, null), Bind(server, client, bob));

        // An interceptor that answers "success" has not logged anybody in.
        LogInAsAlice();
        answer = LdapResult.Success;
        Assert.Equal((ResultCode.Success, null), Bind(server, client, bob));

        LogInAsAlice();
        explode = true;
        Assert.Equal((ResultCode.Other, null), Bind(server, client, bob));
        Assert.Single(server.InternalErrors);

        LogInAsAlice();
        var withControl = ClientEncoder.Encode(1, new BindRequest(3, "", null, "PLAIN", bob), [new LdapControl("1.2.3.4", true, null)]);
        Assert.Equal((int)ResultCode.UnavailableCriticalExtension, client.Exchange(withControl, Patience)?.ResultCode);
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(2, new ExtendedRequest(ExtendedRequest.WhoAmI, null)), Patience)?.ResultCode);
        Assert.Null(server.Requests[^1].BoundDn);

        // The same for a simple bind, and a request that is no bind changes nothing.
        LogInAsAlice();
        answer = new LdapResult(ResultCode.Busy, "try later");
        Assert.Equal((int)ResultCode.Busy, client.Exchange(ClientEncoder.Encode(1, new BindRequest(3, AliceDn, "alice-secret", null)), Patience)?.ResultCode);
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(2, new ExtendedRequest(ExtendedRequest.WhoAmI, null)), Patience)?.ResultCode);
        Assert.Null(server.Requests[^1].BoundDn);
        LogInAsAlice();
        using (server.FailWith<ExtendedRequest>(ResultCode.Busy))
            client.Exchange(ClientEncoder.Encode(3, new ExtendedRequest(ExtendedRequest.WhoAmI, null)), Patience);
        Assert.Equal(0, client.Exchange(ClientEncoder.Encode(2, new ExtendedRequest(ExtendedRequest.WhoAmI, null)), Patience)?.ResultCode);
        Assert.Equal(AliceDn, server.Requests[^1].BoundDn?.ToString());
    }

    [Fact]
    public void A_simple_bind_checks_what_it_always_checked()
    {
        // The checks moved into one place for both kinds of bind; these pin what the move must not change.
        (int? Code, string Message) Simple(LdapTestServer server, string user)
        {
            using var connection = new LdapConnection(new LdapDirectoryIdentifier(server.Host, server.Port))
            {
                AuthType = AuthType.Basic,
                Credential = new NetworkCredential(server.Directory.UserDn(user).ToString(), "x-secret"),
            };
            connection.SessionOptions.ProtocolVersion = 3;
            try
            {
                connection.Bind();
                return (null, "");
            }
            catch (LdapException e)
            {
                return (e.ErrorCode, server.Requests.Last(r => r.Request is BindRequest).Result?.Message ?? "");
            }
        }

        // Active Directory's own states mean nothing to a generic directory.
        using var generic = LdapTestServer.Create()
            .WithUser("locked", "x-secret", u => u.Attribute("lockoutTime", DateTime.UtcNow.ToFileTimeUtc().ToString()))
            .WithUser("mustchange", "x-secret", u => u.Attribute("pwdLastSet", "0"))
            .Start();
        Assert.Null(Simple(generic, "locked").Code);
        Assert.Null(Simple(generic, "mustchange").Code);

        // A lock in the standard attribute is honoured by Active Directory, as "account disabled".
        using var ad = LdapTestServer.Create().AsActiveDirectory()
            .WithUser("standardlock", "x-secret", u => u.Attribute("pwdAccountLockedTime", "000001010000Z"))
            .Start();
        var refused = Simple(ad, "standardlock");
        Assert.Equal(49, refused.Code); // invalidCredentials
        Assert.Contains("data 533", refused.Message);
    }

    [Fact]
    public void A_client_may_name_the_mechanism_first_and_send_the_credentials_second()
    {
        using var server = Generic().Start();
        using var client = new RawClient(server.Host, server.Port);

        Assert.Equal((ResultCode.SaslBindInProgress, null), Bind(server, client, null));
        Assert.Equal((ResultCode.SaslBindInProgress, null), Bind(server, client, []));
        Assert.Equal((ResultCode.Success, AliceDn), Bind(server, client, Credentials("", "alice", "alice-secret")));
    }

    [Fact]
    public void An_authorization_identity_has_to_be_the_user_who_logs_in()
    {
        using var server = Generic().Start();
        using var client = new RawClient(server.Host, server.Port);

        Assert.Equal((ResultCode.Success, AliceDn), Bind(server, client, Credentials("u:alice", "alice", "alice-secret")));
        Assert.Equal((ResultCode.Success, AliceDn), Bind(server, client, Credentials("dn:" + AliceDn, "alice", "alice-secret")));
        // Acting for somebody else is not supported, and a wrong password stays a wrong password.
        Assert.Equal((ResultCode.InsufficientAccessRights, null), Bind(server, client, Credentials("u:bob", "alice", "alice-secret")));
        Assert.Equal((ResultCode.InsufficientAccessRights, null), Bind(server, client, Credentials("u:nobody", "alice", "alice-secret")));
        Assert.Equal((ResultCode.InvalidCredentials, null), Bind(server, client, Credentials("u:bob", "alice", "wrong")));
    }

    [Fact]
    public void Other_mechanisms_are_not_supported_and_Active_Directory_has_no_PLAIN()
    {
        using var server = Generic().Start();
        using var client = new RawClient(server.Host, server.Port);
        foreach (var mechanism in new[] { "GSSAPI", "DIGEST-MD5", "EXTERNAL", "PLAIN-X", "" })
            Assert.Equal((ResultCode.AuthMethodNotSupported, null), Bind(server, client, Credentials("", "alice", "alice-secret"), mechanism));

        // A domain controller offers GSSAPI, GSS-SPNEGO, EXTERNAL and DIGEST-MD5, never PLAIN.
        using var ad = LdapTestServer.Create().AsActiveDirectory().WithUser("alice", "alice-secret").Start();
        using var toAd = new RawClient(ad.Host, ad.Port);
        Assert.Equal((ResultCode.AuthMethodNotSupported, null), Bind(ad, toAd, Credentials("", "alice", "alice-secret")));
    }

    [Fact]
    public void The_root_DSE_announces_PLAIN_where_it_works()
    {
        string[] Mechanisms(LdapTestServer server)
        {
            using var connection = new LdapConnection(new LdapDirectoryIdentifier(server.Host, server.Port)) { AuthType = AuthType.Anonymous };
            connection.SessionOptions.ProtocolVersion = 3;
            var rootDse = ((SearchResponse)connection.SendRequest(new System.DirectoryServices.Protocols.SearchRequest("", "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Base, "supportedSASLMechanisms"))).Entries[0];
            return rootDse.Attributes.Contains("supportedSASLMechanisms")
                ? rootDse.Attributes["supportedSASLMechanisms"].GetValues(typeof(string)).Cast<string>().ToArray()
                : [];
        }
        using var generic = Generic().Start();
        using var ad = LdapTestServer.Create().AsActiveDirectory().WithUser("alice", "alice-secret").Start();

        Assert.Equal(["PLAIN"], Mechanisms(generic));
        Assert.Empty(Mechanisms(ad));
    }

    [Fact]
    public void Anything_after_the_authentication_choice_is_a_protocol_error()
    {
        var sound = ClientEncoder.Encode(1, new BindRequest(3, "", null, "PLAIN", Credentials("", "alice", "alice-secret")));
        Assert.Equal("PLAIN", Assert.IsType<BindRequest>(LdapDecoder.Decode(sound).Request).SaslMechanism);

        // One element too many: inside the SASL credentials, after them, after a password, after an NTLM token.
        static byte[] Bind(Action<System.Formats.Asn1.AsnWriter> authentication)
        {
            var w = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.BER);
            using (w.PushSequence())
            {
                w.WriteInteger(1);
                using (w.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.Application, 0, true)))
                {
                    w.WriteInteger(3);
                    w.WriteOctetString([]);
                    authentication(w);
                }
            }
            return w.Encode();
        }
        static System.Formats.Asn1.Asn1Tag Context(int n, bool constructed = false) => new(System.Formats.Asn1.TagClass.ContextSpecific, n, constructed);
        void Sasl(System.Formats.Asn1.AsnWriter w, bool extraInside)
        {
            using (w.PushSequence(Context(3, true)))
            {
                w.WriteOctetString("PLAIN"u8);
                w.WriteOctetString("\0a\0b"u8);
                if (extraInside) w.WriteOctetString("more"u8);
            }
        }

        Assert.IsType<BindRequest>(LdapDecoder.Decode(Bind(w => Sasl(w, false))).Request);
        Assert.IsType<BindRequest>(LdapDecoder.Decode(Bind(w => w.WriteOctetString("pw"u8, Context(0)))).Request);
        Assert.IsType<BindRequest>(LdapDecoder.Decode(Bind(w => w.WriteOctetString("token"u8, Context(10)))).Request);
        Assert.Throws<LdapProtocolException>(() => LdapDecoder.Decode(Bind(w => Sasl(w, true))));
        Assert.Throws<LdapProtocolException>(() => LdapDecoder.Decode(Bind(w => { Sasl(w, false); w.WriteOctetString("more"u8); })));
        Assert.Throws<LdapProtocolException>(() => LdapDecoder.Decode(Bind(w => { w.WriteOctetString("pw"u8, Context(0)); w.WriteOctetString("more"u8); })));
        Assert.Throws<LdapProtocolException>(() => LdapDecoder.Decode(Bind(w => { w.WriteOctetString("token"u8, Context(10)); w.WriteOctetString("more"u8); })));
    }
}
