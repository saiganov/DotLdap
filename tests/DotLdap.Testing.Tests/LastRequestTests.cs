using DotLdap.Testing.Protocol;
using DotLdap.Testing.Tests.Fuzzing;

namespace DotLdap.Testing.Tests;

/// <summary>
/// <see cref="LdapTestServer.LastAnswer"/> and <see cref="LdapTestServer.Last{TRequest}"/>: what a test asks for
/// when it means "the request I have just made", which <c>Requests[^1]</c> is not once an unbind has come in.
/// </summary>
public class LastRequestTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    private static void WaitForRequests(LdapTestServer server, int count)
    {
        // An unbind has no answer to wait for, so the record is all there is to see.
        Assert.True(SpinWait.SpinUntil(() => server.Requests.Count >= count, Patience), $"The server did not record {count} requests.");
    }

    [Fact]
    public void A_server_that_has_answered_nothing_has_no_last_answer()
    {
        using var server = LdapTestServer.Create().WithUser("alice", "alice-secret").Start();
        Assert.Null(server.LastAnswer);
        Assert.Null(server.Last<BindRequest>());

        // an unbind alone is a request, and no answer
        using (var client = new RawClient(server.Host, server.Port))
        {
            Assert.True(client.Send(ClientEncoder.Encode(1, new UnbindRequest())));
            WaitForRequests(server, 1);
        }
        Assert.Null(server.LastAnswer);
        Assert.IsType<UnbindRequest>(server.Last<UnbindRequest>()!.Request);
    }

    [Fact]
    public void An_unbind_that_comes_after_an_answer_does_not_hide_it()
    {
        using var server = LdapTestServer.Create().WithUser("alice", "alice-secret").Start();
        var alice = server.Directory.UserDn("alice").ToString();
        using var client = new RawClient(server.Host, server.Port);

        Assert.Equal((int)ResultCode.InvalidCredentials, client.Exchange(ClientEncoder.Encode(1, new BindRequest(3, alice, "wrong", null)), Patience)?.ResultCode);
        Assert.True(client.Send(ClientEncoder.Encode(2, new UnbindRequest())));
        WaitForRequests(server, 2);

        // the case the two members are for: the last record is the unbind
        Assert.IsType<UnbindRequest>(server.Requests[^1].Request);
        Assert.Null(server.Requests[^1].Result);

        Assert.IsType<BindRequest>(server.LastAnswer!.Request);
        Assert.Equal(ResultCode.InvalidCredentials, server.LastAnswer!.Result!.Code);
        Assert.Same(server.LastAnswer, server.Last<BindRequest>());
        Assert.Null(server.Last<SearchRequest>());
    }

    [Fact]
    public void The_last_of_several_is_taken_and_the_type_narrows_the_choice()
    {
        using var server = LdapTestServer.Create().WithUser("alice", "alice-secret").Start();
        var alice = server.Directory.UserDn("alice").ToString();
        using var client = new RawClient(server.Host, server.Port);

        Assert.Equal((int)ResultCode.InvalidCredentials, client.Exchange(ClientEncoder.Encode(1, new BindRequest(3, alice, "wrong", null)), Patience)?.ResultCode);
        Assert.Equal((int)ResultCode.Success, client.Exchange(ClientEncoder.Encode(2, new BindRequest(3, alice, "alice-secret", null)), Patience)?.ResultCode);
        Assert.Equal(ResultCode.Success, server.Last<BindRequest>()!.Result!.Code);

        client.Exchange(ClientEncoder.Encode(3, new ExtendedRequest(ExtendedRequest.WhoAmI, null)), Patience);
        Assert.IsType<ExtendedRequest>(server.LastAnswer!.Request);
        Assert.Equal(ResultCode.Success, server.Last<BindRequest>()!.Result!.Code); // still the second bind
        Assert.Equal(alice, server.LastAnswer!.BoundDn?.ToString());

        // the base type takes every request
        Assert.Same(server.Requests[^1], server.Last<LdapRequest>());

        server.ClearRequests();
        Assert.Null(server.LastAnswer);
        Assert.Null(server.Last<BindRequest>());
    }

    [Fact]
    public void A_request_whose_answer_could_not_be_written_is_recorded_once_with_the_answer_it_got()
    {
        using var server = LdapTestServer.Create().WithUser("alice", "alice-secret").Start();
        using var client = new RawClient(server.Host, server.Port);

        // An answer without a message cannot be encoded. This used to leave two records for one request: the
        // answer that was never sent, and the internal error that was.
        using (server.FailWith<ExtendedRequest>(ResultCode.Busy, null!))
        {
            var answer = client.Exchange(ClientEncoder.Encode(1, new ExtendedRequest(ExtendedRequest.WhoAmI, null)), Patience);
            Assert.Equal((int)ResultCode.Other, answer?.ResultCode);
        }
        var recorded = Assert.Single(server.Requests);
        Assert.Equal(ResultCode.Other, recorded.Result!.Code);
        Assert.Same(recorded, server.LastAnswer);
        Assert.Single(server.InternalErrors);
    }

    [Fact]
    public void An_abandon_is_recorded_without_an_answer_and_does_not_hide_the_answer_before_it()
    {
        using var server = LdapTestServer.Create().WithUser("alice", "alice-secret").Start();
        var alice = server.Directory.UserDn("alice").ToString();
        using var client = new RawClient(server.Host, server.Port);

        Assert.Equal((int)ResultCode.Success, client.Exchange(ClientEncoder.Encode(1, new BindRequest(3, alice, "alice-secret", null)), Patience)?.ResultCode);
        Assert.True(client.Send(ClientEncoder.Encode(2, new AbandonRequest(1))));
        WaitForRequests(server, 2);

        Assert.IsType<AbandonRequest>(server.Requests[^1].Request);
        Assert.Null(server.Requests[^1].Result);
        Assert.Null(server.Last<AbandonRequest>()!.Result);
        Assert.IsType<BindRequest>(server.LastAnswer!.Request);

        // the connection lives on, and the next answer is the last one again
        Assert.Equal((int)ResultCode.Success, client.Exchange(ClientEncoder.Encode(3, new ExtendedRequest(ExtendedRequest.WhoAmI, null)), Patience)?.ResultCode);
        Assert.Equal(3, server.Requests.Count);
        Assert.IsType<ExtendedRequest>(server.LastAnswer!.Request);
        Assert.IsType<AbandonRequest>(server.Last<AbandonRequest>()!.Request);
    }

    [Fact]
    public void Every_request_and_context_has_a_one_line_text_of_its_own()
    {
        Assert.Equal("Compare uid=alice,ou=users,dc=example,dc=com mail",
            new Protocol.CompareRequest { Dn = "uid=alice,ou=users,dc=example,dc=com", Attribute = "mail", Value = [1, 2] }.ToString());
        Assert.Equal("Abandon 7", new Protocol.AbandonRequest { MessageId = 7 }.ToString());
        Assert.Equal("#3 Delete cn=x", new LdapRequestContext { ConnectionId = 3, Request = new Protocol.DeleteRequest { Dn = "cn=x" } }.ToString());
    }
}
