using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>
/// An LDAP server that lives inside the test process. It listens on 127.0.0.1, serves an
/// <see cref="InMemoryDirectory"/>, records every request and can be told to misbehave.
/// </summary>
public sealed class LdapTestServer : IDisposable, IAsyncDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<long, (LdapSession Connection, Task Task)> _connections = new();
    private readonly ConcurrentQueue<RecordedRequest> _requests = new();
    private readonly ConcurrentQueue<string> _protocolErrors = new();
    private readonly ConcurrentQueue<Exception> _internalErrors = new();
    private readonly List<LdapRequestInterceptor> _interceptors = [];
    private readonly List<TcpListener> _listeners = [];
    private readonly List<Task> _acceptLoops = [];
    private long _nextConnectionId;
    private int _disposed;

    internal LdapTestServer(InMemoryDirectory directory, LdapTestServerOptions options)
    {
        Directory = directory;
        Options = options;
        if (options.EnableTls) Certificate = options.Certificate ?? SelfSignedCertificate.Create();

        try
        {
            Port = Listen(options.Port, implicitTls: false);
            if (options.EnableTls) LdapsPort = Listen(options.LdapsPort, implicitTls: true);
        }
        catch
        {
            // The ldaps:// port may be taken after the ldap:// listener started: stop what is already running.
            Dispose();
            throw;
        }
    }

    /// <summary>Starts configuring a server: <c>LdapTestServer.Create().WithUser("alice", "secret").Start()</c>.</summary>
    public static LdapTestServerBuilder Create() => new();

    /// <summary>The data. It can be read and changed while the server runs; changes show to the next request.</summary>
    public InMemoryDirectory Directory { get; }
    /// <summary>The address the server listens on: always the IPv4 loopback.</summary>
    public string Host => "127.0.0.1";
    /// <summary>The port of the ldap:// listener.</summary>
    public int Port { get; }

    /// <summary>Port of the ldaps:// listener, or null when TLS is off.</summary>
    public int? LdapsPort { get; }

    /// <summary>The ldap:// URL, such as <c>ldap://127.0.0.1:50123</c>.</summary>
    public string Url => $"ldap://{Host}:{Port}";
    /// <summary>The ldaps:// URL, or null when TLS is off.</summary>
    public string? LdapsUrl => LdapsPort is null ? null : $"ldaps://{Host}:{LdapsPort}";
    /// <summary>The suffix the data lives under.</summary>
    public DistinguishedName BaseDn => Directory.Layout.BaseDn;

    /// <summary>The server certificate (public part is enough for clients to trust it), or null when TLS is off.</summary>
    public X509Certificate2? Certificate { get; }

    /// <summary>The certificate in PEM form, e.g. for LDAPTLS_CACERT or a CA file.</summary>
    public string? CertificatePem => Certificate?.ExportCertificatePem();

    /// <summary>Every request handled so far, in order of completion.</summary>
    /// <remarks>
    /// The last entry is not always the request a test has just made. A client closes a connection on its own
    /// time, and the unbind it sends, which has no answer, is recorded whenever the server gets to it. Use
    /// <see cref="LastAnswer"/> for the last request that was answered, or <see cref="Last{TRequest}"/> for the
    /// last request of one type.
    /// </remarks>
    public IReadOnlyList<RecordedRequest> Requests => _requests.ToArray();

    /// <summary>
    /// The last request the server answered, or null when it has answered none. Requests without an answer
    /// (unbind, abandon) are passed over, so an old connection that closes late does not get in the way.
    /// </summary>
    /// <remarks>
    /// A request is recorded just before its answer is sent, so a client never holds an answer that is not
    /// here yet. Connections are not told apart: with several clients at work this is whichever was answered
    /// last, and <see cref="RecordedRequest.ConnectionId"/> says whose it was. Each read looks at the list
    /// anew; keep the value in a variable to assert on it more than once.
    /// </remarks>
    public RecordedRequest? LastAnswer => _requests.LastOrDefault(r => r.Result is not null);

    /// <summary>
    /// The last recorded request of type <typeparamref name="TRequest"/>, or null when there is none, e.g.
    /// <c>server.Last&lt;BindRequest&gt;()</c>. Requests of other types that came later are passed over.
    /// Answered or not: <c>Last&lt;UnbindRequest&gt;()</c> has no <see cref="RecordedRequest.Result"/>.
    /// </summary>
    public RecordedRequest? Last<TRequest>() where TRequest : LdapRequest => _requests.LastOrDefault(r => r.Request is TRequest);

    /// <summary>Malformed input seen from clients; empty in a healthy test.</summary>
    public IReadOnlyList<string> ProtocolErrors => _protocolErrors.ToArray();

    /// <summary>
    /// Exceptions the server did not expect: an interceptor that threw, or a bug in the server. The client got
    /// <see cref="ResultCode.Other"/> for that request and the server kept running. Empty in a healthy test.
    /// </summary>
    public IReadOnlyList<Exception> InternalErrors => _internalErrors.ToArray();

    /// <summary>Empties <see cref="Requests"/>, for example after the set-up part of a test.</summary>
    public void ClearRequests() => _requests.Clear();

    /// <summary>Adds an interceptor. Dispose the returned handle to remove it.</summary>
    public IDisposable Intercept(LdapRequestInterceptor interceptor)
    {
        lock (_interceptors) _interceptors.Add(interceptor);
        return new Removal(() =>
        {
            lock (_interceptors) _interceptors.Remove(interceptor);
        });
    }

    /// <summary>Answers every request of type <typeparamref name="TRequest"/> with the given result until the handle is disposed.</summary>
    public IDisposable FailWith<TRequest>(ResultCode code, string message = "Injected by test") where TRequest : LdapRequest =>
        Intercept(context => context.Request is TRequest ? new LdapResult(code, message) : null);

    internal LdapTestServerOptions Options { get; }

    internal LdapResult? RunInterceptors(LdapRequestContext context)
    {
        LdapRequestInterceptor[] interceptors;
        lock (_interceptors) interceptors = _interceptors.ToArray();
        foreach (var interceptor in interceptors)
            if (interceptor(context) is { } result) return result;
        return null;
    }

    internal void Record(LdapRequestContext context, LdapResult? result) =>
        _requests.Enqueue(new RecordedRequest(context.ConnectionId, context.BoundDn, context.IsTls, context.Request, result));

    internal void ReportProtocolError(long connectionId, string message) => _protocolErrors.Enqueue($"#{connectionId}: {message}");

    internal void ReportInternalError(Exception exception) => _internalErrors.Enqueue(exception);

    private int Listen(int port, bool implicitTls)
    {
        var listener = new TcpListener(IPAddress.Loopback, port);
        listener.Start();
        _listeners.Add(listener);
        _acceptLoops.Add(Task.Run(() => AcceptLoopAsync(listener, implicitTls)));
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private async Task AcceptLoopAsync(TcpListener listener, bool implicitTls)
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false);
                var id = Interlocked.Increment(ref _nextConnectionId);
                var connection = new LdapSession(this, client, id);
                var task = connection.RunAsync(implicitTls, _stop.Token);
                _connections[id] = (connection, task);
                _ = task.ContinueWith(_ => _connections.TryRemove(id, out var _), TaskScheduler.Default);
            }
        }
        catch (Exception e) when (e is OperationCanceledException or SocketException or InvalidOperationException)
        {
            // stopping; a listener stopped between the check and the call says "not listening" (InvalidOperationException)
        }
    }

    /// <summary>Stops listening and closes every connection.</summary>
    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    /// <summary>Stops listening and closes every connection.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _stop.Cancel();
        foreach (var listener in _listeners) listener.Stop();
        var connections = _connections.Values.ToArray();
        foreach (var (connection, _) in connections) connection.Close();
        try
        {
            await Task.WhenAll(_acceptLoops.Concat(connections.Select(c => c.Task)))
                .WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (Exception e) when (e is TimeoutException or OperationCanceledException)
        {
            // do not hang test teardown on a stuck socket
        }
        if (Options.Certificate is null) Certificate?.Dispose();
        _stop.Dispose();
    }

    private sealed class Removal(Action remove) : IDisposable
    {
        public void Dispose() => remove();
    }
}
