using System.Security.Cryptography.X509Certificates;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>How the server listens and behaves. Set through <see cref="LdapTestServerBuilder.WithOptions"/>.</summary>
public sealed class LdapTestServerOptions
{
    /// <summary>TCP port for ldap://. 0 (default) picks a free port, which keeps parallel test runs apart.</summary>
    public int Port { get; set; }

    /// <summary>Enables StartTLS on the plain port and a separate ldaps:// listener.</summary>
    public bool EnableTls { get; set; }

    /// <summary>TCP port for ldaps:// when TLS is enabled. 0 picks a free port.</summary>
    public int LdapsPort { get; set; }

    /// <summary>Server certificate with a private key. When null and TLS is on, a self-signed one is generated for 127.0.0.1/localhost.</summary>
    public X509Certificate2? Certificate { get; set; }

    /// <summary>Let clients that have not bound (or bound anonymously) search the tree. The root DSE is always readable.</summary>
    public bool AllowAnonymousSearch { get; set; }

    /// <summary>Return userPassword in search results. Off by default, like a server with sane ACLs.</summary>
    public bool ExposeUserPassword { get; set; }

    /// <summary>
    /// Server-side cap on entries per search (or per page), like MaxPageSize=1000 in Active Directory.
    /// A non-paged search that hits it ends with sizeLimitExceeded. 0 means unlimited.
    /// </summary>
    public int MaxSearchResults { get; set; }

    /// <summary>
    /// Most values of one attribute returned at once, like MaxValRange in Active Directory. An attribute with more
    /// comes back as <c>member;range=0-1499</c> and the client asks for the rest with <c>member;range=1500-*</c>.
    /// Null (default) means 1500 in the Active Directory flavour and no limit otherwise; 0 means no limit.
    /// </summary>
    public int? MaxValuesPerAttribute { get; set; }

    /// <summary>
    /// Active Directory flavour: refuse writes to unicodePwd on a connection without TLS, as a real domain
    /// controller does. Off by default so that password tests work without certificates; turn it on together
    /// with TLS to catch code that would send a password reset over plain ldap://.
    /// </summary>
    public bool RequireTlsForUnicodePwd { get; set; }

    /// <summary>The largest LDAP message the server reads, in bytes; a client that sends more is disconnected. 4 MB by default.</summary>
    public int MaxMessageSize { get; set; } = 4 * 1024 * 1024;

    internal LdapTestServerOptions Clone() => (LdapTestServerOptions)MemberwiseClone();
}

/// <summary>What an interceptor sees before the server handles a request.</summary>
public sealed record LdapRequestContext
{
    /// <summary>An empty LdapRequestContext, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public LdapRequestContext()
    {
    }

    [System.Diagnostics.CodeAnalysis.SetsRequiredMembers]
    internal LdapRequestContext(long connectionId, DistinguishedName? boundDn, bool isTls, LdapRequest request)
    {
        ConnectionId = connectionId;
        BoundDn = boundDn;
        IsTls = isTls;
        Request = request;
    }

    /// <summary>The connection, numbered from 1 in the order they were opened.</summary>
    public long ConnectionId { get; init; }

    /// <summary>Who the connection is bound as, or null when it is anonymous.</summary>
    public DistinguishedName? BoundDn { get; init; }

    /// <summary>True on ldaps:// or after StartTLS.</summary>
    public bool IsTls { get; init; }

    /// <summary>The request.</summary>
    public required LdapRequest Request { get; init; }

    /// <summary>One line for a log: the connection and the request.</summary>
    public override string ToString() => $"#{ConnectionId} {Request}";
}

/// <summary>One handled request, kept for assertions in tests.</summary>
public sealed record RecordedRequest
{
    /// <summary>An empty RecordedRequest, to fill in with an object initializer, for example to test an interceptor without a server.</summary>
    public RecordedRequest()
    {
    }

    [System.Diagnostics.CodeAnalysis.SetsRequiredMembers]
    internal RecordedRequest(long connectionId, DistinguishedName? boundDn, bool isTls, LdapRequest request, LdapResult? result)
    {
        ConnectionId = connectionId;
        BoundDn = boundDn;
        IsTls = isTls;
        Request = request;
        Result = result;
    }

    /// <summary>The connection, numbered from 1 in the order they were opened.</summary>
    public long ConnectionId { get; init; }

    /// <summary>Who the connection was bound as when the request arrived; a bind's own record has the identity before it.</summary>
    public DistinguishedName? BoundDn { get; init; }

    /// <summary>True on ldaps:// or after StartTLS.</summary>
    public bool IsTls { get; init; }

    /// <summary>The request.</summary>
    public required LdapRequest Request { get; init; }

    /// <summary>The final answer, or null for a request that has none (unbind, abandon).</summary>
    public LdapResult? Result { get; init; }

    /// <summary>One line for a log: connection, request, result code and any referral URLs.</summary>
    public override string ToString() => $"#{ConnectionId} {Request} => {Result?.Code.ToString() ?? "(no response)"}"
        + (Result?.Referrals is { Count: > 0 } urls ? $" [{string.Join(", ", urls)}]" : "");
}

/// <summary>
/// Looks at a request before normal handling. Return a result to answer with it (fault injection: Busy,
/// Unavailable, InvalidCredentials, ...), or null to let the server handle the request as usual. A bind that
/// an interceptor answers logs nobody in, whatever the answer: the connection is anonymous afterwards.
/// </summary>
public delegate LdapResult? LdapRequestInterceptor(LdapRequestContext context);
