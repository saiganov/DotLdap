using System.Net.Security;
using System.Net.Sockets;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>One client connection: reads PDUs, keeps the bind state, runs operations against the directory.</summary>
internal sealed class LdapSession(LdapTestServer server, TcpClient client, long id)
{
    private const string VendorName = "DotLdap.Testing";

    private readonly InMemoryDirectory _directory = server.Directory;
    private readonly LdapTestServerOptions _options = server.Options;
    private Stream _stream = client.GetStream();
    private DistinguishedName? _boundDn;
    private bool _boundReadOnly; // what the bound user was when their entry was last seen; see IsReadOnly
    private bool _isTls;
    private bool _manageDsaIt; // of the request being handled; requests on a connection are handled one at a time

    public void Close() => client.Close();

    public async Task RunAsync(bool implicitTls, CancellationToken ct)
    {
        try
        {
            client.NoDelay = true;
            if (implicitTls) await StartTlsAsync(ct).ConfigureAwait(false);

            while (!ct.IsCancellationRequested)
            {
                var frame = await LdapFrameReader.ReadAsync(_stream, _options.MaxMessageSize, ct).ConfigureAwait(false);
                if (frame is null) break;
                var message = LdapDecoder.Decode(frame);
                if (!await HandleAsync(message, ct).ConfigureAwait(false)) break;
            }
        }
        catch (Exception e) when (EndsConnection(e))
        {
            // The client went away, sent garbage, or the server is stopping: drop the connection.
            if (e is LdapProtocolException) server.ReportProtocolError(id, e.Message);
        }
        catch (Exception e)
        {
            // Nothing above expects to get here. The connection is dropped, the server keeps running.
            server.ReportInternalError(e);
        }
        finally
        {
            try { await _stream.DisposeAsync().ConfigureAwait(false); } catch (Exception) { /* already closed */ }
            client.Dispose();
        }
    }

    private async Task StartTlsAsync(CancellationToken ct)
    {
        var ssl = new SslStream(_stream, leaveInnerStreamOpen: false);
        try
        {
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = server.Certificate,
                ClientCertificateRequired = false,
            }, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (!EndsConnection(e))
        {
            // Whatever the TLS stack makes of bytes that are no handshake, the connection is over: after
            // StartTLS the stream is half-way into a handshake and no LDAP answer can follow.
            throw new IOException("The TLS handshake failed.", e);
        }
        _stream = ssl;
        _isTls = true;
    }

    /// <summary>The client went away, sent something that is not LDAP, or the server is stopping.</summary>
    private static bool EndsConnection(Exception e) =>
        e is IOException or SocketException or ObjectDisposedException or OperationCanceledException
            or LdapProtocolException or System.Security.Authentication.AuthenticationException;

    /// <returns>false when the connection should be closed.</returns>
    private async Task<bool> HandleAsync(LdapMessage message, CancellationToken ct)
    {
        var context = new LdapRequestContext(id, _boundDn, _isTls, message.Request);
        // A bind first of all resets who the connection is (RFC 4511 §4.2.1). Here and not in Bind: the same
        // holds for a bind an interceptor answers, in whatever way, and for one that fails before it is looked at.
        if (message.Request is BindRequest) _boundDn = null;
        try
        {
            return await DispatchAsync(message, context, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (!EndsConnection(e))
        {
            // A bug in the server or an interceptor that threw. The client gets an answer instead of a dropped
            // connection, and the test can read the exception from LdapTestServer.InternalErrors.
            server.ReportInternalError(e);
            if (message.Request.ResponseTag is null) return true;
            var failed = new LdapResult(ResultCode.Other, $"Internal error in {VendorName}: {e.GetType().Name}: {e.Message}");
            await CompleteAsync(message, context, failed, ct).ConfigureAwait(false);
            return true;
        }
    }

    private async Task<bool> DispatchAsync(LdapMessage message, LdapRequestContext context, CancellationToken ct)
    {
        var request = message.Request;

        if (request is UnbindRequest)
        {
            server.Record(context, null);
            return false;
        }
        if (request is AbandonRequest)
        {
            server.Record(context, null); // operations run to completion one at a time; nothing to abandon
            return true;
        }

        var injected = server.RunInterceptors(context);
        if (injected is not null)
        {
            await CompleteAsync(message, context, injected, ct).ConfigureAwait(false);
            return true;
        }

        // Paging and sorting are search controls. On any other operation they are as unknown as the rest.
        var ad = _directory.Layout.IsActiveDirectory;
        var critical = message.Controls.FirstOrDefault(c => c.Critical
            && !(request is SearchRequest && c.Oid is LdapEncoder.PagedResultsOid or LdapEncoder.SortRequestOid)
            && !(c.Oid == LdapEncoder.ManageDsaItOid && !ad && request is not (BindRequest or ExtendedRequest))
            && !(c.Oid == LdapEncoder.DomainScopeOid && ad && request is SearchRequest));
        // ManageDsaIT (RFC 3296): the client wants the referral entries themselves, not to be sent away. A domain
        // controller does not know the control.
        // Nor do a bind or an extended operation take it, critical or not.
        _manageDsaIt = !ad && request is not (BindRequest or ExtendedRequest) && message.Controls.Any(c => c.Oid == LdapEncoder.ManageDsaItOid);
        if (critical is not null)
        {
            var unavailable = new LdapResult(ResultCode.UnavailableCriticalExtension, $"Control {critical.Oid} is not supported.");
            await CompleteAsync(message, context, unavailable, ct).ConfigureAwait(false);
            return true;
        }

        switch (request)
        {
            case BindRequest bind:
                await CompleteAsync(message, context, Bind(bind), ct).ConfigureAwait(false);
                break;
            case SearchRequest search:
                var (searchResult, controls) = await SearchAsync(message, search, ct).ConfigureAwait(false);
                await CompleteAsync(message, context, searchResult, ct, controls).ConfigureAwait(false);
                break;
            case CompareRequest compare:
                await CompleteAsync(message, context, Compare(compare), ct).ConfigureAwait(false);
                break;
            case ExtendedRequest extended:
                await ExtendedAsync(message, context, extended, ct).ConfigureAwait(false);
                break;
            case AddRequest add:
                await CompleteAsync(message, context, Add(add), ct).ConfigureAwait(false);
                break;
            case ModifyRequest modify:
                await CompleteAsync(message, context, Modify(modify), ct).ConfigureAwait(false);
                break;
            case DeleteRequest delete:
                await CompleteAsync(message, context, Delete(delete), ct).ConfigureAwait(false);
                break;
            case ModifyDnRequest rename:
                await CompleteAsync(message, context, ModifyDn(rename), ct).ConfigureAwait(false);
                break;
            default:
                var unwilling = new LdapResult(ResultCode.UnwillingToPerform, $"{request.GetType().Name} is not supported by {VendorName}.");
                await CompleteAsync(message, context, unwilling, ct).ConfigureAwait(false);
                break;
        }
        return true;
    }

    /// <summary>
    /// Records the request and then sends its final response, in that order: a test that reads
    /// <see cref="LdapTestServer.Requests"/> right after its client call returns must already see the request.
    /// </summary>
    private ValueTask CompleteAsync(LdapMessage message, LdapRequestContext context, LdapResult result, CancellationToken ct,
        IReadOnlyList<LdapControl>? controls = null, string? responseOid = null, byte[]? responseValue = null)
    {
        // Encoded before it is recorded: an answer that cannot be written down (an interceptor that returned a
        // result without a message) fails here, and the request is then recorded once, with the answer it got.
        var pdu = message.Request is ExtendedRequest
            ? LdapEncoder.ExtendedResponse(message.MessageId, result, responseOid, responseValue)
            : LdapEncoder.Result(message.MessageId, message.Request.ResponseTag ?? 5, result, controls);
        server.Record(context, result);
        return SendAsync(pdu, ct);
    }

    private ValueTask SendAsync(byte[] pdu, CancellationToken ct) => _stream.WriteAsync(pdu, ct);

    // ---- Bind ------------------------------------------------------------------------------------------------

    private LdapResult Bind(BindRequest bind)
    {
        if (bind.Version != 3) return new LdapResult(ResultCode.ProtocolError, "Only LDAPv3 is supported.");
        if (bind.SaslMechanism == BindRequest.Sicily)
            return new LdapResult(ResultCode.AuthMethodNotSupported,
                $"NTLM authentication is not supported by {VendorName}; use a simple bind. "
                + "With System.DirectoryServices that is AuthenticationTypes.None instead of the default AuthenticationTypes.Secure.");
        if (!bind.IsSimple) return SaslBind(bind);

        var password = bind.Password ?? "";
        if (bind.Name.Length == 0 && password.Length == 0) return LdapResult.Success; // anonymous
        if (password.Length == 0)
            return new LdapResult(ResultCode.UnwillingToPerform, "Unauthenticated bind (a DN with an empty password) is not allowed.");

        return Authenticate(ResolveBindName(bind.Name), password);
    }

    /// <summary>
    /// SASL PLAIN (RFC 4616): "[authzid] NUL authcid NUL password". The name is a DN ("dn:" in front or not) or
    /// a user name ("u:" in front or not), which is looked up as uid. Acting for somebody else is not supported:
    /// an authorization identity has to name the user who logs in. A domain controller does not offer PLAIN, so
    /// the Active Directory flavour does not either.
    /// </summary>
    private LdapResult SaslBind(BindRequest bind)
    {
        if (!SupportsSaslPlain || !string.Equals(bind.SaslMechanism, BindRequest.Plain, StringComparison.OrdinalIgnoreCase))
            return new LdapResult(ResultCode.AuthMethodNotSupported, $"SASL mechanism {bind.SaslMechanism} is not supported.");
        // The mechanism lets a client name it first and send the credentials in a second step.
        if (bind.SaslCredentials is not { Length: > 0 } credentials) return new LdapResult(ResultCode.SaslBindInProgress);

        if (!BindRequest.TryReadPlain(credentials, out var authorization, out var name, out var password))
            return new LdapResult(ResultCode.InvalidCredentials, "SASL PLAIN: the credentials are not \"[authzid] NUL authcid NUL password\".");

        var entry = ResolveSaslName(name);
        var result = Authenticate(entry, password);
        if (result.Code != ResultCode.Success || authorization.Length == 0) return result;
        if (ResolveSaslName(authorization)?.Dn.Equals(entry!.Dn) == true) return result;
        _boundDn = null;
        return new LdapResult(ResultCode.InsufficientAccessRights, "SASL PLAIN: acting for another user (an authorization identity) is not supported.");
    }

    private bool SupportsSaslPlain => !_directory.Layout.IsActiveDirectory;

    private Entry? ResolveSaslName(string name)
    {
        if (name.StartsWith("dn:", StringComparison.OrdinalIgnoreCase))
            return DistinguishedName.TryParse(name[3..], out var dn) && !dn.IsRoot ? Here(_directory.Find(dn)) : null;
        if (!name.StartsWith("u:", StringComparison.OrdinalIgnoreCase))
        {
            if (ResolveBindName(name) is { } byDn) return byDn;
        }
        else name = name[2..];
        return TheOneHere(new LdapFilter.Equality("uid", Utf8.Bytes(name)));
    }

    /// <summary>
    /// An entry behind a referral entry is another server's: to this one it does not exist (RFC 3296 §5.6.1),
    /// neither as someone to log in nor as a second bearer of a name that would make a user here ambiguous.
    /// </summary>
    private Entry? Here(Entry? entry) => entry is not null && _directory.ReferralAtOrAbove(entry.Dn) is null ? entry : null;

    /// <summary>The entry a name stands for when exactly one entry of this server has it.</summary>
    private Entry? TheOneHere(LdapFilter filter)
    {
        var matches = _directory.Search(DistinguishedName.Root, SearchScope.WholeSubtree, filter, requested: [])
            .Where(e => Here(e) is not null).Take(2).ToArray();
        return matches.Length == 1 ? matches[0] : null;
    }

    /// <summary>The checks every kind of bind ends in: the entry, its password, the state of the account.</summary>
    private LdapResult Authenticate(Entry? entry, string password)
    {
        var ad = _directory.Layout.IsActiveDirectory;
        entry = Here(entry);
        if (entry is null) return InvalidCredentials(ad, "525");
        // Active Directory reports a lockout whether or not the password is right, every other state only when it is.
        if (ad && ActiveDirectory.IsLockedOut(entry, _directory.Layout)) return InvalidCredentials(ad, "775");
        if (!PasswordVerifier.Verify(entry.GetValues("userPassword"), password)) return InvalidCredentials(ad, "52e");
        if (ad && ActiveDirectory.LogonRestriction(entry) is { } restriction) return InvalidCredentials(ad, restriction);
        // Whatever the flavour, data that marks the account as disabled or locked is honoured: the ACCOUNTDISABLE
        // bit on an entry loaded into a generic directory, pwdAccountLockedTime on one loaded into an AD one.
        if (ActiveDirectory.IsDisabled(entry) || entry.Has("pwdAccountLockedTime")) return InvalidCredentials(ad, "533");

        _boundDn = entry.Dn;
        _boundReadOnly = false;
        IsReadOnly(entry.Dn); // remembered from the start, in case the entry is gone before the first write
        return LdapResult.Success;
    }

    private static LdapResult InvalidCredentials(bool activeDirectory, string adCode) => new(
        ResultCode.InvalidCredentials,
        activeDirectory
            ? $"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data {adCode}, v2580"
            : "Invalid credentials");

    private Entry? ResolveBindName(string name)
    {
        if (DistinguishedName.TryParse(name, out var dn) && !dn.IsRoot && Here(_directory.Find(dn)) is { } byDn) return byDn;
        if (!_directory.Layout.IsActiveDirectory) return null;

        // Active Directory also accepts user@domain and DOMAIN\user in a simple bind.
        var filter = name.Contains('@')
            ? new LdapFilter.Equality("userPrincipalName", Utf8.Bytes(name))
            : new LdapFilter.Equality("sAMAccountName", Utf8.Bytes(name[(name.IndexOf('\\') + 1)..]));
        return TheOneHere(filter);
    }

    // ---- Search ----------------------------------------------------------------------------------------------

    private async Task<(LdapResult, IReadOnlyList<LdapControl>?)> SearchAsync(LdapMessage message, SearchRequest search, CancellationToken ct)
    {
        DistinguishedName? baseDn;
        if (_directory.Layout.IsActiveDirectory && search.BaseDn.StartsWith('<'))
        {
            // Active Directory also takes <GUID=...> and <SID=...> where a DN is expected. The bind check comes
            // first, so the answer does not tell an anonymous client which objects exist.
            if (RefuseAnonymousSearch() is { } refused) return (refused, null);
            if (!TryResolveAlternateDn(search.BaseDn, out baseDn))
                return (new LdapResult(ResultCode.InvalidDnSyntax, $"Invalid base DN '{search.BaseDn}'."), null);
            if (baseDn is null) return (new LdapResult(ResultCode.NoSuchObject, $"No such object: {search.BaseDn}"), null);
        }
        else if (!DistinguishedName.TryParse(search.BaseDn, out baseDn))
        {
            return (new LdapResult(ResultCode.InvalidDnSyntax, $"Invalid base DN '{search.BaseDn}'."), null);
        }

        IReadOnlyList<Entry> entries;
        IReadOnlyList<Entry> references = [];
        Func<string, bool> isOperational = _directory.IsOperational;
        var isSubschema = false;
        var sorting = message.Controls.FirstOrDefault(c => c.Oid == LdapEncoder.SortRequestOid);
        IReadOnlyList<(string Attribute, string? OrderingRule, bool Reverse)> sortKeys = [];
        if (sorting is not null)
        {
            try
            {
                sortKeys = LdapEncoder.ReadSortRequestControl(sorting.Value);
            }
            catch (LdapProtocolException e)
            {
                // The message itself is sound, so the client gets an answer and keeps its connection.
                return (new LdapResult(ResultCode.ProtocolError, e.Message), null);
            }
        }
        if (baseDn.IsRoot && search.Scope == SearchScope.BaseObject)
        {
            var rootDse = BuildRootDse();
            entries = _directory.Matches(search.Filter, rootDse) ? [rootDse] : [];
            isOperational = _ => false; // the root DSE gives everything it has to "*"
        }
        else if (_directory.FindSubschema(baseDn) is { } subschema)
        {
            if (RefuseAnonymousSearch() is { } refused) return (refused, null);
            // A leaf: a search of the entry or of its subtree finds it, a search of its children finds nothing.
            entries = search.Scope != SearchScope.SingleLevel && _directory.Matches(search.Filter, subschema)
                ? [_directory.WithComputedAttributes(subschema, [.. search.Attributes, .. sortKeys.Select(k => k.Attribute)])]
                : [];
            isOperational = _directory.IsSubschemaOperational;
            isSubschema = true;
        }
        else
        {
            if (RefuseAnonymousSearch() is { } refused) return (refused, null);
            // RFC 3296 §5.3: the URLs of a referred search say which scope the other server is to search.
            var scope = search.Scope switch { SearchScope.BaseObject => "base", SearchScope.SingleLevel => "one", _ => "sub" };
            if (Refer(baseDn, scope) is { } elsewhere) return (elsewhere, null);
            if (!baseDn.IsRoot && !_directory.Exists(baseDn))
            {
                var matched = _directory.NearestExistingAncestor(baseDn)?.ToString() ?? "";
                return (new LdapResult(ResultCode.NoSuchObject, $"No such object: {baseDn}", matched), null);
            }
            // A sort key may be a computed attribute the client did not ask to see.
            IReadOnlyList<string> needed = sortKeys.Count == 0 ? search.Attributes : [.. search.Attributes, .. sortKeys.Select(k => k.Attribute)];
            entries = _directory.Search(baseDn, search.Scope, search.Filter, needed);
            if (!_manageDsaIt && _directory.ReferralsBelow(baseDn, search.Scope) is { Count: > 0 } found)
            {
                // What lies behind a referral entry is another server's to return, the entry itself included.
                entries = entries.Where(e => !found.Any(r => e.Dn.IsWithin(r.Dn))).ToArray();
                // A domain controller asked to stay within its domain names no other servers.
                if (!message.Controls.Any(c => c.Oid == LdapEncoder.DomainScopeOid && _directory.Layout.IsActiveDirectory))
                    references = found;
            }
        }

        var result = LdapResult.Success;
        List<LdapControl>? responseControls = null;

        // Server-side sorting (RFC 2891), before any paging or size limit cuts the result.
        if (sorting is not null)
        {
            // A domain controller sorts by one attribute only. Code that asks for two works here or nowhere.
            var limit = _directory.Layout.IsActiveDirectory ? 1 : MaxKeysSortedBy;
            if (sortKeys.Count > limit)
            {
                // The sort that cannot be done: a critical control fails the search, any other leaves it unsorted.
                var failed = LdapEncoder.SortResponseControl(ResultCode.UnwillingToPerform);
                if (sorting.Critical)
                {
                    var why = _directory.Layout.IsActiveDirectory
                        ? "Active Directory sorts by one attribute only."
                        : $"At most {limit} sort keys are supported.";
                    return (new LdapResult(ResultCode.UnavailableCriticalExtension, why), [failed]);
                }
                responseControls = [failed];
            }
            else
            {
                entries = Sort(entries, sortKeys);
                responseControls = [LdapEncoder.SortResponseControl()];
            }
        }

        // Simple paged results (RFC 2696). The cookie is the offset of the next page; the search is re-run per page.
        var serverLimit = _options.MaxSearchResults;
        var paging = message.Controls.FirstOrDefault(c => c.Oid == LdapEncoder.PagedResultsOid);
        if (paging?.Value is not null)
        {
            int pageSize;
            byte[] cookie;
            try
            {
                (pageSize, cookie) = LdapEncoder.ReadPagedResultsControl(paging.Value);
            }
            catch (LdapProtocolException e)
            {
                // The message itself is sound, so the client gets an answer and keeps its connection.
                return (new LdapResult(ResultCode.ProtocolError, e.Message), null);
            }
            var offset = 0;
            if (cookie.Length > 0 && (!int.TryParse(Utf8.String(cookie), out offset) || offset < 0 || offset > entries.Count))
                return (new LdapResult(ResultCode.UnwillingToPerform, "Invalid paged results cookie."), null);
            var total = entries.Count;
            if (serverLimit > 0 && pageSize > serverLimit) pageSize = serverLimit;
            // A page size of 0 abandons the paged search: no entries, empty cookie.
            var next = pageSize <= 0 ? total : (int)Math.Min((long)offset + pageSize, total); // long: the page size may be int.MaxValue
            entries = pageSize <= 0 ? [] : entries.Skip(offset).Take(next - offset).ToArray();
            var nextCookie = next < total ? Utf8.Bytes(next.ToString(System.Globalization.CultureInfo.InvariantCulture)) : [];
            (responseControls ??= []).Add(LdapEncoder.PagedResultsControl(nextCookie));
            if (nextCookie.Length > 0 || pageSize <= 0) references = []; // they come once, with the last page
        }
        else
        {
            var limit = (search.SizeLimit, serverLimit) switch
            {
                ( > 0, > 0) => Math.Min(search.SizeLimit, serverLimit),
                ( > 0, _) => search.SizeLimit,
                _ => serverLimit,
            };
            if (limit > 0 && entries.Count > limit)
            {
                entries = entries.Take(limit).ToArray();
                result = new LdapResult(ResultCode.SizeLimitExceeded, "Size limit exceeded.");
                references = []; // the search ends here
            }
        }

        foreach (var entry in entries)
        {
            // The schema goes out whole: a client that reads it does not expect ranged retrieval there.
            var maxValues = isSubschema ? 0 : _options.MaxValuesPerAttribute ?? (_directory.Layout.IsActiveDirectory ? 1500 : 0);
            var pdu = LdapEncoder.SearchResultEntry(message.MessageId, entry.Dn.ToString(), SelectAttributes(entry, search, isOperational, maxValues));
            await SendAsync(pdu, ct).ConfigureAwait(false);
        }
        foreach (var reference in references)
        {
            // RFC 3296 §5.4: the other server searches the subtree it holds; for a search of one level that is
            // the referral entry's counterpart alone, hence the scope "base".
            var urls = ReferralUrls(reference, reference.Dn, search.Scope == SearchScope.SingleLevel ? "base" : "sub");
            await SendAsync(LdapEncoder.SearchResultReference(message.MessageId, urls), ct).ConfigureAwait(false);
        }
        return (result, responseControls);
    }

    // ---- Referrals -------------------------------------------------------------------------------------------

    /// <summary>
    /// The answer for a name this server does not serve: one at or below a referral entry (RFC 3296), or one
    /// outside every naming context when the directory has a default referral. Null when the name is ours.
    /// </summary>
    private LdapResult? Refer(DistinguishedName target, string? scope = null)
    {
        if (target.IsRoot) return null;
        if (!_manageDsaIt && _directory.ReferralAtOrAbove(target) is { } entry)
            return ReferralResult(ReferralUrls(entry, target, scope), entry.Dn.ToString());
        if (_directory.DefaultReferral is { Count: > 0 } urls && !_directory.Holds(target))
        {
            var rewritten = urls.Select(url =>
                LdapUrl.TrySplit(url, out var server, out var dn) && dn is null ? LdapUrl.Build(server, target.ToString(), scope) : url).ToArray();
            return ReferralResult(rewritten, "");
        }
        return null;
    }

    private LdapResult ReferralResult(IReadOnlyList<string> urls, string matchedDn) => _directory.Layout.IsActiveDirectory
        ? new LdapResult(ResultCode.Referral,
            $"0000202B: RefErr: DSID-03100835, data 0, {urls.Count} access points\n"
            + string.Concat(urls.Select((url, i) => $"\tref {i + 1}: '{HostOf(url)}'\n")), matchedDn, urls)
        : new LdapResult(ResultCode.Referral, "Referral", matchedDn, urls);

    /// <summary>The host of a URL without its port, as a domain controller names an access point.</summary>
    private static string HostOf(string url)
    {
        if (!LdapUrl.TrySplit(url, out var server, out _)) return url;
        var host = server[(server.IndexOf("//", StringComparison.Ordinal) + 2)..];
        var port = host.LastIndexOf(':');
        return port > host.LastIndexOf(']') ? host[..port] : host;
    }

    /// <summary>
    /// The URLs of a referral entry, made to name <paramref name="target"/> on the other server: the part of the
    /// name the referral entry stands for is replaced by the DN in the URL. A URL without a DN means "the same name".
    /// </summary>
    private static IReadOnlyList<string> ReferralUrls(Entry referral, DistinguishedName target, string? scope) =>
        referral.GetStrings("ref").Where(url => !string.IsNullOrWhiteSpace(url)).Select(url =>
        {
            // ref is a labeled URI: what follows the first space is a label for people, not for clients (RFC 3296 §2.2).
            url = url.TrimStart();
            if (url.AsSpan().IndexOfAny(' ', '\t') is > 0 and var label) url = url[..label];
            // Any other kind of URI is allowed in ref and goes out as it is.
            if (!LdapUrl.TrySplit(url, out var server, out var dn)) return url;
            var name = dn is not null && DistinguishedName.TryParse(dn, out var there)
                ? target.Rebase(referral.Dn, there).ToString()
                : dn is null ? target.ToString() : dn;
            return LdapUrl.Build(server, name, scope);
        }).ToArray();

    private LdapResult? RefuseAnonymousSearch()
    {
        if (_boundDn is not null || _options.AllowAnonymousSearch) return null;
        return _directory.Layout.IsActiveDirectory
            ? new LdapResult(ResultCode.OperationsError,
                "000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563")
            : new LdapResult(ResultCode.InsufficientAccessRights, "Anonymous search is not allowed; bind first.");
    }

    /// <summary>False when the text is not a well-formed &lt;GUID=...&gt; or &lt;SID=...&gt;; otherwise the object's DN, or null when nothing has that id.</summary>
    private bool TryResolveAlternateDn(string text, out DistinguishedName? dn)
    {
        dn = null;
        var separator = text.IndexOf('=');
        if (separator < 0 || !text.EndsWith('>')) return false;
        var kind = text[1..separator].Trim();
        var value = text[(separator + 1)..^1].Trim();

        LdapFilter filter;
        if (kind.Equals("SID", StringComparison.OrdinalIgnoreCase) && ActiveDirectory.ParseSid(value) is not null)
        {
            // As text, so that this lookup and the filter (objectSid=S-1-...) find the same objects.
            filter = new LdapFilter.Equality("objectSid", Utf8.Bytes(value));
        }
        else if (kind.Equals("GUID", StringComparison.OrdinalIgnoreCase))
        {
            // Either the usual dashed form, or the 16 bytes as stored, in hex.
            byte[] bytes;
            if (value.Contains('-') && Guid.TryParse(value, out var guid)) bytes = guid.ToByteArray();
            else if (value.Length == 32 && value.All(Uri.IsHexDigit)) bytes = Convert.FromHexString(value);
            else return false;
            filter = new LdapFilter.Equality("objectGUID", bytes);
        }
        else
        {
            return false;
        }
        var matches = _directory.Search(DistinguishedName.Root, SearchScope.WholeSubtree, filter, requested: []);
        if (matches.Count == 1) dn = matches[0].Dn;
        return true;
    }

    /// <summary>What a generic directory sorts by at most (OpenLDAP's own default is lower still).</summary>
    private const int MaxKeysSortedBy = 8;

    /// <summary>
    /// Orders entries by the sort keys. A key compares as a number or as text, whichever the attribute's syntax
    /// says; of several values the smallest counts. An entry without the attribute counts as larger than any
    /// value (RFC 2891): it comes last, and first in reverse order.
    /// Text compares without regard to case and otherwise by code point, in both flavours. A domain controller
    /// sorts by the rules of a language, but what .NET makes of those depends on the machine (ICU, NLS or
    /// neither), and a test must not pass on one machine and fail on the next.
    /// </summary>
    private IReadOnlyList<Entry> Sort(IReadOnlyList<Entry> entries, IReadOnlyList<(string Attribute, string? OrderingRule, bool Reverse)> keys)
    {
        IOrderedEnumerable<Entry>? ordered = null;
        foreach (var (attribute, _, reverse) in keys)
        {
            var name = FilterEvaluator.StripOptions(attribute);
            var numeric = _directory.IsNumber(name);
            var comparer = Comparer<SortKey?>.Create(SortKey.Compare);
            SortKey? Key(Entry entry) => entry.GetValues(name).Select(v => new SortKey(v, numeric)).Min(comparer);
            ordered = (ordered, reverse) switch
            {
                (null, false) => entries.OrderBy(Key, comparer),
                (null, true) => entries.OrderByDescending(Key, comparer),
                (not null, false) => ordered.ThenBy(Key, comparer),
                (not null, true) => ordered.ThenByDescending(Key, comparer),
            };
        }
        return ordered?.ToArray() ?? entries;
    }

    private sealed class SortKey(byte[] value, bool numeric)
    {
        private readonly System.Numerics.BigInteger? _number = numeric && Utf8.TryString(value, out var digits)
            && System.Numerics.BigInteger.TryParse(digits.Trim(), System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out var number)
                ? number
                : null;
        private readonly string? _text = Utf8.TryString(value, out var text) ? text : null;

        /// <summary>Numbers first, then text without regard to case, then binary values; no value at all is the largest.</summary>
        public static int Compare(SortKey? a, SortKey? b)
        {
            if (a is null || b is null) return (a is null ? 1 : 0) - (b is null ? 1 : 0);
            if (a._number is { } x && b._number is { } y) return x.CompareTo(y);
            if (a._number is null != b._number is null) return a._number is null ? 1 : -1;
            if (a._text is not null && b._text is not null)
            {
                var byText = string.Compare(a._text, b._text, StringComparison.OrdinalIgnoreCase);
                return byText != 0 ? byText : string.CompareOrdinal(a._text, b._text);
            }
            if (a._text is null != b._text is null) return a._text is null ? 1 : -1;
            return a.Bytes.AsSpan().SequenceCompareTo(b.Bytes);
        }

        private byte[] Bytes { get; } = value;
    }

    private IEnumerable<(string, IReadOnlyList<byte[]>)> SelectAttributes(Entry entry, SearchRequest search, Func<string, bool> isOperational, int maxValues)
    {
        var requested = search.Attributes;
        if (requested.Count == 1 && requested[0] == "1.1") yield break;
        var allUser = requested.Count == 0 || requested.Contains("*");
        var allOperational = requested.Contains("+");
        foreach (var attribute in entry.Attributes)
        {
            if (!_options.ExposeUserPassword && attribute.Name.Equals("userPassword", StringComparison.OrdinalIgnoreCase)) continue;
            var matching = requested.Where(r => FilterEvaluator.StripOptions(r).Equals(attribute.Name, StringComparison.OrdinalIgnoreCase)).ToList();
            var operational = isOperational(attribute.Name);
            if (matching.Count == 0 && !(operational ? allOperational : allUser)) continue;
            // An attribute is answered once, under the first description that asked for it. Ranges are the
            // exception: "member;range=0-4" and "member;range=5-9" are two slices and both go out.
            var ranged = matching.Where(r => ParseRange(r) is not null).ToList<string?>();
            var asked = ranged.Count > 0 ? ranged : [matching.FirstOrDefault()];

            var sent = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var description in asked)
            {
                if (Slice(attribute, description, maxValues) is not var (name, values) || !sent.Add(name)) continue;
                yield return (name, search.TypesOnly ? [] : values);
            }
        }
    }

    /// <summary>The name and values one requested description gets back, or null when its range is past the end.</summary>
    private static (string Name, IReadOnlyList<byte[]> Values)? Slice(EntryAttribute attribute, string? asked, int maxValues)
    {
        // Options are not stored, so "userCertificate;binary" asks for userCertificate and gets it back under
        // the description the client used.
        // A range option never goes back as sent: the server states the range it really returned.
        var name = asked is not null && asked.Contains(';') ? WithoutRange(asked) : attribute.Name;
        var count = attribute.Values.Count;

        // Ranged retrieval: "member;range=1500-*" asks for a slice, and an attribute with more values than
        // the server returns at once comes back as "member;range=0-1499" even when asked for plainly.
        if (ParseRange(asked) is var (low, high))
        {
            // A range that starts past the last value: the attribute is left out. (A real domain controller is
            // said to fail the whole search here; a client that stops at "-*" never gets this far.)
            if (low >= count) return null;
            var last = Math.Min(count - 1, high ?? int.MaxValue);
            if (maxValues > 0) last = (int)Math.Min(last, (long)low + maxValues - 1); // long: the limit may be int.MaxValue
            return ($"{name};range={low}-{(last == count - 1 ? "*" : last)}", attribute.Items.GetRange(low, last - low + 1));
        }
        return maxValues > 0 && count > maxValues
            ? ($"{name};range=0-{maxValues - 1}", attribute.Items.GetRange(0, maxValues))
            : (name, attribute.Items);
    }

    private static string WithoutRange(string description) =>
        string.Join(';', description.Split(';').Where(part => !part.TrimStart().StartsWith("range=", StringComparison.OrdinalIgnoreCase)));

    private static (int Low, int? High)? ParseRange(string? requested)
    {
        const string option = ";range=";
        var start = requested?.IndexOf(option, StringComparison.OrdinalIgnoreCase) ?? -1;
        if (start < 0) return null;
        var bounds = requested![(start + option.Length)..].Split(';')[0].Split('-');
        if (bounds.Length != 2 || !int.TryParse(bounds[0], out var low) || low < 0) return null;
        if (bounds[1] == "*") return (low, null);
        return int.TryParse(bounds[1], out var high) && high >= low ? (low, high) : null;
    }

    private Entry BuildRootDse()
    {
        var layout = _directory.Layout;
        // A referral entry at the top is a name another server holds, not a naming context of this one.
        var contexts = _directory.NamingContexts.Where(dn => _directory.ReferralAtOrAbove(dn) is null).Select(dn => dn.ToString()).ToArray();
        var rootDse = new Entry(DistinguishedName.Root)
            .Set("objectClass", "top")
            .Set("namingContexts", contexts)
            .Set("supportedLDAPVersion", "3")
            .Set("subschemaSubentry", _directory.SubschemaDn.ToString())
            .Set("supportedControl", LdapEncoder.PagedResultsOid, LdapEncoder.SortRequestOid,
                layout.IsActiveDirectory ? LdapEncoder.DomainScopeOid : LdapEncoder.ManageDsaItOid)
            .Set("supportedExtension", SupportedExtensions())
            .Set("vendorName", VendorName)
            .Set("vendorVersion", typeof(LdapTestServer).Assembly.GetName().Version?.ToString() ?? "0");
        if (SupportsSaslPlain) rootDse.Set("supportedSASLMechanisms", BindRequest.Plain);
        if (layout.IsActiveDirectory)
        {
            rootDse.Set("defaultNamingContext", layout.BaseDn.ToString())
                .Set("rootDomainNamingContext", layout.BaseDn.ToString())
                .Set("schemaNamingContext", "CN=Schema,CN=Configuration," + layout.BaseDn)
                .Set("dnsHostName", "dc1." + layout.DomainName)
                .Set("supportedCapabilities", "1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670");
        }
        return rootDse;
    }

    // ---- Add / Modify / Delete / ModifyDN --------------------------------------------------------------------

    /// <summary>
    /// Writes need an authenticated connection, and a user who is not marked read-only
    /// (<see cref="InMemoryDirectory.SetReadOnly"/>). There are no ACLs beyond that.
    /// </summary>
    private LdapResult? RefuseUnlessBound() => _boundDn is null
        ? _directory.Layout.IsActiveDirectory
            ? new LdapResult(ResultCode.OperationsError,
                "000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563")
            : new LdapResult(ResultCode.StrongerAuthRequired, "modifications require authentication")
        : RefuseIfReadOnly();

    private LdapResult? RefuseIfReadOnly() => _boundDn is null || !IsReadOnly(_boundDn)
        ? null
        : _directory.Layout.IsActiveDirectory
            ? new LdapResult(ResultCode.InsufficientAccessRights,
                "00002098: SecErr: DSID-03150F94, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0")
            : new LdapResult(ResultCode.InsufficientAccessRights, $"Insufficient access: {_boundDn} is a read-only user.");

    /// <summary>
    /// The mark is read on every request, so that a test can set and lift it on an open connection. A connection
    /// keeps the DN it bound with; once no entry has that name (the user was renamed or deleted by someone else),
    /// the connection stays what it was when the entry was last seen, instead of quietly gaining the right to write.
    /// </summary>
    private bool IsReadOnly(DistinguishedName boundDn)
    {
        if (_directory.ReadOnlyState(boundDn) is { } now) _boundReadOnly = now;
        return _boundReadOnly;
    }

    /// <summary>
    /// Active Directory lets anyone who knows a password change it: delete the old <c>unicodePwd</c>, add the new
    /// one, nothing else in the request. A read-only user may do that too.
    /// </summary>
    private bool IsPasswordChange(ModifyRequest modify) =>
        _directory.Layout.IsActiveDirectory
        && modify.Changes is [{ Operation: ModificationType.Delete } delete, { Operation: ModificationType.Add } add]
        && IsUnicodePwd(delete.Attribute.Name) && IsUnicodePwd(add.Attribute.Name);

    private static bool IsUnicodePwd(string attribute) =>
        FilterEvaluator.StripOptions(attribute).Equals("unicodePwd", StringComparison.OrdinalIgnoreCase);

    private static LdapResult InvalidDn(string dn) => new(ResultCode.InvalidDnSyntax, $"Invalid DN '{dn}'.");

    /// <summary>
    /// A bound client that names an entry another server holds is sent there before anything else is looked at:
    /// whether it may write here does not matter. A client that has not bound is told to bind first.
    /// </summary>
    private LdapResult? ReferBound(string name) =>
        _boundDn is not null && DistinguishedName.TryParse(name, out var dn) ? Refer(dn) : null;

    private LdapResult Add(AddRequest add)
    {
        if (ReferBound(add.Dn) is { } elsewhere) return elsewhere;
        if (RefuseUnlessBound() is { } refused) return refused;
        if (!DistinguishedName.TryParse(add.Dn, out var dn)) return InvalidDn(add.Dn);
        if (add.Attributes.FirstOrDefault(a => a.Values.Count == 0) is { } empty)
            return new LdapResult(ResultCode.ProtocolError, $"add: {empty.Name} has no values.");
        if (RefuseUnicodePwdWithoutTls(add.Attributes.Select(a => a.Name)) is { } insecure) return insecure;
        var entry = new Entry(dn);
        foreach (var attribute in add.Attributes) entry.AddBinary(attribute.Name, attribute.Values.ToArray());
        return _directory.ApplyAdd(entry);
    }

    private LdapResult Modify(ModifyRequest modify)
    {
        if (ReferBound(modify.Dn) is { } elsewhere) return elsewhere;
        if (RefuseUnlessBound() is { } refused && !(_boundDn is not null && IsPasswordChange(modify))) return refused;
        if (RefuseUnicodePwdWithoutTls(modify.Changes.Select(c => c.Attribute.Name)) is { } insecure) return insecure;
        return DistinguishedName.TryParse(modify.Dn, out var dn) ? _directory.ApplyModify(dn, modify.Changes) : InvalidDn(modify.Dn);
    }

    /// <summary>Active Directory takes unicodePwd only over an encrypted connection; see <see cref="LdapTestServerOptions.RequireTlsForUnicodePwd"/>.</summary>
    private LdapResult? RefuseUnicodePwdWithoutTls(IEnumerable<string> attributes)
    {
        if (_isTls || !_options.RequireTlsForUnicodePwd || !_directory.Layout.IsActiveDirectory) return null;
        return attributes.Any(IsUnicodePwd)
            ? InMemoryDirectory.BadUnicodePwd("unicodePwd needs an encrypted connection")
            : null;
    }

    private LdapResult Delete(DeleteRequest delete)
    {
        if (ReferBound(delete.Dn) is { } elsewhere) return elsewhere;
        if (RefuseUnlessBound() is { } refused) return refused;
        return DistinguishedName.TryParse(delete.Dn, out var dn) ? _directory.ApplyDelete(dn) : InvalidDn(delete.Dn);
    }

    private LdapResult ModifyDn(ModifyDnRequest rename)
    {
        if (ReferBound(rename.Dn) is { } elsewhere) return elsewhere;
        if (RefuseUnlessBound() is { } refused) return refused;
        if (!DistinguishedName.TryParse(rename.Dn, out var dn)) return InvalidDn(rename.Dn);
        DistinguishedName? newSuperior = null;
        if (rename.NewSuperior is not null && !DistinguishedName.TryParse(rename.NewSuperior, out newSuperior)) return InvalidDn(rename.NewSuperior);
        // A move to another server is no rename (RFC 4511 §4.9), and neither is taking the name of a referral
        // entry: that name is in use on the other server, not here (RFC 3296 §5.6.2).
        // Only for a request the directory would look at twice: an entry that is there, a new RDN that is one,
        // not a move below itself. Without a new superior the default referral has no say: a renamed suffix is
        // always outside every naming context, and still here.
        var parent = newSuperior ?? dn.Parent;
        if (parent is not null && _directory.Exists(dn)
            && DistinguishedName.TryParse(rename.NewRdn, out var rdn) && rdn.Rdns.Count == 1
            && DistinguishedName.Join(rdn.Rdns[0], parent) is var renamed
            && !parent.IsWithin(dn)
            && (newSuperior is not null ? Refer(renamed) is not null : !_manageDsaIt && _directory.ReferralAtOrAbove(renamed) is not null))
            return new LdapResult(ResultCode.AffectsMultipleDsas, $"'{renamed}' is held by another server.");
        return _directory.ApplyModifyDn(dn, rename.NewRdn, rename.DeleteOldRdn, newSuperior);
    }

    /// <summary>Password Modify (RFC 3062): a user changes their own password, or a bound user sets someone else's.</summary>
    private LdapResult PasswordModify(ExtendedRequest extended)
    {
        string? identity, oldPassword, newPassword;
        try
        {
            (identity, oldPassword, newPassword) = LdapDecoder.ReadPasswordModify(extended.Value);
        }
        catch (LdapProtocolException e)
        {
            return new LdapResult(ResultCode.ProtocolError, e.Message);
        }
        if (newPassword is null)
            return new LdapResult(ResultCode.UnwillingToPerform, "The server does not generate passwords; send a new password.");

        // Without a bind, knowing the old password is the only proof of identity. Checked before the user is
        // looked up, so the answer does not tell an anonymous client which users exist.
        if (_boundDn is null && oldPassword is null) return RefuseUnlessBound()!;
        var named = identity is null ? null : identity.StartsWith("dn:", StringComparison.OrdinalIgnoreCase) ? identity[3..] : identity;
        // A bound client that names a user another server holds is sent there, like for any other write and
        // before its own right to write is looked at. So is one whose own entry has since gone behind a referral
        // entry. An anonymous client, which got this far by knowing some old password, is not told where to go:
        // to it the user does not exist (below).
        if (_boundDn is not null)
        {
            var asked = named is null ? _boundDn : DistinguishedName.TryParse(named, out var dn) ? dn : null;
            if (asked is not null && Refer(asked) is { } elsewhere) return elsewhere;
        }
        // A read-only user has the same right as an anonymous client: to change a password they know.
        if (oldPassword is null && RefuseIfReadOnly() is { } readOnly) return readOnly;

        DistinguishedName? target = _boundDn;
        if (named is not null)
        {
            target = ResolveBindName(named)?.Dn; // no one behind a referral entry
            if (target is null) return new LdapResult(ResultCode.NoSuchObject, $"No such user: {named}");
        }
        if (target is null) return new LdapResult(ResultCode.UnwillingToPerform, "No user given and the connection is anonymous.");
        return _directory.ApplySetPassword(target, oldPassword, newPassword);
    }

    private string[] SupportedExtensions()
    {
        var extensions = new List<string> { ExtendedRequest.WhoAmI };
        if (server.Certificate is not null) extensions.Add(ExtendedRequest.StartTls);
        if (!_directory.Layout.IsActiveDirectory) extensions.Add(ExtendedRequest.PasswordModify);
        return extensions.ToArray();
    }

    // ---- Compare / Extended ----------------------------------------------------------------------------------

    private LdapResult Compare(CompareRequest compare)
    {
        if (_boundDn is null && !_options.AllowAnonymousSearch)
            return new LdapResult(ResultCode.InsufficientAccessRights, "Anonymous compare is not allowed; bind first.");
        if (!DistinguishedName.TryParse(compare.Dn, out var dn)) return new LdapResult(ResultCode.InvalidDnSyntax);
        if (Refer(dn) is { } elsewhere) return elsewhere;
        var matches = _directory.Search(dn, SearchScope.BaseObject, new LdapFilter.Present("objectClass"), [compare.Attribute]);
        if (matches.Count == 0) return new LdapResult(ResultCode.NoSuchObject);
        var equal = matches[0].GetValues(compare.Attribute).Any(v => FilterEvaluator.ValueEquals(compare.Attribute, v, compare.Value));
        return new LdapResult(equal ? ResultCode.CompareTrue : ResultCode.CompareFalse);
    }

    private async Task ExtendedAsync(LdapMessage message, LdapRequestContext context, ExtendedRequest extended, CancellationToken ct)
    {
        switch (extended.Oid)
        {
            case ExtendedRequest.StartTls when server.Certificate is not null && !_isTls:
                await CompleteAsync(message, context, LdapResult.Success, ct, responseOid: ExtendedRequest.StartTls).ConfigureAwait(false);
                await StartTlsAsync(ct).ConfigureAwait(false);
                break;
            case ExtendedRequest.StartTls:
                var refused = _isTls
                    ? new LdapResult(ResultCode.OperationsError, "TLS is already established.")
                    : new LdapResult(ResultCode.ProtocolError, "StartTLS is not enabled on this server.");
                await CompleteAsync(message, context, refused, ct).ConfigureAwait(false);
                break;
            // RFC 3062 is an OpenLDAP-world operation; Active Directory does not implement it (it uses unicodePwd).
            case ExtendedRequest.PasswordModify when !_directory.Layout.IsActiveDirectory:
                await CompleteAsync(message, context, PasswordModify(extended), ct).ConfigureAwait(false);
                break;
            case ExtendedRequest.WhoAmI:
                var identity = _boundDn is null ? "" : "dn:" + _boundDn;
                await CompleteAsync(message, context, LdapResult.Success, ct, responseValue: Utf8.Bytes(identity)).ConfigureAwait(false);
                break;
            default:
                var unknown = new LdapResult(ResultCode.ProtocolError, $"Extended operation {extended.Oid} is not supported.");
                await CompleteAsync(message, context, unknown, ct).ConfigureAwait(false);
                break;
        }
    }
}
