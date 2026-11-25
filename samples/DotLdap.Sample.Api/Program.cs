using Microsoft.Extensions.Options;
using DotLdap.Sample.Api;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOptions<LdapSettings>()
    .Bind(builder.Configuration.GetSection("Ldap"))
    .ValidateOnStart(); // a wrong URL stops the application at startup, not at the first login
builder.Services.AddSingleton<IValidateOptions<LdapSettings>, LdapSettingsValidation>();
builder.Services.AddSingleton<DirectoryLogin>();

var app = builder.Build();

// POST /login {"user": "alice", "password": "..."}: 200 with who the user is, 401 when the directory says no,
// 403 for a user outside the allowed group, 503 when the directory cannot be reached.
app.MapPost("/login", (LoginRequest request, DirectoryLogin login) =>
{
    var outcome = login.LogIn(request.User, request.Password);
    return outcome.Status switch
    {
        LoginStatus.Success => Results.Ok(outcome.User),
        LoginStatus.NotInAllowedGroup => Results.StatusCode(StatusCodes.Status403Forbidden),
        LoginStatus.DirectoryUnavailable => Results.StatusCode(StatusCodes.Status503ServiceUnavailable),
        _ => Results.Unauthorized(),
    };
});

app.Run();

internal sealed record LoginRequest(string User, string Password);

/// <summary>The entry point, for <c>WebApplicationFactory&lt;Program&gt;</c> in the tests.</summary>
public partial class Program;
