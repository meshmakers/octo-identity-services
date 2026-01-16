using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IdentityServices.IntegrationTests.Infrastructure;

public class TestAuthHandlerOptions : AuthenticationSchemeOptions
{
    public string DefaultUserId { get; set; } = "test-user-id";
    public string DefaultUserName { get; set; } = "Test User";
    public string DefaultEmail { get; set; } = "test@example.com";
    public IEnumerable<string> Scopes { get; set; } = new[] { "IdentityApiFullAccess" };
    public IEnumerable<string> Roles { get; set; } = Array.Empty<string>();
}

public class TestAuthHandler : AuthenticationHandler<TestAuthHandlerOptions>
{
    public const string SchemeName = "TestScheme";

    public TestAuthHandler(
        IOptionsMonitor<TestAuthHandlerOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, Options.DefaultUserId),
            new(ClaimTypes.Name, Options.DefaultUserName),
            new(ClaimTypes.Email, Options.DefaultEmail)
        };

        foreach (var scope in Options.Scopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        foreach (var role in Options.Roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
