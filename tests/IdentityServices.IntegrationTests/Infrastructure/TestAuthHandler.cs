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
    public IEnumerable<string> Scopes { get; set; } = new[] { "identityAPI.full_access" };
    public IEnumerable<string> Roles { get; set; } = Array.Empty<string>();
}

public class TestAuthHandler : AuthenticationHandler<TestAuthHandlerOptions>
{
    public const string SchemeName = "TestScheme";

    // Custom headers that can be used to override default values per-request
    public const string UserIdHeader = "X-Test-UserId";
    public const string UserNameHeader = "X-Test-UserName";
    public const string EmailHeader = "X-Test-Email";
    public const string RoleHeader = "X-Test-Role";
    public const string ScopeHeader = "X-Test-Scope";

    public TestAuthHandler(
        IOptionsMonitor<TestAuthHandlerOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Check if the request has an Authorization header
        if (!Request.Headers.ContainsKey("Authorization"))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        // Read values from headers or fall back to defaults
        var userId = GetHeaderValue(UserIdHeader, Options.DefaultUserId);
        var userName = GetHeaderValue(UserNameHeader, Options.DefaultUserName);
        var email = GetHeaderValue(EmailHeader, Options.DefaultEmail);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.Name, userName),
            new(ClaimTypes.Email, email),
            // IdentityServer uses "sub" claim for User.GetSubjectId()
            new("sub", userId)
        };

        // Add allowed_tenants claim from the route tenant so TenantAuthorizationMiddleware passes.
        // Extract the tenant ID from the first path segment (e.g., "/octosystem/v1/users" → "octosystem").
        var pathSegments = Request.Path.Value?.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (pathSegments is { Length: > 0 })
        {
            claims.Add(new Claim("allowed_tenants", pathSegments[0]));
        }

        // Add scopes from headers or defaults
        var scopes = GetHeaderValues(ScopeHeader);
        if (scopes.Any())
        {
            foreach (var scope in scopes)
            {
                claims.Add(new Claim("scope", scope));
            }
        }
        else
        {
            foreach (var scope in Options.Scopes)
            {
                claims.Add(new Claim("scope", scope));
            }
        }

        // Add roles from headers or defaults
        var roles = GetHeaderValues(RoleHeader);
        if (roles.Any())
        {
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
        }
        else
        {
            foreach (var role in Options.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
        }

        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    private string GetHeaderValue(string headerName, string defaultValue)
    {
        if (Request.Headers.TryGetValue(headerName, out var values) && values.Count > 0)
        {
            return values.First() ?? defaultValue;
        }
        return defaultValue;
    }

    private IEnumerable<string> GetHeaderValues(string headerName)
    {
        if (Request.Headers.TryGetValue(headerName, out var values))
        {
            return values.Where(v => !string.IsNullOrEmpty(v)).Cast<string>();
        }
        return Enumerable.Empty<string>();
    }
}
