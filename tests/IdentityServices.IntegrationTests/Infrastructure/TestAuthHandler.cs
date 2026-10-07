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
    public IEnumerable<string> Scopes { get; set; } = new[] { "octo_api" };
    public IEnumerable<string> Roles { get; set; } = Array.Empty<string>();
}

/// <summary>
/// Roles of the default test caller: a tenant administrator, like a TenantOwners member. The tenant
/// REST API requires them since AB#5859; tests of the role gate pass their own roles per request.
/// </summary>
public static class TestAuthDefaults
{
    public static readonly IReadOnlyList<string> AdministratorRoles =
        ["UserManagement", "TenantManagement", "AdminPanelManagement"];
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

    // AB#5859: "true" = a token without any role claim (default roles are not applied).
    public const string NoRolesHeader = "X-Test-NoRoles";

    // AB#5859: simulates a client-credentials token of the given client id (no "sub", "client_id" set).
    public const string ClientCredentialsHeader = "X-Test-ClientCredentials";

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

        var clientCredentialsClientId = GetHeaderValue(ClientCredentialsHeader, string.Empty);
        var claims = new List<Claim>();
        if (string.IsNullOrEmpty(clientCredentialsClientId))
        {
            claims.Add(new Claim(ClaimTypes.NameIdentifier, userId));
            claims.Add(new Claim(ClaimTypes.Name, userName));
            claims.Add(new Claim(ClaimTypes.Email, email));
            // IdentityServer uses "sub" claim for User.GetSubjectId()
            claims.Add(new Claim("sub", userId));
        }
        else
        {
            // A client-credentials token carries no subject — the platform recognizes service tokens
            // by the absence of "sub".
            claims.Add(new Claim("client_id", clientCredentialsClientId));
        }

        // Add tenant_id claim from the route tenant so TenantAuthorizationMiddleware passes.
        // Extract the tenant ID from the first path segment (e.g., "/octosystem/v1/users" → "octosystem").
        var pathSegments = Request.Path.Value?.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (pathSegments is { Length: > 0 })
        {
            claims.Add(new Claim("tenant_id", pathSegments[0]));
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

        // Add roles from headers or defaults. Emitted as the raw JWT "role" claim — the shape the
        // identity service's own bearer handler sees (MapInboundClaims = false), so the role gate is
        // tested against real tokens, not against the mapped ClaimTypes.Role (AB#5859).
        var roles = GetHeaderValues(RoleHeader).ToList();
        var noRoles = string.Equals(GetHeaderValue(NoRolesHeader, "false"), "true", StringComparison.OrdinalIgnoreCase);
        if (!noRoles)
        {
            foreach (var role in roles.Count > 0 ? roles : Options.Roles)
            {
                claims.Add(new Claim("role", role));
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
