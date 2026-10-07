using System.Reflection;
using System.Security.Claims;
using FluentAssertions;
using IdentityServerPersistence;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace IdentityServices.UnitTests.Authorization;

/// <summary>
///     AB#5859: the tenant REST API policies combine the scope with a tenant role. Evaluated through the
///     real <see cref="IAuthorizationService" /> with the production policy registration and handler.
/// </summary>
public class IdentityApiAuthorizationPolicyTests
{
    private const string SystemTenantId = "octosystem";
    private const string CustomerTenantId = "customer";

    private static IAuthorizationService CreateAuthorizationService(
        IdentityApiRoleEnforcementMode mode = IdentityApiRoleEnforcementMode.Enforce)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Options.Create(new OctoSystemConfiguration { SystemTenantId = SystemTenantId }));
        var monitor = Substitute.For<IOptionsMonitor<IdentityApiAuthorizationOptions>>();
        monitor.CurrentValue.Returns(new IdentityApiAuthorizationOptions { RoleEnforcement = mode });
        services.AddSingleton(monitor);
        services.AddSingleton<IAuthorizationHandler, IdentityApiRoleAuthorizationHandler>();
        services.AddAuthorization(options => options.AddIdentityApiPolicies());
        return services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
    }

    private static ClaimsPrincipal Principal(IEnumerable<string> roles, string roleClaimType = "role",
        string scope = "octo_api", bool authenticated = true)
    {
        var claims = new List<Claim> { new("sub", "user-1"), new("scope", scope) };
        claims.AddRange(roles.Select(r => new Claim(roleClaimType, r)));
        // ClaimsIdentity keeps its default RoleClaimType (ClaimTypes.Role), exactly like the identity
        // service's bearer handler with MapInboundClaims = false — the AB#4969/AB#5539 trap.
        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticated ? "Bearer" : null));
    }

    private static HttpContext RouteContext(string tenantId)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.RouteValues["tenantId"] = tenantId;
        return httpContext;
    }

    private static async Task<bool> AuthorizeAsync(IAuthorizationService service, ClaimsPrincipal user,
        string policy, string tenantId = CustomerTenantId)
    {
        var result = await service.AuthorizeAsync(user, RouteContext(tenantId), policy);
        return result.Succeeded;
    }

    [Theory]
    [InlineData("role")]
    [InlineData(ClaimTypes.Role)]
    public async Task UserAdministration_WithUserManagement_IsGranted_UnderEitherRoleClaimSpelling(string claimType)
    {
        var service = CreateAuthorizationService();

        (await AuthorizeAsync(service, Principal(["UserManagement"], claimType),
            IdentityServiceConstants.IdentityUserAdministrationWritePolicy)).Should().BeTrue();
    }

    [Theory]
    [InlineData("")]
    [InlineData("DashboardViewer")]
    [InlineData("TenantManagement")]
    [InlineData("CommunicationManagement")]
    public async Task UserAdministration_WithoutUserManagement_IsDenied(string role)
    {
        string[] roles = role.Length == 0 ? [] : [role];
        var service = CreateAuthorizationService();

        (await AuthorizeAsync(service, Principal(roles),
            IdentityServiceConstants.IdentityUserAdministrationWritePolicy)).Should().BeFalse();
        (await AuthorizeAsync(service, Principal(roles),
            IdentityServiceConstants.IdentityUserAdministrationReadPolicy)).Should().BeFalse();
    }

    [Fact]
    public async Task Role_IsCaseSensitive_LikeTheTokenClaims()
    {
        var service = CreateAuthorizationService();

        (await AuthorizeAsync(service, Principal(["usermanagement"]),
            IdentityServiceConstants.IdentityUserAdministrationWritePolicy)).Should().BeFalse();
    }

    [Theory]
    [InlineData("TenantManagement", true)]
    [InlineData("UserManagement", true)]
    [InlineData("AdminPanelManagement", false)]
    [InlineData("DashboardViewer", false)]
    public async Task TenantAdministration_AcceptsTenantOrUserManagement(string role, bool expected)
    {
        var service = CreateAuthorizationService();

        (await AuthorizeAsync(service, Principal([role]),
            IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)).Should().Be(expected);
    }

    [Theory]
    [InlineData("UserManagement", true)]
    [InlineData("TenantManagement", true)]
    [InlineData("AdminPanelManagement", true)]
    [InlineData("CommunicationManagement", true)]
    [InlineData("DashboardViewer", false)]
    public async Task DirectoryRead_AcceptsTheOperationalRoles(string role, bool expected)
    {
        var service = CreateAuthorizationService();

        (await AuthorizeAsync(service, Principal([role]),
            IdentityServiceConstants.IdentityDirectoryReadPolicy)).Should().Be(expected);
    }

    [Fact]
    public async Task ReadOnlyScope_CanRead_ButNeverWrite_EvenWithTheRole()
    {
        var service = CreateAuthorizationService();
        var user = Principal(["UserManagement"], scope: "octo_api.read_only");

        (await AuthorizeAsync(service, user, IdentityServiceConstants.IdentityUserAdministrationReadPolicy))
            .Should().BeTrue();
        (await AuthorizeAsync(service, user, IdentityServiceConstants.IdentityUserAdministrationWritePolicy))
            .Should().BeFalse();
    }

    [Fact]
    public async Task WarnMode_LetsAMissingRoleThrough_ButNotAMissingScope()
    {
        var service = CreateAuthorizationService(IdentityApiRoleEnforcementMode.Warn);

        (await AuthorizeAsync(service, Principal(["DashboardViewer"]),
            IdentityServiceConstants.IdentityUserAdministrationWritePolicy)).Should().BeTrue();
        (await AuthorizeAsync(service, Principal(["UserManagement"], scope: "octo_api.read_only"),
            IdentityServiceConstants.IdentityUserAdministrationWritePolicy)).Should().BeFalse();
    }

    [Fact]
    public async Task WarnMode_DoesNotAuthorizeAnonymous()
    {
        var service = CreateAuthorizationService(IdentityApiRoleEnforcementMode.Warn);

        (await AuthorizeAsync(service, Principal([], authenticated: false),
            IdentityServiceConstants.IdentityUserAdministrationReadPolicy)).Should().BeFalse();
    }

    [Theory]
    [InlineData(SystemTenantId, true)]
    [InlineData("OctoSystem", true)]
    [InlineData(CustomerTenantId, false)]
    public async Task ServiceAdministration_IsSystemTenantOnly(string routeTenantId, bool expected)
    {
        var service = CreateAuthorizationService();

        (await AuthorizeAsync(service, Principal(["TenantManagement"]),
            IdentityServiceConstants.IdentityServiceAdministrationPolicy, routeTenantId)).Should().Be(expected);
    }

    [Fact]
    public async Task ServiceAdministration_FromCustomerTenant_IsDeniedEvenInWarnMode()
    {
        var service = CreateAuthorizationService(IdentityApiRoleEnforcementMode.Warn);

        (await AuthorizeAsync(service, Principal(["TenantManagement"]),
            IdentityServiceConstants.IdentityServiceAdministrationPolicy, CustomerTenantId)).Should().BeFalse();
    }

    // ------------------------------------------------------------------ guard over every endpoint

    private static readonly string[] ScopeOnlyAllowList =
    [
        // Self-service / harmless: the caller's own claims and the password generator.
        $"{nameof(DiagnosticsController)}.{nameof(DiagnosticsController.Get)}",
        $"{nameof(ToolsController)}.{nameof(ToolsController.Get)}",
        // Only works while the tenant has no user at all (bootstrap); unchanged.
        $"{nameof(SetupController)}.{nameof(SetupController.AddAdminUser)}"
    ];

    private static readonly string[] RoleBasedPolicies =
    [
        IdentityServiceConstants.IdentityUserAdministrationReadPolicy,
        IdentityServiceConstants.IdentityUserAdministrationWritePolicy,
        IdentityServiceConstants.IdentityTenantAdministrationReadPolicy,
        IdentityServiceConstants.IdentityTenantAdministrationWritePolicy,
        IdentityServiceConstants.IdentityDirectoryReadPolicy,
        IdentityServiceConstants.IdentityServiceAdministrationPolicy
    ];

    private static readonly string[] ReadPolicies =
    [
        IdentityServiceConstants.IdentityUserAdministrationReadPolicy,
        IdentityServiceConstants.IdentityTenantAdministrationReadPolicy,
        IdentityServiceConstants.IdentityDirectoryReadPolicy,
        IdentityServiceConstants.IdentityApiReadOnlyPolicy
    ];

    public static TheoryData<string> TenantApiActions()
    {
        var data = new TheoryData<string>();
        foreach (var (name, _, _) in EnumerateActions())
        {
            data.Add(name);
        }

        return data;
    }

    private static IEnumerable<(string Name, MethodInfo Method, string? Policy)> EnumerateActions()
    {
        var controllerTypes = typeof(UsersController).Assembly.GetTypes()
            .Where(t => t.Namespace == typeof(UsersController).Namespace &&
                        typeof(ControllerBase).IsAssignableFrom(t) && !t.IsAbstract);

        foreach (var type in controllerTypes)
        {
            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                         .Where(m => m.GetCustomAttributes<HttpMethodAttribute>().Any()))
            {
                var policy = method.GetCustomAttributes<AuthorizeAttribute>().Select(a => a.Policy)
                                 .FirstOrDefault(p => p != null)
                             ?? type.GetCustomAttributes<AuthorizeAttribute>().Select(a => a.Policy)
                                 .FirstOrDefault(p => p != null);
                yield return ($"{type.Name}.{method.Name}", method, policy);
            }
        }
    }

    [Theory]
    [MemberData(nameof(TenantApiActions))]
    public void EveryTenantApiEndpoint_RequiresARole_UnlessExplicitlyAllowListed(string action)
    {
        var entries = EnumerateActions().Where(a => a.Name == action).ToList();

        foreach (var (_, method, policy) in entries)
        {
            if (ScopeOnlyAllowList.Contains(action))
            {
                continue;
            }

            policy.Should().NotBeNull($"{action} must declare an authorization policy");
            RoleBasedPolicies.Should().Contain(policy!,
                $"{action} must require a tenant role (AB#5859), not only a scope");

            var isRead = method.GetCustomAttributes<HttpMethodAttribute>()
                .All(a => a.HttpMethods.All(m => m == "GET"));
            if (!isRead)
            {
                ReadPolicies.Should().NotContain(policy!, $"{action} writes and must not use a read policy");
            }
        }
    }

    [Fact]
    public void Guard_SeesTheWholeApi()
    {
        // A namespace change would turn the guard above into an empty, vacuously green theory.
        EnumerateActions().Count().Should().BeGreaterThan(100);
    }
}
