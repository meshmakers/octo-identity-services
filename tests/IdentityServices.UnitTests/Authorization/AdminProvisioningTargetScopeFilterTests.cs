using System.Security.Claims;
using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace IdentityServices.UnitTests.Authorization;

/// <summary>
///     AB#5859: cross-tenant admin provisioning only reaches the caller's own tenant and its descendants.
/// </summary>
public class AdminProvisioningTargetScopeFilterTests
{
    private const string SystemTenantId = "octosystem";

    private readonly ITenantDiscoveryService _discovery = Substitute.For<ITenantDiscoveryService>();

    public AdminProvisioningTargetScopeFilterTests()
    {
        _discovery.GetScopeDescendantsAsync("parent")
            .Returns(new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "child", "grandchild" });
        _discovery.GetScopeDescendantsAsync("stranger")
            .Returns(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
    }

    private AdminProvisioningTargetScopeFilter CreateFilter(
        IdentityApiRoleEnforcementMode mode = IdentityApiRoleEnforcementMode.Enforce)
    {
        var monitor = Substitute.For<IOptionsMonitor<IdentityApiAuthorizationOptions>>();
        monitor.CurrentValue.Returns(new IdentityApiAuthorizationOptions { RoleEnforcement = mode });
        return new AdminProvisioningTargetScopeFilter(_discovery,
            Options.Create(new OctoSystemConfiguration { SystemTenantId = SystemTenantId }), monitor,
            NullLogger<AdminProvisioningTargetScopeFilter>.Instance);
    }

    private static async Task<(bool NextCalled, IActionResult? Result)> RunAsync(
        AdminProvisioningTargetScopeFilter filter, string? callerTenantId, string targetTenantId)
    {
        var claims = new List<Claim> { new("sub", "user-1") };
        if (callerTenantId != null)
        {
            claims.Add(new Claim("tenant_id", callerTenantId));
        }

        var httpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer")) };
        var routeData = new RouteData();
        routeData.Values["targetTenantId"] = targetTenantId;
        var actionContext = new ActionContext(httpContext, routeData, new ActionDescriptor());
        var context = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(),
            new Dictionary<string, object?>(), controller: new object());

        var nextCalled = false;
        await filter.OnActionExecutionAsync(context, () =>
        {
            nextCalled = true;
            return Task.FromResult(new ActionExecutedContext(actionContext, new List<IFilterMetadata>(), new object()));
        });
        return (nextCalled, context.Result);
    }

    [Theory]
    [InlineData(SystemTenantId, "anything")]
    [InlineData("OctoSystem", "anything")]
    [InlineData("parent", "parent")]
    [InlineData("parent", "child")]
    [InlineData("parent", "GrandChild")]
    public async Task TargetInsideTheCallerSubtree_IsAllowed(string caller, string target)
    {
        var (nextCalled, result) = await RunAsync(CreateFilter(), caller, target);

        nextCalled.Should().BeTrue();
        result.Should().BeNull();
    }

    [Theory]
    [InlineData("stranger", "child")]
    [InlineData("child", "parent")]
    [InlineData("unknown", "child")]
    [InlineData(null, "child")]
    public async Task TargetOutsideTheCallerSubtree_IsForbidden(string? caller, string target)
    {
        var (nextCalled, result) = await RunAsync(CreateFilter(), caller, target);

        nextCalled.Should().BeFalse();
        result.Should().BeOfType<ForbidResult>();
    }

    [Fact]
    public async Task WarnMode_LetsTheCallThrough()
    {
        var (nextCalled, result) = await RunAsync(CreateFilter(IdentityApiRoleEnforcementMode.Warn), "stranger", "child");

        nextCalled.Should().BeTrue();
        result.Should().BeNull();
    }
}
