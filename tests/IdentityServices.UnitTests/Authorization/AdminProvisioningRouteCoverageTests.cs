using System.Reflection;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Xunit;

namespace IdentityServices.UnitTests.Authorization;

/// <summary>
///     AB#4824 regression guard: every identity API route that addresses a <b>target tenant</b> in its path
///     must carry <see cref="AdminProvisioningTargetScopeFilter" />. The route set is derived by reflection
///     over all controllers of the assembly, so a new route without the filter fails the build instead of
///     silently re-opening the cross-tenant escalation (any signed-in user became TenantOwner of any tenant).
/// </summary>
public class AdminProvisioningRouteCoverageTests
{
    private const string TargetTenantToken = "{targetTenantId";

    private sealed record ActionRoute(MethodInfo Action, string Template, bool HasScopeFilter)
    {
        public override string ToString() => $"{Action.DeclaringType!.Name}.{Action.Name} [{Template}]";
    }

    private static IEnumerable<ActionRoute> AllActionRoutes()
    {
        var controllers = typeof(AdminProvisioningController).Assembly.GetTypes()
            .Where(t => t is { IsAbstract: false, IsClass: true } && typeof(ControllerBase).IsAssignableFrom(t));

        foreach (var controller in controllers)
        {
            var classRoute = controller.GetCustomAttributes<RouteAttribute>(true).Select(a => a.Template)
                .FirstOrDefault() ?? string.Empty;

            foreach (var action in controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                         .Where(m => m.DeclaringType != typeof(ControllerBase) && m.DeclaringType != typeof(object)))
            {
                var httpAttributes = action.GetCustomAttributes<HttpMethodAttribute>(true).ToList();
                if (httpAttributes.Count == 0)
                {
                    continue; // not an action
                }

                var hasFilter = HasScopeFilter(controller) || HasScopeFilter(action);
                foreach (var http in httpAttributes)
                {
                    yield return new ActionRoute(action, Combine(classRoute, http.Template), hasFilter);
                }
            }
        }
    }

    private static string Combine(string classRoute, string? actionTemplate)
    {
        if (string.IsNullOrEmpty(actionTemplate))
        {
            return classRoute;
        }

        // A template starting with / or ~/ replaces the controller route.
        return actionTemplate.StartsWith('/') || actionTemplate.StartsWith("~/")
            ? actionTemplate
            : $"{classRoute}/{actionTemplate}";
    }

    private static bool HasScopeFilter(MemberInfo member)
    {
        return member.GetCustomAttributes(true).Any(a =>
            a is TypeFilterAttribute { ImplementationType: var t } && t == typeof(AdminProvisioningTargetScopeFilter) ||
            a is ServiceFilterAttribute { ServiceType: var s } && s == typeof(AdminProvisioningTargetScopeFilter));
    }

    private static List<ActionRoute> TargetTenantRoutes() =>
        AllActionRoutes().Where(r => r.Template.Contains(TargetTenantToken, StringComparison.OrdinalIgnoreCase))
            .ToList();

    [Fact]
    public void RouteDiscovery_FindsTheAdminProvisioningRoutes()
    {
        // Guards the guard: if discovery silently returned nothing, the coverage test below would pass vacuously.
        var routes = TargetTenantRoutes();

        routes.Should().NotBeEmpty();
        routes.Select(r => r.Action.DeclaringType).Should().Contain(typeof(AdminProvisioningController));
        routes.Count(r => r.Action.DeclaringType == typeof(AdminProvisioningController))
            .Should().Be(8, "list, create, provisionCurrentUser, withGroups, delete, sourceUsers, roles, groups");
        routes.Should().Contain(r => r.Template.EndsWith("provisionCurrentUser", StringComparison.Ordinal));
    }

    [Fact]
    public void EveryRouteWithATargetTenantParameter_CarriesTheTargetScopeFilter()
    {
        var unprotected = TargetTenantRoutes().Where(r => !r.HasScopeFilter).Select(r => r.ToString()).ToList();

        unprotected.Should().BeEmpty(
            "a route addressing {targetTenantId} reaches that tenant through the system context; without " +
            nameof(AdminProvisioningTargetScopeFilter) + " any signed-in user could address any tenant (AB#4824)");
    }
}
