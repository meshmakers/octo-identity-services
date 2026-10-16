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
    private static readonly string[] TargetTenantNames = AdminProvisioningTargetScopeFilter.TargetParameterNames;

    private sealed record ActionRoute(MethodInfo Action, string Template, bool HasScopeFilter, bool NamesTargetTenant)
    {
        public override string ToString() => $"{Action.DeclaringType!.Name}.{Action.Name} [{Template}]";
    }

    private static IEnumerable<ActionRoute> AllActionRoutes()
    {
        var controllers = typeof(AdminProvisioningController).Assembly.GetTypes()
            .Where(t => t is { IsAbstract: false, IsClass: true } && typeof(ControllerBase).IsAssignableFrom(t));

        foreach (var controller in controllers)
        {
            // Every controller-level [Route] template combines with every action template.
            var classRoutes = controller.GetCustomAttributes<RouteAttribute>(true).Select(a => a.Template).ToList();
            if (classRoutes.Count == 0)
            {
                classRoutes.Add(string.Empty);
            }

            foreach (var action in controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                         .Where(m => m.DeclaringType != typeof(ControllerBase) && m.DeclaringType != typeof(object)))
            {
                // [HttpGet]/[HttpPost]/... and a plain [Route] on the action both declare a reachable route.
                var actionTemplates = action.GetCustomAttributes(true).OfType<IRouteTemplateProvider>()
                    .Select(a => a.Template).ToList();
                if (actionTemplates.Count == 0)
                {
                    continue; // not an action
                }

                var hasFilter = HasScopeFilter(controller) || HasScopeFilter(action);
                // A target tenant named by an action parameter (route, query or body binding) counts like one in the
                // route: provisionInTenant?childTenantId= has no placeholder in its template (AB#6758).
                var namesParameter = action.GetParameters().Any(p =>
                    TargetTenantNames.Contains(p.Name, StringComparer.OrdinalIgnoreCase));
                foreach (var classRoute in classRoutes)
                {
                    foreach (var template in actionTemplates)
                    {
                        yield return new ActionRoute(action, Combine(classRoute, template), hasFilter,
                            namesParameter || TargetTenantNames.Any(n => Combine(classRoute, template)
                                .Contains("{" + n, StringComparison.OrdinalIgnoreCase)));
                    }
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

    private static List<ActionRoute> TargetTenantRoutes() => AllActionRoutes().Where(r => r.NamesTargetTenant).ToList();

    [Fact]
    public void RouteDiscovery_FindsTheAdminProvisioningAndClientMirrorActions()
    {
        // Guards the guard: if discovery silently returned nothing, the coverage test below would pass vacuously.
        var routes = TargetTenantRoutes();

        routes.Count(r => r.Action.DeclaringType == typeof(AdminProvisioningController))
            .Should().Be(8, "list, create, provisionCurrentUser, withGroups, delete, sourceUsers, roles, groups");
        routes.Should().Contain(r => r.Template.EndsWith("provisionCurrentUser", StringComparison.Ordinal));

        var mirror = routes.Where(r => r.Action.DeclaringType == typeof(ClientMirrorController))
            .Select(r => r.Action.Name).ToList();
        mirror.Should().BeEquivalentTo("ProvisionInTenant", "RotateSecret", "Delete");
        routes.Single(r => r.Action.Name == "ProvisionInTenant").Template.Should()
            .NotContain("childTenantId", "the query-bound parameter is found through the action signature");
    }

    [Fact]
    public void EveryActionNamingATargetTenant_CarriesTheTargetScopeFilter()
    {
        var unprotected = TargetTenantRoutes().Where(r => !r.HasScopeFilter).Select(r => r.ToString()).ToList();

        unprotected.Should().BeEmpty(
            "an action addressing a target tenant ({targetTenantId} / {childTenantId} in the route, or a " +
            "targetTenantId / childTenantId parameter in the query) reaches that tenant through the system context; " +
            "without " + nameof(AdminProvisioningTargetScopeFilter) +
            " any signed-in user could address any tenant (AB#4824, AB#6758)");
    }
}
