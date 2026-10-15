using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Text.Encodings.Web;
using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServices.UnitTests.Authorization;

/// <summary>
///     AB#4824: the real HTTP pipeline of <c>POST {tenant}/v1/adminProvisioning/{target}/provisionCurrentUser</c> —
///     real routing, real <see cref="AdminProvisioningController" />, real
///     <see cref="IdentityServiceConstants.IdentityTenantAdministrationWritePolicy" /> (production policy
///     registration and role handler) and the real <see cref="AdminProvisioningTargetScopeFilter" /> — against a
///     fake tenant registry. Only the persistence below the action is faked: for a registered target tenant a
///     test-only innermost filter answers <c>201</c> (the action itself needs MongoDB); for an unregistered one
///     the real action runs and answers <c>404</c>, exactly like the live reproduction.
/// </summary>
public class AdminProvisioningPipelineTests : IAsyncDisposable
{
    private const string SystemTenant = "octosystem";
    private const string Roles = "TenantManagement";
    private static readonly Uri ProvisionUnknown = new("http://localhost/");

    private FakeTenantRegistry _registry = null!;
    private CapturingLogger<AdminProvisioningTargetScopeFilter> _filterLog = null!;
    private CapturingLogger<IdentityApiRoleAuthorizationHandler> _policyLog = null!;
    private ISystemContext _systemContext = null!;
    private WebApplication? _app;
    private HttpClient _client = null!;

    // octosystem
    //   +- a            (the caller's tenant)
    //   |   +- a-child
    //   |        +- a-grandchild
    //   +- s            (sibling of a)
    //   |   +- s-child  (descendant of the sibling)
    //   +- u            (unrelated)
    private static FakeTenantRegistry CreateRegistry()
    {
        var registry = new FakeTenantRegistry();
        registry.AddTenant(SystemTenant, null);
        registry.AddTenant("a", SystemTenant);
        registry.AddTenant("a-child", "a");
        registry.AddTenant("a-grandchild", "a-child");
        registry.AddTenant("s", SystemTenant);
        registry.AddTenant("s-child", "s");
        registry.AddTenant("u", SystemTenant);
        return registry;
    }

    private async Task StartAsync(IdentityApiRoleEnforcementMode mode = IdentityApiRoleEnforcementMode.Enforce)
    {
        _registry = CreateRegistry();
        _filterLog = new CapturingLogger<AdminProvisioningTargetScopeFilter>();
        _policyLog = new CapturingLogger<IdentityApiRoleAuthorizationHandler>();
        _systemContext = Substitute.For<ISystemContext>();
        _systemContext.TryFindTenantRepositoryAsync(Arg.Any<string>()).Returns(Task.FromResult<ITenantRepository?>(null));

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        var services = builder.Services;

        services.AddSingleton<ITenantDiscoveryService>(_registry);
        services.AddSingleton(Options.Create(new OctoSystemConfiguration { SystemTenantId = SystemTenant }));
        services.Configure<IdentityApiAuthorizationOptions>(o => o.RoleEnforcement = mode);
        services.AddSingleton<ILogger<AdminProvisioningTargetScopeFilter>>(_filterLog);
        services.AddSingleton<ILogger<IdentityApiRoleAuthorizationHandler>>(_policyLog);
        services.AddSingleton(_systemContext);
        services.AddSingleton(Substitute.For<IDynamicAuthSchemeService>());

        // The very registration of production: scope + tenant-role policies and their handler.
        services.AddSingleton<IAuthorizationHandler, IdentityApiRoleAuthorizationHandler>();
        services.AddAuthorization(options => options.AddIdentityApiPolicies());
        services.AddAuthentication("Bearer").AddScheme<AuthenticationSchemeOptions, HeaderAuthHandler>("Bearer", _ => { });

        // The route constraints the host registers elsewhere; irrelevant for the question under test.
        services.Configure<RouteOptions>(o =>
        {
            o.ConstraintMap["tenantId"] = typeof(AnyValueConstraint);
            o.ConstraintMap["apiVersion"] = typeof(AnyValueConstraint);
        });

        services.AddControllers(o => o.Filters.Add(new ReachedActionFilter(_registry)))
            .ConfigureApplicationPartManager(m =>
            {
                m.ApplicationParts.Clear();
                m.ApplicationParts.Add(new AssemblyPart(typeof(AdminProvisioningController).Assembly));
                m.FeatureProviders.Add(new OnlyAdminProvisioningControllerProvider());
            });

        _app = builder.Build();
        _app.UseRouting();
        _app.UseAuthentication();
        _app.UseAuthorization();
        _app.MapControllers();
        await _app.StartAsync();
        _client = _app.GetTestClient();
    }

    public async ValueTask DisposeAsync()
    {
        _client?.Dispose();
        if (_app != null)
        {
            await _app.DisposeAsync();
        }
    }

    private async Task<(HttpStatusCode Status, string Body, string Headers)> ProvisionAsync(string callerTenant,
        string target, string? roles = Roles)
    {
        var request = new HttpRequestMessage(HttpMethod.Post,
            $"/{callerTenant}/v1/adminProvisioning/{target}/provisionCurrentUser");
        request.Headers.Add(HeaderAuthHandler.TenantHeader, callerTenant);
        if (roles != null)
        {
            request.Headers.Add(HeaderAuthHandler.RolesHeader, roles);
        }

        var response = await _client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        // Location (the AccessDenied redirect echo of the requested path) is cosmetic and differs per path.
        var headers = string.Join("|", response.Headers.Concat(response.Content.Headers)
            .Where(h => !string.Equals(h.Key, "Location", StringComparison.OrdinalIgnoreCase))
            .OrderBy(h => h.Key, StringComparer.OrdinalIgnoreCase)
            .Select(h => $"{h.Key}={string.Join(",", h.Value)}"));
        return (response.StatusCode, body, headers);
    }

    [Theory]
    [InlineData("a-child")]
    [InlineData("a-grandchild")]
    [InlineData("a")]
    public async Task RoleHolder_ProvisioningIntoOwnTenantOrDescendant_Succeeds(string target)
    {
        await StartAsync();

        var result = await ProvisionAsync("a", target);

        result.Status.Should().Be(HttpStatusCode.Created);
        _registry.ActionReachedFor.Should().Equal(target);
    }

    [Theory]
    [InlineData("s", "sibling")]
    [InlineData("s-child", "descendant of a sibling")]
    [InlineData("u", "unrelated tenant")]
    [InlineData(SystemTenant, "the system tenant")]
    [InlineData("does-not-exist", "unknown tenant")]
    public async Task RoleHolder_ProvisioningOutsideTheOwnSubtree_IsForbidden_AndTheActionNeverRuns(string target,
        string _)
    {
        await StartAsync();

        var result = await ProvisionAsync("a", target);

        result.Status.Should().Be(HttpStatusCode.Forbidden);
        _registry.ActionReachedFor.Should().BeEmpty();
        _systemContext.ReceivedCalls().Should().BeEmpty("nothing of the target tenant may be touched");
        _filterLog.AllText.Should().Contain("Admin provisioning denied, target outside the caller's tenant subtree");
    }

    [Fact]
    public async Task UnknownTarget_IsIndistinguishableFromAForeignTarget()
    {
        await StartAsync();

        var sibling = await ProvisionAsync("a", "s");
        var descendantOfSibling = await ProvisionAsync("a", "s-child");
        var unrelated = await ProvisionAsync("a", "u");
        var unknown = await ProvisionAsync("a", "does-not-exist");

        foreach (var other in new[] { descendantOfSibling, unrelated, unknown })
        {
            other.Status.Should().Be(sibling.Status);
            other.Body.Should().Be(sibling.Body);
            other.Headers.Should().Be(sibling.Headers);
        }
    }

    [Fact]
    public async Task SystemCaller_Succeeds_ForAnyRegisteredTenant()
    {
        await StartAsync();

        foreach (var target in new[] { "a", "a-grandchild", "s", "s-child", "u" })
        {
            (await ProvisionAsync(SystemTenant, target)).Status.Should().Be(HttpStatusCode.Created, target);
        }
    }

    [Fact]
    public async Task SystemCaller_OnAnUnknownTenant_PassesTheFilter_AndTheActionAnswers404()
    {
        // Documents the current behavior (live repro AB#4824): the system caller is allowed to learn that a
        // tenant does not exist; the filter lets it through and the action answers 404.
        await StartAsync();

        var result = await ProvisionAsync(SystemTenant, "does-not-exist");

        result.Status.Should().Be(HttpStatusCode.NotFound);
        result.Body.Should().Contain("not found");
        _filterLog.AllText.Should().BeEmpty();
        await _systemContext.Received(1).TryFindTenantRepositoryAsync("does-not-exist");
    }

    [Fact]
    public async Task TenantCreatedBelowTheCaller_ImmediatelyCountsAsDescendant()
    {
        // CreateTenant-then-provision in one step (octo-cli Create): the new tenant is registered below the
        // caller's tenant first, the provisioning call follows.
        await StartAsync();
        (await ProvisionAsync("a", "a-new")).Status.Should().Be(HttpStatusCode.Forbidden, "not created yet");

        _registry.AddTenant("a-new", "a");
        var result = await ProvisionAsync("a", "a-new");

        result.Status.Should().Be(HttpStatusCode.Created);
        _registry.ActionReachedFor.Should().Equal("a-new");
    }

    [Fact]
    public async Task Policy_And_Filter_ApplyTogether_RolelessCallerIsStoppedByThePolicyFirst()
    {
        await StartAsync();

        // roleless caller, even towards its own descendant
        var result = await ProvisionAsync("a", "a-child", roles: null);

        result.Status.Should().Be(HttpStatusCode.Forbidden);
        _policyLog.AllText.Should().Contain("required role missing");
        _filterLog.AllText.Should().BeEmpty("the filter never runs when the policy already denied");
        _registry.DescendantLookups.Should().Be(0);
        _registry.ActionReachedFor.Should().BeEmpty();
    }

    [Fact]
    public async Task Policy_And_Filter_ApplyTogether_RoleHolderIsStoppedByTheFilter()
    {
        // Isolates the filter: the policy lets the role holder through, so the 403 is the filter's.
        await StartAsync();

        var result = await ProvisionAsync("a", "u");

        result.Status.Should().Be(HttpStatusCode.Forbidden);
        _policyLog.AllText.Should().BeEmpty("the role policy was satisfied");
        _filterLog.AllText.Should().Contain("target outside the caller's tenant subtree");
        _registry.DescendantLookups.Should().Be(1);
    }

    [Fact]
    public async Task WarnMode_RoleHolderOutsideTheSubtree_PassesThrough_AndLogsTheWarning()
    {
        // Documents the dependency of the AB#4824/AB#5859 fix on RoleEnforcement: in Warn the filter only logs.
        await StartAsync(IdentityApiRoleEnforcementMode.Warn);

        var sibling = await ProvisionAsync("a", "s");
        var unrelated = await ProvisionAsync("a", "u");

        sibling.Status.Should().Be(HttpStatusCode.Created);
        unrelated.Status.Should().Be(HttpStatusCode.Created);
        _registry.ActionReachedFor.Should().Equal("s", "u");
        _filterLog.AllText.Should().Contain(
            "Admin provisioning outside the caller's tenant subtree allowed by RoleEnforcement=Warn");
        _filterLog.Messages.Should().HaveCount(2);
    }

    [Fact]
    public async Task WarnMode_RolelessCaller_PassesThePolicyToo_AndLogsBothWarnings()
    {
        await StartAsync(IdentityApiRoleEnforcementMode.Warn);

        var result = await ProvisionAsync("a", "u", roles: null);

        result.Status.Should().Be(HttpStatusCode.Created);
        _policyLog.AllText.Should().Contain("allowed by RoleEnforcement=Warn");
        _filterLog.AllText.Should().Contain(
            "Admin provisioning outside the caller's tenant subtree allowed by RoleEnforcement=Warn");
    }

    #region test doubles

    /// <summary>Registry with a mutable parent/child hierarchy; unknown scope yields <c>null</c> like the real one.</summary>
    private sealed class FakeTenantRegistry : ITenantDiscoveryService
    {
        private readonly Dictionary<string, List<string>> _children = new(StringComparer.OrdinalIgnoreCase);
        private readonly Lock _gate = new();
        private readonly List<string> _reached = [];
        private int _lookups;

        public int DescendantLookups => Volatile.Read(ref _lookups);
        public IReadOnlyList<string> ActionReachedFor { get { lock (_gate) { return _reached.ToList(); } } }

        public bool Knows(string tenantId) => _children.ContainsKey(tenantId);

        public void MarkReached(string tenantId)
        {
            lock (_gate)
            {
                _reached.Add(tenantId);
            }
        }

        public void AddTenant(string tenantId, string? parentId)
        {
            _children[tenantId] = [];
            if (parentId != null)
            {
                _children[parentId].Add(tenantId);
            }
        }

        public Task<IReadOnlyList<string>> FindTenantsForUserAsync(string emailOrUsername, string? scopeTenantId = null)
            => throw new NotSupportedException();

        public Task<IReadOnlySet<string>?> GetScopeDescendantsAsync(string scopeTenantId)
        {
            Interlocked.Increment(ref _lookups);
            if (!_children.ContainsKey(scopeTenantId))
            {
                return Task.FromResult<IReadOnlySet<string>?>(null);
            }

            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var queue = new Queue<string>(_children[scopeTenantId]);
            while (queue.Count > 0)
            {
                var next = queue.Dequeue();
                if (result.Add(next))
                {
                    foreach (var child in _children[next])
                    {
                        queue.Enqueue(child);
                    }
                }
            }

            return Task.FromResult<IReadOnlySet<string>?>(result);
        }
    }

    /// <summary>Authenticated principal from test headers: tenant_id, roles, and the full-access scope.</summary>
    private sealed class HeaderAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger,
        UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string TenantHeader = "X-Test-Tenant";
        public const string RolesHeader = "X-Test-Roles";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var claims = new List<Claim> { new("sub", "user-1"), new("scope", "octo_api") };
            if (Request.Headers.TryGetValue(TenantHeader, out var tenant))
            {
                claims.Add(new Claim("tenant_id", tenant.ToString()));
            }

            if (Request.Headers.TryGetValue(RolesHeader, out var roles))
            {
                claims.AddRange(roles.ToString().Split(',').Select(r => new Claim("role", r)));
            }

            var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer")), "Bearer");
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }

    /// <summary>
    ///     Innermost action filter (runs after the controller's own filters): for a registered target it ends the
    ///     request with 201 instead of the MongoDB-backed action, recording that the action was reached.
    /// </summary>
    private sealed class ReachedActionFilter(FakeTenantRegistry registry) : IAsyncActionFilter, IOrderedFilter
    {
        public int Order => int.MaxValue;

        public Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var target = (string)context.RouteData.Values["targetTenantId"]!;
            if (registry.Knows(target))
            {
                registry.MarkReached(target);
                context.Result = new StatusCodeResult(StatusCodes.Status201Created);
                return Task.CompletedTask;
            }

            return next();
        }
    }

    private sealed class OnlyAdminProvisioningControllerProvider : IApplicationFeatureProvider<ControllerFeature>
    {
        public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature)
        {
            foreach (var type in feature.Controllers.Where(t => t != typeof(AdminProvisioningController).GetTypeInfo())
                         .ToList())
            {
                feature.Controllers.Remove(type);
            }
        }
    }

    private sealed class AnyValueConstraint : IRouteConstraint
    {
        public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values,
            RouteDirection routeDirection) => true;
    }

    #endregion
}
