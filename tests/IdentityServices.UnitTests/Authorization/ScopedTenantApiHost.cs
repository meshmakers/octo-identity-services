using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Text.Encodings.Web;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
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

namespace IdentityServices.UnitTests.Authorization;

/// <summary>
///     An in-memory ASP.NET Core pipeline (AB#4824, AB#6758) with the real routing, the real controllers
///     under test, the production authorization policies and role handler, and the real
///     <see cref="AdminProvisioningTargetScopeFilter" /> — against a fake tenant registry. Only the persistence
///     below the action is faked: for a registered target tenant a test-only innermost filter ends the request
///     (<c>201</c> for POST, <c>204</c> for DELETE) instead of running the MongoDB-backed action, and records
///     that the action was reached; for an unregistered target the real action runs.
/// </summary>
internal sealed class ScopedTenantApiHost : IAsyncDisposable
{
    public const string SystemTenant = "octosystem";
    public const string DefaultRoles = "TenantManagement";

    private readonly WebApplication _app;
    private readonly HttpClient _client;

    private ScopedTenantApiHost(WebApplication app, FakeTenantRegistry registry,
        CapturingLogger<AdminProvisioningTargetScopeFilter> filterLog,
        CapturingLogger<IdentityApiRoleAuthorizationHandler> policyLog, ISystemContext systemContext)
    {
        _app = app;
        _client = app.GetTestClient();
        Registry = registry;
        FilterLog = filterLog;
        PolicyLog = policyLog;
        SystemContext = systemContext;
    }

    public FakeTenantRegistry Registry { get; }
    public CapturingLogger<AdminProvisioningTargetScopeFilter> FilterLog { get; }
    public CapturingLogger<IdentityApiRoleAuthorizationHandler> PolicyLog { get; }
    public ISystemContext SystemContext { get; }

    // octosystem
    //   +- a            (the caller's tenant)
    //   |   +- a-child
    //   |        +- a-grandchild
    //   +- s            (sibling of a)
    //   |   +- s-child  (descendant of the sibling)
    //   +- u            (unrelated)
    public static FakeTenantRegistry CreateRegistry()
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

    public static async Task<ScopedTenantApiHost> StartAsync(IdentityApiRoleEnforcementMode mode,
        params Type[] controllers)
    {
        var registry = CreateRegistry();
        var filterLog = new CapturingLogger<AdminProvisioningTargetScopeFilter>();
        var policyLog = new CapturingLogger<IdentityApiRoleAuthorizationHandler>();
        var systemContext = Substitute.For<ISystemContext>();
        systemContext.TryFindTenantRepositoryAsync(Arg.Any<string>())
            .Returns(Task.FromResult<ITenantRepository?>(null));

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        var services = builder.Services;

        services.AddSingleton<ITenantDiscoveryService>(registry);
        services.AddSingleton(Options.Create(new OctoSystemConfiguration { SystemTenantId = SystemTenant }));
        services.Configure<IdentityApiAuthorizationOptions>(o => o.RoleEnforcement = mode);
        services.AddSingleton<ILogger<AdminProvisioningTargetScopeFilter>>(filterLog);
        services.AddSingleton<ILogger<IdentityApiRoleAuthorizationHandler>>(policyLog);
        services.AddSingleton(systemContext);
        services.AddSingleton(Substitute.For<IDynamicAuthSchemeService>());
        services.AddSingleton(Substitute.For<IdentityServerPersistence.SystemStores.IOctoClientStore>());
        services.AddSingleton(Substitute.For<IClientMirrorProvisioningService>());

        // The very registration of production: scope + tenant-role policies and their handler.
        services.AddSingleton<IAuthorizationHandler, IdentityApiRoleAuthorizationHandler>();
        services.AddAuthorization(options => options.AddIdentityApiPolicies());
        services.AddAuthentication("Bearer")
            .AddScheme<AuthenticationSchemeOptions, HeaderAuthHandler>("Bearer", _ => { });

        // The route constraints the host registers elsewhere; irrelevant for the question under test.
        services.Configure<RouteOptions>(o =>
        {
            o.ConstraintMap["tenantId"] = typeof(AnyValueConstraint);
            o.ConstraintMap["apiVersion"] = typeof(AnyValueConstraint);
        });

        var allowed = controllers.Select(c => c.GetTypeInfo()).ToHashSet();
        services.AddControllers(o => o.Filters.Add(new ReachedActionFilter(registry)))
            .ConfigureApplicationPartManager(m =>
            {
                m.ApplicationParts.Clear();
                m.ApplicationParts.Add(new AssemblyPart(controllers[0].Assembly));
                m.FeatureProviders.Add(new OnlyTheseControllersProvider(allowed));
            });

        var app = builder.Build();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapControllers();
        await app.StartAsync();
        return new ScopedTenantApiHost(app, registry, filterLog, policyLog, systemContext);
    }

    public async ValueTask DisposeAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
    }

    /// <summary>One request as a caller of <paramref name="callerTenant" /> (the token's <c>tenant_id</c>).</summary>
    public async Task<(HttpStatusCode Status, string Body, string Headers)> SendAsync(HttpMethod method, string url,
        string callerTenant, string? roles = DefaultRoles)
    {
        var request = new HttpRequestMessage(method, url);
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

    /// <summary>Registry with a mutable parent/child hierarchy; unknown scope yields <c>null</c> like the real one.</summary>
    internal sealed class FakeTenantRegistry : ITenantDiscoveryService
    {
        private readonly Dictionary<string, List<string>> _children = new(StringComparer.OrdinalIgnoreCase);
        private readonly Lock _gate = new();
        private readonly List<string> _reached = [];
        private int _lookups;

        public int DescendantLookups => Volatile.Read(ref _lookups);

        public IReadOnlyList<string> ActionReachedFor
        {
            get
            {
                lock (_gate)
                {
                    return _reached.ToList();
                }
            }
        }

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

        public Task<IReadOnlyList<string>> FindTenantsForUserAsync(string emailOrUsername,
            string? scopeTenantId = null) => throw new NotSupportedException();

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
    private sealed class HeaderAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
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
    ///     Innermost action filter (runs after the controller's own filters): for a registered target tenant (route
    ///     <c>targetTenantId</c>/<c>childTenantId</c> or query <c>childTenantId</c>) it ends the request instead of
    ///     the MongoDB-backed action, recording that the action was reached.
    /// </summary>
    private sealed class ReachedActionFilter(FakeTenantRegistry registry) : IAsyncActionFilter, IOrderedFilter
    {
        public int Order => int.MaxValue;

        public Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var target = context.RouteData.Values["targetTenantId"] as string
                         ?? context.RouteData.Values["childTenantId"] as string
                         ?? context.HttpContext.Request.Query["childTenantId"].FirstOrDefault();
            if (target != null && registry.Knows(target))
            {
                registry.MarkReached(target);
                context.Result = new StatusCodeResult(context.HttpContext.Request.Method == "DELETE"
                    ? StatusCodes.Status204NoContent
                    : StatusCodes.Status201Created);
                return Task.CompletedTask;
            }

            return next();
        }
    }

    private sealed class OnlyTheseControllersProvider(HashSet<TypeInfo> allowed)
        : IApplicationFeatureProvider<ControllerFeature>
    {
        public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature)
        {
            foreach (var type in feature.Controllers.Where(t => !allowed.Contains(t)).ToList())
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
}
