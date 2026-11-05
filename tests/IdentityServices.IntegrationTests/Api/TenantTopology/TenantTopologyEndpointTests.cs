using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantTopology;

/// <summary>
///     AB#7044: <c>GET /api/tenant-topology?scope=</c> through the real identity pipeline (authentication,
///     tenant gate in Enforce mode, authorization, controller, topology service, a real MongoDB hierarchy).
///     Hierarchy (ids are made unique per test class instance):
///     <code>
///     system → { R → { G → { L2 }, X }, S → { SC } }
///     </code>
/// </summary>
public class TenantTopologyEndpointTests : IntegrationTestBase
{
    private const string Route = "/api/tenant-topology";

    // Created once per class instance, lazily (xUnit creates one instance per test).
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static Hierarchy? _hierarchy;

    private sealed record Hierarchy(string R, string G, string L2, string X, string S, string SC);

    public TenantTopologyEndpointTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    private async Task<Hierarchy> EnsureHierarchyAsync()
    {
        await Gate.WaitAsync();
        try
        {
            if (_hierarchy != null)
            {
                return _hierarchy;
            }

            string Id(string prefix) => $"{prefix}{Guid.NewGuid():N}"[..20];
            var h = new Hierarchy(Id("tr"), Id("tg"), Id("tl"), Id("tx"), Id("ts"), Id("tc"));

            using var scope = Factory.Services.CreateScope();
            var systemContext = scope.ServiceProvider.GetRequiredService<ISystemContext>();
            await CreateChildAsync(systemContext, h.R);
            await CreateChildAsync(systemContext, h.S);
            await CreateChildAsync(await Context(systemContext, h.R), h.G);
            await CreateChildAsync(await Context(systemContext, h.R), h.X);
            await CreateChildAsync(await Context(systemContext, h.G), h.L2);
            await CreateChildAsync(await Context(systemContext, h.S), h.SC);

            _hierarchy = h;
            return h;
        }
        finally
        {
            Gate.Release();
        }
    }

    private static async Task<ITenantContext> Context(ISystemContext systemContext, string tenantId) =>
        (await systemContext.TryFindTenantContextAsync(tenantId))!;

    private static async Task CreateChildAsync(ISystemContext parent, string tenantId) =>
        await CreateChildAsync((ITenantContext)parent, tenantId);

    private static async Task CreateChildAsync(ITenantContext parent, string tenantId)
    {
        using var session = await parent.GetAdminSessionAsync();
        session.StartTransaction();
        try
        {
            await parent.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    /// <summary>A user token of tenant <paramref name="tokenTenant" /> with the given allowed_tenants claim.</summary>
    private HttpClient UserToken(string tokenTenant, params string[] allowedTenants)
    {
        var client = CreateAuthenticatedClient(userId: $"topo-{Guid.NewGuid():N}");
        client.DefaultRequestHeaders.Add(TestAuthHandler.TenantIdHeader, tokenTenant);
        foreach (var t in allowedTenants)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.AllowedTenantsHeader, t);
        }

        return client;
    }

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    private static List<(string TenantId, int Depth, bool HasChildren)> Tenants(JsonElement body) =>
        body.GetProperty("tenants").EnumerateArray()
            .Select(t => (t.GetProperty("tenantId").GetString()!, t.GetProperty("depth").GetInt32(),
                t.GetProperty("hasChildren").GetBoolean()))
            .ToList();

    [Fact]
    public async Task UserToken_GetsExactlyTheClaimedTenantsBelowTheScope_WithDepthAndHasChildren()
    {
        var h = await EnsureHierarchyAsync();
        var client = UserToken(h.R, h.G, h.X, h.R);

        var response = await client.GetAsync($"{Route}?scope={h.R}", TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await JsonAsync(response);
        body.GetProperty("scope").GetString().Should().Be(h.R);
        body.GetProperty("scopeHasChildren").GetBoolean().Should().BeTrue();
        Tenants(body).Should().BeEquivalentTo([(h.G, 1, true), (h.X, 1, false)],
            "L2 is below the scope but not claimed; R itself is never listed");
    }

    [Fact]
    public async Task ResponseCarriesNoOtherFieldThanTheContract()
    {
        var h = await EnsureHierarchyAsync();

        var response = await UserToken(h.R, h.G, h.X).GetAsync($"{Route}?scope={h.R}",
            TestContext.Current.CancellationToken);

        var body = await JsonAsync(response);
        body.EnumerateObject().Select(p => p.Name).Should().BeEquivalentTo("scope", "scopeHasChildren", "tenants");
        foreach (var tenant in body.GetProperty("tenants").EnumerateArray())
        {
            tenant.EnumerateObject().Select(p => p.Name).Should().BeEquivalentTo("tenantId", "depth", "hasChildren");
        }
    }

    [Fact]
    public async Task ClaimedDescendantOfAGroup_IsListedWithItsDepth_AndUnclaimedOnesAreNot()
    {
        var h = await EnsureHierarchyAsync();

        var response = await UserToken(h.R, h.L2, h.SC).GetAsync($"{Route}?scope={h.R}",
            TestContext.Current.CancellationToken);

        var body = await JsonAsync(response);
        Tenants(body).Should().BeEquivalentTo([(h.L2, 2, false)],
            "SC is claimed but lies in a sibling subtree; G and X are not claimed, so their facts stay hidden");
        body.GetRawText().Should().NotContain(h.G).And.NotContain(h.SC).And.NotContain(h.X);
    }

    [Fact]
    public async Task UnknownScope_ScopeWithoutEntitledDescendants_AndForeignScope_HaveTheSameShape()
    {
        var h = await EnsureHierarchyAsync();
        var client = UserToken(h.R, h.X);

        var unknown = await JsonAsync(await client.GetAsync($"{Route}?scope=does-not-exist",
            TestContext.Current.CancellationToken));
        var nothingEntitled = await JsonAsync(await client.GetAsync($"{Route}?scope={h.X}",
            TestContext.Current.CancellationToken));
        var foreign = await JsonAsync(await client.GetAsync($"{Route}?scope={h.S}",
            TestContext.Current.CancellationToken));
        var malformed = await JsonAsync(await client.GetAsync($"{Route}?scope=../etc",
            TestContext.Current.CancellationToken));

        foreach (var body in new[] { unknown, nothingEntitled, foreign, malformed })
        {
            body.GetProperty("scopeHasChildren").GetBoolean().Should().BeFalse();
            body.GetProperty("tenants").GetArrayLength().Should().Be(0);
            body.EnumerateObject().Select(p => p.Name).Should().BeEquivalentTo("scope", "scopeHasChildren", "tenants");
        }
    }

    [Fact]
    public async Task LegacySingleTenantDeployment_ScopeInTheClaimWithoutChildren_IsEmptyAndHasNoChildren()
    {
        var h = await EnsureHierarchyAsync();

        var response = await UserToken(h.X, h.X).GetAsync($"{Route}?scope={h.X}",
            TestContext.Current.CancellationToken);

        var body = await JsonAsync(response);
        body.GetProperty("scopeHasChildren").GetBoolean().Should().BeFalse();
        body.GetProperty("tenants").GetArrayLength().Should().Be(0);
    }

    [Fact]
    public async Task MissingScope_Is400()
    {
        var h = await EnsureHierarchyAsync();

        var response = await UserToken(h.R, h.G).GetAsync(Route, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ClientCredentialsToken_Is403()
    {
        var h = await EnsureHierarchyAsync();
        var client = CreateAuthenticatedClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.ClientCredentialsHeader, "some-service");
        client.DefaultRequestHeaders.Add(TestAuthHandler.AllowedTenantsHeader, h.G);

        var response = await client.GetAsync($"{Route}?scope={h.R}", TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task NoToken_Is401()
    {
        var h = await EnsureHierarchyAsync();

        var response = await CreateAnonymousClient().GetAsync($"{Route}?scope={h.R}",
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task UserTokenWithoutTheReadScope_Is403()
    {
        var h = await EnsureHierarchyAsync();
        var client = UserToken(h.R, h.G);
        client.DefaultRequestHeaders.Add(TestAuthHandler.ScopeHeader, "openid");

        var response = await client.GetAsync($"{Route}?scope={h.R}", TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    /// <summary>
    ///     No new exemption: the tenant gate runs in Enforce mode (its default). The token of tenant A reaches the
    ///     tenant-less topology route, while the same token against another tenant's route is still refused. The
    ///     test fails if someone adds a tenant segment to the route or an exemption marker to the gate.
    /// </summary>
    [Fact]
    public async Task TenantGateInEnforceMode_AllowsTheTenantLessRoute_AndStillRefusesAForeignTenantRoute()
    {
        var h = await EnsureHierarchyAsync();
        using var enforcing = Factory.WithWebHostBuilder(b => b.ConfigureAppConfiguration((_, c) =>
            c.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TenantAuthorization:UserTokenEnforcement"] = "Enforce"
            })));
        var client = enforcing.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add("X-Test-UserId", $"topo-{Guid.NewGuid():N}");
        client.DefaultRequestHeaders.Add(TestAuthHandler.TenantIdHeader, h.R);
        client.DefaultRequestHeaders.Add(TestAuthHandler.AllowedTenantsHeader, h.G);
        // Without this the principal is not a "Bearer" one and the tenant gate would skip every request.
        client.DefaultRequestHeaders.Add(TestAuthHandler.RealBearerPrincipalHeader, "true");

        var topology = await client.GetAsync($"{Route}?scope={h.R}", TestContext.Current.CancellationToken);
        // ToolsController: policy = read scope only, so the tenant gate is the only thing that can refuse.
        var foreignRoute = await client.GetAsync($"/{h.S}/v1/tools/generatePassword",
            TestContext.Current.CancellationToken);
        var ownRoute = await client.GetAsync($"/{h.R}/v1/tools/generatePassword",
            TestContext.Current.CancellationToken);

        topology.StatusCode.Should().Be(HttpStatusCode.OK);
        foreignRoute.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        ownRoute.StatusCode.Should().Be(HttpStatusCode.OK, "the same token is fine on its own tenant's route");
    }

    /// <summary>
    ///     CORS (checked with the origin pattern of the seed clients of meshmakers-app and energy-community): the
    ///     policy is global and built from the origins of every client of every tenant, so a browser app of such a
    ///     client can preflight and call the route with its bearer header.
    /// </summary>
    [Theory]
    [InlineData("https://acme-accounting.127-0-0-1.nip.io")]
    [InlineData("https://energy-community.127-0-0-1.nip.io")]
    public async Task AppOriginOfASeedClient_CanPreflightAndCallTheRouteFromTheBrowser(string origin)
    {
        var h = await EnsureHierarchyAsync();
        await AddClientWithOriginAsync(origin);

        var preflight = new HttpRequestMessage(HttpMethod.Options, $"{Route}?scope={h.R}");
        preflight.Headers.Add("Origin", origin);
        preflight.Headers.Add("Access-Control-Request-Method", "GET");
        preflight.Headers.Add("Access-Control-Request-Headers", "authorization");
        var preflightResponse = await CreateAnonymousClient().SendAsync(preflight, TestContext.Current.CancellationToken);

        preflightResponse.Headers.GetValues("Access-Control-Allow-Origin").Should().ContainSingle().Which.Should().Be(origin);
        preflightResponse.Headers.TryGetValues("Access-Control-Allow-Headers", out var allowedHeaders).Should().BeTrue();
        string.Join(",", allowedHeaders!).Should().ContainEquivalentOf("authorization");

        var call = new HttpRequestMessage(HttpMethod.Get, $"{Route}?scope={h.R}");
        call.Headers.Add("Origin", origin);
        call.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        call.Headers.Add("X-Test-UserId", $"topo-{Guid.NewGuid():N}");
        call.Headers.Add(TestAuthHandler.TenantIdHeader, h.R);
        call.Headers.Add(TestAuthHandler.AllowedTenantsHeader, h.G);
        var callResponse = await Factory.CreateClient().SendAsync(call, TestContext.Current.CancellationToken);

        callResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        callResponse.Headers.GetValues("Access-Control-Allow-Origin").Should().ContainSingle().Which.Should().Be(origin);
    }

    [Fact]
    public async Task UnknownOrigin_GetsNoCorsHeader()
    {
        var h = await EnsureHierarchyAsync();
        var preflight = new HttpRequestMessage(HttpMethod.Options, $"{Route}?scope={h.R}");
        preflight.Headers.Add("Origin", "https://evil.example");
        preflight.Headers.Add("Access-Control-Request-Method", "GET");

        var response = await CreateAnonymousClient().SendAsync(preflight, TestContext.Current.CancellationToken);

        response.Headers.Contains("Access-Control-Allow-Origin").Should().BeFalse();
    }

    private async Task AddClientWithOriginAsync(string origin)
    {
        using var scope = Factory.Services.CreateScope();
        var systemContext = scope.ServiceProvider.GetRequiredService<ISystemContext>();
        var repository = (await systemContext.TryFindTenantRepositoryAsync(systemContext.TenantId))!;
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        await repository.InsertOneRtEntityAsync(session, new RtClientBuilder()
            .WithClientId($"app-{Guid.NewGuid():N}")
            .WithCorsOrigins(origin)
            .Build());
        await session.CommitTransactionAsync();

        // The CORS policy is cached for CorsPolicyCacheSeconds; the event that normally clears it is
        // disabled in tests.
        Factory.Services.GetRequiredService<Meshmakers.Octo.Backend.IdentityServices.Services.IdentityCorsPolicyProvider>()
            .InvalidateCache();
    }
}
