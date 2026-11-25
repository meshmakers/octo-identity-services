using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.ServiceAccountExchange;
using IdentityServerPersistence.Services.SourceTenantGrants;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#9777 — <see cref="ServiceAccountExchangeGate" /> against a real MongoDB with a registry hierarchy below the
///     system tenant: <c>G</c> with children <c>A</c> and <c>B</c>, grandchild <c>C</c> below <c>A</c>, and an unrelated
///     top-level tenant <c>X</c> with child <c>Y</c>. Every abuse case of the story is one test; the roles of T never
///     appear in the decision for U.
/// </summary>
public class ServiceAccountExchangeGateIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;
    private readonly HashSet<(string Source, string Target)> _permitted = [];
    private readonly IClientMirrorProvisioningService _mirrors = Substitute.For<IClientMirrorProvisioningService>();

    public ServiceAccountExchangeGateIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
        _mirrors.GetMirrorsAsync(Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<IReadOnlyList<RtClientMirror>>([]));
    }

    [Fact]
    public async Task Parent_ProvisionedAndPermitted_IsAdmitted_WithExactlyTheTargetRoles()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.A, roleNameInSource: "SourceOnlyAdmin");
        await ProvisionShadowAsync(h.G, h.A, client, "TargetReader");
        _permitted.Add((h.A, h.G));

        var decision = await CreateGate().EvaluateAsync(h.A, client, h.G);

        decision.IsAdmitted.Should().BeTrue(decision.Reason);
        decision.Relation.Should().Be(ServiceAccountExchangeRelation.Parent);
        decision.ShadowClient!.ClientId.Should().Be(CrossTenantShadowUserName.Build(h.A, client));
        decision.RoleNames.Should().BeEquivalentTo(["TargetReader"],
            "only roles assigned in the target count; the source role never crosses the boundary");
    }

    [Fact]
    public async Task Child_Provisioned_IsAdmitted_WithoutTheAllowList()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.G, roleNameInSource: "GroupAdmin");
        await ProvisionShadowAsync(h.A, h.G, client, "CompanyWriter");

        var decision = await CreateGate().EvaluateAsync(h.G, client, h.A);

        decision.IsAdmitted.Should().BeTrue(decision.Reason);
        decision.Relation.Should().Be(ServiceAccountExchangeRelation.Child);
        decision.RoleNames.Should().BeEquivalentTo(["CompanyWriter"]);
    }

    [Fact]
    public async Task Sibling_ProvisionedAndPermitted_IsAdmitted()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.A);
        await ProvisionShadowAsync(h.B, h.A, client, "SiblingReader");
        _permitted.Add((h.A, h.B));

        var decision = await CreateGate().EvaluateAsync(h.A, client, h.B);

        decision.IsAdmitted.Should().BeTrue(decision.Reason);
        decision.Relation.Should().Be(ServiceAccountExchangeRelation.Sibling);
    }

    [Fact]
    public async Task Sibling_ProvisionedButNotPermittedBySource_IsRefused()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.A);
        await ProvisionShadowAsync(h.B, h.A, client, "SiblingReader");

        var decision = await CreateGate().EvaluateAsync(h.A, client, h.B);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.NotPermitted);
        decision.ShadowClient.Should().BeNull();
    }

    [Fact]
    public async Task Parent_ProvisionedButNotPermittedBySource_IsRefused()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.A);
        await ProvisionShadowAsync(h.G, h.A, client, "TargetReader");

        var decision = await CreateGate().EvaluateAsync(h.A, client, h.G);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.NotPermitted);
    }

    [Fact]
    public async Task NoShadowClientInTarget_IsNotProvisioned()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.G, roleNameInSource: "GroupAdmin");

        var decision = await CreateGate().EvaluateAsync(h.G, client, h.A);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.NotProvisioned,
            "ancestry is not authority: without provisioning in the target no role is granted (AB#6839)");
    }

    [Fact]
    public async Task ShadowClientWithoutRole_IsNotProvisioned()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.G);
        await ProvisionShadowAsync(h.A, h.G, client, roleName: null);

        var decision = await CreateGate().EvaluateAsync(h.G, client, h.A);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.NotProvisioned);
    }

    [Fact]
    public async Task DisabledShadowClient_IsNotProvisioned()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.G);
        await ProvisionShadowAsync(h.A, h.G, client, "CompanyWriter", enabled: false);

        var decision = await CreateGate().EvaluateAsync(h.G, client, h.A);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.NotProvisioned);
    }

    [Fact]
    public async Task ShadowClientThatIsAMirror_IsNotProvisioned()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.G);
        await ProvisionShadowAsync(h.A, h.G, client, "CompanyWriter", provisionedByParent: h.G);

        var decision = await CreateGate().EvaluateAsync(h.G, client, h.A);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.NotProvisioned,
            "a mirror was written by the parent, not provisioned by the target's administrator");
    }

    [Theory]
    [InlineData("client_credentials")]
    [InlineData("authorization_code")]
    [InlineData("refresh_token")]
    [InlineData("device_code")]
    [InlineData("redirect")]
    [InlineData("offline")]
    [InlineData("secret")]
    public async Task ShadowClientThatCanDoMoreThanTheExchange_IsRefused(string capability)
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.G);
        await ProvisionShadowAsync(h.A, h.G, client, "CompanyWriter", shape: shadow =>
        {
            switch (capability)
            {
                case "redirect":
                    shadow.RedirectUris = new Shared.TestUtilities.Builders.RtClientBuilder()
                        .WithRedirectUris("https://evil.example/cb").Build().RedirectUris;
                    break;
                case "offline":
                    shadow.AllowOfflineAccess = true;
                    break;
                case "secret":
                    shadow.RequireClientSecret = true;
                    break;
                default:
                    shadow.AllowedGrantTypes!.Add(capability == "device_code"
                        ? "urn:ietf:params:oauth:grant-type:device_code"
                        : capability);
                    break;
            }
        });

        var decision = await CreateGate().EvaluateAsync(h.G, client, h.A);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.ShadowClientNotExchangeOnly, decision.Reason);
    }

    [Fact]
    public async Task ShadowNameInAnotherCase_IsNotTheShadowClient()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.G, clientId: $"Svc-{Guid.NewGuid():N}"[..20]);
        await ProvisionShadowAsync(h.A, h.G, client.ToLowerInvariant(), "CompanyWriter");

        var decision = await CreateGate().EvaluateAsync(h.G, client, h.A);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.NotProvisioned,
            "the shadow name is compared exactly");
    }

    [Theory]
    [InlineData("flag")]
    [InlineData("mirror")]
    [InlineData("tracked")]
    public async Task MirroredSubjectClient_IsRefused(string kind)
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.A, autoProvision: kind == "flag",
            provisionedByParent: kind == "mirror" ? h.G : null);
        if (kind == "tracked")
        {
            _mirrors.GetMirrorsAsync(h.A, client).Returns(Task.FromResult<IReadOnlyList<RtClientMirror>>(
                [new RtClientMirror { RtId = OctoObjectId.GenerateNewId() }]));
        }

        await ProvisionShadowAsync(h.G, h.A, client, "TargetReader");
        _permitted.Add((h.A, h.G));

        var decision = await CreateGate().EvaluateAsync(h.A, client, h.G);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.MirroredClient);
    }

    [Fact]
    public async Task Grandchild_IsNotRelated()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.G);
        await ProvisionShadowAsync(h.C, h.G, client, "DeepReader");

        var decision = await CreateGate().EvaluateAsync(h.G, client, h.C);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.NotRelated, "no Descendant relation in v1");
    }

    [Fact]
    public async Task Grandparent_IsNotRelated()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.C);
        await ProvisionShadowAsync(h.G, h.C, client, "TargetReader");
        _permitted.Add((h.C, h.G));

        var decision = await CreateGate().EvaluateAsync(h.C, client, h.G);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.NotRelated);
    }

    [Fact]
    public async Task Cousin_IsNotRelated()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.A);
        await ProvisionShadowAsync(h.Y, h.A, client, "StrangerReader");
        _permitted.Add((h.A, h.Y));

        var decision = await CreateGate().EvaluateAsync(h.A, client, h.Y);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.NotRelated);
    }

    [Fact]
    public async Task TopLevelTenants_AreNoSiblings()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.G);
        await ProvisionShadowAsync(h.X, h.G, client, "CustomerReader");
        _permitted.Add((h.G, h.X));

        var decision = await CreateGate().EvaluateAsync(h.G, client, h.X);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.NotRelated,
            "children of the system tenant are unrelated customers");
    }

    [Fact]
    public async Task SystemTenant_AsTargetOrSource_IsRefused()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.G);
        var gate = CreateGate();

        (await gate.EvaluateAsync(h.G, client, h.System)).Refusal.Should().Be(ServiceAccountExchangeRefusal.SystemTenant);
        (await gate.EvaluateAsync(h.System, client, h.G)).Refusal.Should().Be(ServiceAccountExchangeRefusal.SystemTenant);
    }

    [Fact]
    public async Task UnregisteredTarget_IsRefused()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.A);

        var decision = await CreateGate().EvaluateAsync(h.A, client, "no-such-tenant-9777");

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.UnknownTenant);
    }

    [Fact]
    public async Task UnknownOrDisabledSubjectClient_IsRefused()
    {
        var h = await ArrangeAsync();
        var disabled = await CreateServiceAccountAsync(h.G, enabled: false);
        await ProvisionShadowAsync(h.A, h.G, disabled, "CompanyWriter");
        await ProvisionShadowAsync(h.A, h.G, "never-created", "CompanyWriter");
        var gate = CreateGate();

        (await gate.EvaluateAsync(h.G, disabled, h.A)).Refusal.Should()
            .Be(ServiceAccountExchangeRefusal.SourceClientUnknown);
        (await gate.EvaluateAsync(h.G, "never-created", h.A)).Refusal.Should()
            .Be(ServiceAccountExchangeRefusal.SourceClientUnknown);
    }

    [Fact]
    public async Task ShadowSubject_IsRefused_NoChains()
    {
        var h = await ArrangeAsync();
        var shadowAsSubject = await CreateServiceAccountAsync(h.A, clientId: CrossTenantShadowUserName.Build(h.G, "svc"));

        var decision = await CreateGate().EvaluateAsync(h.A, shadowAsSubject, h.B);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.AmbiguousSubject);
    }

    [Fact]
    public async Task ShadowNameThatAlsoReadsAsAnotherTenantsClient_IsRefused()
    {
        // Adds a tenant to the hierarchy, so it gets a hierarchy of its own.
        var h = await ArrangeFreshAsync();
        // Tenant "<A>_b" exists, so xt_<A>_b_svc names client "b_svc" of A as well as client "svc" of "<A>_b".
        await CreateTenantAsync(h.G, $"{h.A}_b");
        var client = await CreateServiceAccountAsync(h.A, clientId: "b_svc");
        await ProvisionShadowAsync(h.G, h.A, client, "TargetReader");
        _permitted.Add((h.A, h.G));

        var decision = await CreateGate().EvaluateAsync(h.A, client, h.G);

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.AmbiguousSubject);
    }

    [Fact]
    public async Task SameTenant_IsRefused()
    {
        var h = await ArrangeAsync();
        var client = await CreateServiceAccountAsync(h.A);

        (await CreateGate().EvaluateAsync(h.A, client, h.A)).Refusal.Should()
            .Be(ServiceAccountExchangeRefusal.SameTenant);
    }

    // ---------- arrangement ----------

    private sealed record Hierarchy(string System, string G, string A, string B, string C, string X, string Y);

    // xUnit creates a new instance of this class per test, while the IdentityServicesFixture (and its databases)
    // lives for the whole class. Creating the six tenants takes about 20 s, so the hierarchy is built once per
    // fixture and shared by every test that only adds its own clients and roles to it (each test uses fresh client
    // ids). A test that changes the tenant structure itself (adds, re-parents, disables or deletes a tenant) or a
    // tenant's state (generation, allow-list) uses ArrangeFreshAsync instead.
    private static readonly SemaphoreSlim SharedHierarchyLock = new(1, 1);
    private static (IdentityServicesFixture Fixture, Hierarchy Hierarchy)? _sharedHierarchy;

    private async Task<Hierarchy> ArrangeAsync()
    {
        await SharedHierarchyLock.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            if (_sharedHierarchy is { } shared && ReferenceEquals(shared.Fixture, _fixture))
            {
                return shared.Hierarchy;
            }

            var hierarchy = await ArrangeFreshAsync();
            _sharedHierarchy = (_fixture, hierarchy);
            return hierarchy;
        }
        finally
        {
            SharedHierarchyLock.Release();
        }
    }

    private async Task<Hierarchy> ArrangeFreshAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(systemContext.TenantId);

        var g = await CreateTenantAsync(systemContext.TenantId, NewId("g"));
        var a = await CreateTenantAsync(g, NewId("a"));
        var b = await CreateTenantAsync(g, NewId("b"));
        var c = await CreateTenantAsync(a, NewId("c"));
        var x = await CreateTenantAsync(systemContext.TenantId, NewId("x"));
        var y = await CreateTenantAsync(x, NewId("y"));
        return new Hierarchy(systemContext.TenantId, g, a, b, c, x, y);
    }

    private ServiceAccountExchangeGate CreateGate()
    {
        var systemContext = _fixture.GetSystemContext();
        var policy = Substitute.For<ISourceTenantGrantPolicy>();
        policy.IsPermittedAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(call => _permitted.Contains((call.ArgAt<string>(0), call.ArgAt<string>(1))));
        return new ServiceAccountExchangeGate(
            systemContext,
            new TenantRegistry(systemContext, new MemoryCache(new MemoryCacheOptions())),
            policy,
            _mirrors,
            new CrossTenantShadowUserChainResolver(systemContext),
            NullLogger<ServiceAccountExchangeGate>.Instance);
    }

    private static string NewId(string prefix) => $"sa{prefix}-{Guid.NewGuid():N}"[..16];

    private async Task<string> CreateTenantAsync(string parentTenantId, string tenantId)
    {
        var systemContext = _fixture.GetSystemContext();
        ITenantContext parent = parentTenantId == systemContext.TenantId
            ? systemContext
            : (await systemContext.TryFindTenantContextAsync(parentTenantId))!;
        using (var session = await parent.GetAdminSessionAsync())
        {
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

        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantId);
        return tenantId;
    }

    private async Task<ITenantRepository> RepositoryAsync(string tenantId)
        => (await _fixture.GetSystemContext().TryFindTenantRepositoryAsync(tenantId))!;

    /// <summary>A client-credentials service account in <paramref name="tenantId" />, optionally holding a role there.</summary>
    private async Task<string> CreateServiceAccountAsync(string tenantId, string? roleNameInSource = null,
        string? clientId = null, bool enabled = true, bool autoProvision = false, string? provisionedByParent = null)
    {
        clientId ??= $"octo-pipeline-sa-{Guid.NewGuid():N}"[..28];
        var repo = await RepositoryAsync(tenantId);
        var rtId = await InsertClientAsync(repo, clientId, enabled, requireSecret: true, autoProvision,
            provisionedByParent);
        if (roleNameInSource != null)
        {
            await AssignRoleAsync(repo, rtId, roleNameInSource);
        }

        return clientId;
    }

    /// <summary>What U's administrator does: registers <c>xt_{T}_{clientId}</c> in U and assigns roles of U.</summary>
    private async Task ProvisionShadowAsync(string targetTenantId, string sourceTenantId, string sourceClientId,
        string? roleName, bool enabled = true, string? provisionedByParent = null, Action<RtClient>? shape = null)
    {
        var repo = await RepositoryAsync(targetTenantId);
        var rtId = await InsertClientAsync(repo, CrossTenantShadowUserName.Build(sourceTenantId, sourceClientId),
            enabled, requireSecret: false, autoProvision: false, provisionedByParent, shape);
        if (roleName != null)
        {
            await AssignRoleAsync(repo, rtId, roleName);
        }
    }

    private static async Task<OctoObjectId> InsertClientAsync(ITenantRepository repo, string clientId, bool enabled,
        bool requireSecret, bool autoProvision, string? provisionedByParent, Action<RtClient>? shape = null)
    {
        var rtId = OctoObjectId.GenerateNewId();
        var client = new RtClient
        {
            RtId = rtId,
            Enabled = enabled,
            ClientId = clientId,
            ProtocolType = "oidc",
            RequireClientSecret = requireSecret,
            AutoProvisionInChildTenants = autoProvision,
            ProvisionedByParentTenantId = provisionedByParent,
            AllowedGrantTypes = new AttributeStringValueList
            {
                requireSecret ? "client_credentials" : "urn:ietf:params:oauth:grant-type:token-exchange"
            },
            AllowedScopes = new AttributeStringValueList { "octo_api" }
        };
        shape?.Invoke(client);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, client);
        await session.CommitTransactionAsync();
        return rtId;
    }

    private async Task AssignRoleAsync(ITenantRepository repo, OctoObjectId clientRtId, string roleName)
    {
        using (var session = await repo.GetSessionAsync())
        {
            session.StartTransaction();
            // The shared hierarchy is used by several tests: create each role of a tenant once.
            var existing = await repo.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtRole.NormalizedName), FieldFilterOperator.Equals, roleName.ToUpperInvariant()));
            if (!existing.Items.Any())
            {
                await repo.InsertOneRtEntityAsync(session, new RtRole
                {
                    RtId = OctoObjectId.GenerateNewId(),
                    Name = roleName,
                    NormalizedName = roleName.ToUpperInvariant()
                });
            }

            await session.CommitTransactionAsync();
        }

        var resolver = new FixedTenantResolver(repo);
        var roleStore = new ClientRoleStore(resolver,
            new GroupRoleResolver(new GroupStore(resolver), new ExternalTenantUserMappingStore(resolver),
                new CrossTenantShadowUserChainResolver(_fixture.GetSystemContext())),
            NullLogger<ClientRoleStore>.Instance);
        await roleStore.AddRoleAsync(clientRtId, roleName);
    }
}
