using System.Net;
using System.Security.Claims;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Configuration;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     <c>Client.SetMirrorRoles-1</c> on the real host - the caller rule (TenantManagement in the tenant of the
///     original), the deny-list, confidential clients only, a mirror as target, the role change guard (role not held,
///     self-grant), the dry run, one audit event per call, and the effect on the wire: the mirror's client-credentials token
///     in a child carries the mirrored role and passes the method authorization there, the same client gains nothing in a
///     tenant that declined it, and the original's system-tenant token gains nothing in a child.
/// </summary>
public class ClientSetMirrorRolesMethodTests : IntegrationTestBase, IDisposable
{
    private const string Deploy = "CommunicationManagement";
    private const string ApiScope = "octo_api";
    private const string AdminSubject = "507f1f77bcf86cd799439013";
    private static readonly string[] ChildRoles = [Deploy, "DashboardViewer", "TenantManagement", "UserManagement"];

    private readonly WebApplicationFactory<Program> _host;
    private readonly RecordingAudit _audit = new();

    public ClientSetMirrorRolesMethodTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _host = factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Methods:Identity:EnablePasswordMethods", "true");
            b.ConfigureTestServices(services =>
            {
                // The test host has no broker: drop the bus side of the method host.
                foreach (var descriptor in services
                             .Where(d => d.ImplementationType?.Name is "CkMethodHandlerStartupService"
                                 or "CkMethodHandlerHeartbeatService").ToList())
                {
                    services.Remove(descriptor);
                }

                services.AddSingleton<IIdentityMethodAuditWriter>(_audit);
            });
        });
    }

    public void Dispose()
    {
        _host.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task TenantAdministrator_SetsTheList_TheMirrorGetsTheRole_AndTheCallIsAuditedOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync();
        var child = await CreateChildTenantAsync();

        var outcome = await SetAsync(client, [Deploy], Admin(Deploy), ct);

        outcome.IsSuccess.Should().BeTrue(outcome.Failure?.Code);
        var tenant = outcome.Value!.Value!.Tenants.Single(t => t.ChildTenantId == child);
        tenant.Added.Should().Equal(Deploy);
        tenant.Outcome.Should().Be("Applied");
        (await StoredListAsync(client.ClientId)).Should().Equal(Deploy);
        (await MirrorRoleNamesAsync(child, client.ClientId)).Should().Equal(Deploy);
        _audit.For(client.RtId.ToString()).Should().ContainSingle("one Identity.Method event per call")
            .Which.Details!["roleNames"].Should().Be(Deploy);
    }

    [Fact]
    public async Task OmittedRoleNames_IsAValidationFailure_NeverAClearedList()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync();
        (await SetAsync(client, [Deploy], Admin(Deploy), ct)).IsSuccess.Should().BeTrue();

        var outcome = await SetAsync(client, null, Admin(Deploy), ct);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodValidationFailed);
        (await StoredListAsync(client.ClientId)).Should().Equal(Deploy);
    }

    [Fact]
    public async Task UserManagementAlone_IsRefused_AndNothingIsStored()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync();

        var outcome = await SetAsync(client, [Deploy],
            new CkMethodPrincipal(AdminSubject, ["UserManagement", Deploy], [ApiScope], null, NormalizedSystemTenantId),
            ct);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        (await StoredListAsync(client.ClientId)).Should().BeEmpty();
    }

    [Theory]
    [InlineData("TenantManagement")]
    [InlineData("UserManagement")]
    [InlineData("SecretManagement")]
    [InlineData("AdminPanelManagement")]
    [InlineData("AiBudgetAdmin")]
    public async Task DenyListedRole_IsRefusedWithMirrorRoleNotAllowed_AndNeverStored(string role)
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync();

        var outcome = await SetAsync(client, [Deploy, role], Admin(Deploy, role), ct);

        outcome.Failure!.Code.Should().Be("MIRROR_ROLE_NOT_ALLOWED");
        outcome.Failure.Parameters!["roleNames"].Should().Be(role);
        (await StoredListAsync(client.ClientId)).Should().BeEmpty();
        _audit.For(client.RtId.ToString()).Should().ContainSingle()
            .Which.Outcome.Should().Be("MIRROR_ROLE_NOT_ALLOWED", "a refusal is audited too");
    }

    [Fact]
    public async Task PublicClient_IsRefusedWithClientNotConfidential()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync(b => b.WithGrantTypes("authorization_code").RequireClientSecret(false));

        var outcome = await SetAsync(client, [Deploy], Admin(Deploy), ct);

        outcome.Failure!.Code.Should().Be("CLIENT_NOT_CONFIDENTIAL");
        (await StoredListAsync(client.ClientId)).Should().BeEmpty();
    }

    [Fact]
    public async Task RoleTheCallerDoesNotHold_IsRefused_RoleNotHeld()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync();

        var outcome = await SetAsync(client, [Deploy], Admin(), ct);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        outcome.Failure.Parameters!["reason"].Should().Be("role-not-held");
        (await StoredListAsync(client.ClientId)).Should().BeEmpty();
    }

    [Fact]
    public async Task ClientExtendingItsOwnList_IsRefused_SelfGrant()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync();
        var self = new CkMethodPrincipal(null, ["TenantManagement", Deploy], [ApiScope], client.ClientId,
            NormalizedSystemTenantId);

        var outcome = await SetAsync(client, [Deploy], self, ct);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        outcome.Failure.Parameters!["reason"].Should().Be("self-grant");
        (await StoredListAsync(client.ClientId)).Should().BeEmpty();
    }

    [Fact]
    public async Task AdministratorOfAChildTenant_CannotSetTheParentsList()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync();
        var child = await CreateChildTenantAsync();
        var childAdmin = new CkMethodPrincipal(AdminSubject, ["TenantManagement", Deploy], [ApiScope])
        {
            IsFromAccessToken = true,
            TokenTenantId = child
        };

        var outcome = await SetAsync(client, [Deploy], childAdmin, ct);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        outcome.Failure.Parameters!["reason"].Should().Be(CrossTenantMethodSupport.TenantOutOfScopeReason);
        (await StoredListAsync(client.ClientId)).Should().BeEmpty();
        (await MirrorRoleNamesAsync(child, client.ClientId)).Should().BeEmpty();
    }

    [Fact]
    public async Task TheMirrorAsTarget_IsRefused_OnlyTheOriginalCarriesAList()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync();
        var child = await CreateChildTenantAsync();
        var mirror = (await ChildClientAsync(child, client.ClientId))!;

        var outcome = await SetAsync(mirror, [Deploy], Admin(Deploy), ct, tenantId: child);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        outcome.Failure.Parameters!["reason"].Should().Be("mirror-client");
        (await MirrorRoleNamesAsync(child, client.ClientId)).Should().BeEmpty();
    }

    [Fact]
    public async Task DryRun_WritesNothing_AndAnswersThePlan()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync();
        var child = await CreateChildTenantAsync();

        var outcome = await SetAsync(client, [Deploy], Admin(Deploy), ct, dryRun: true);

        outcome.IsSuccess.Should().BeTrue(outcome.Failure?.Code);
        outcome.Value!.Value!.DryRun.Should().BeTrue();
        var tenant = outcome.Value.Value.Tenants.Single(t => t.ChildTenantId == child);
        tenant.Outcome.Should().Be("Planned");
        tenant.Added.Should().Equal(Deploy);
        (await StoredListAsync(client.ClientId)).Should().BeEmpty();
        (await MirrorRoleNamesAsync(child, client.ClientId)).Should().BeEmpty();
    }

    /// <summary>
    ///     The tokens on the wire: the mirror's client-credentials token in a child carries the mirrored
    ///     role and passes a method that declares it; the same client's token in a child that declined the role is refused
    ///     (<c>METHOD_FORBIDDEN</c>); the original's token of the system tenant gains nothing in a child (wrong tenant).
    /// </summary>
    [Fact]
    public async Task Tokens_MirrorTokenCarriesTheRoleOnlyWhereMirrored_AndTheOriginalsTokenGainsNothingInAChild()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync();
        var secret = await AddSecretAsync(client, ct);
        var granted = await CreateChildTenantAsync();
        var declined = await CreateChildTenantAsync();
        (await SetAsync(client, [Deploy], Admin(Deploy), ct)).IsSuccess.Should().BeTrue();
        await RemoveRoleEdgeAsync(declined, client.ClientId, Deploy); // the tenant takes it away
        (await SetAsync(client, [Deploy], Admin(Deploy), ct)).Value!.Value!.Tenants
            .Single(t => t.ChildTenantId == declined).Declined.Should().Equal(Deploy);

        var inGranted = await TokenPrincipalAsync(granted, client.ClientId, secret, ct);
        var inDeclined = await TokenPrincipalAsync(declined, client.ClientId, secret, ct);
        var inSystem = await TokenPrincipalAsync(NormalizedSystemTenantId, client.ClientId, secret, ct);

        var declaration = new CkMethodAuthorizationDto { Roles = new List<string> { Deploy } };
        var evaluator = new CkMethodAuthorizationEvaluator(Options.Create(new CkMethodAuthorizationOptions()));
        inGranted.Roles.Should().Contain(Deploy);
        evaluator.Evaluate(declaration, CkMethodKindDto.Instance, null, inGranted).Allowed.Should().BeTrue();
        inDeclined.Roles.Should().NotContain(Deploy);
        evaluator.Evaluate(declaration, CkMethodKindDto.Instance, null, inDeclined).Denial.Should()
            .Be(CkMethodDenial.NotAuthorized, "the gateway answers METHOD_FORBIDDEN");
        inSystem.Roles.Should().NotContain(Deploy, "the original itself holds no role through its list");
        CkMethodCallerTenantCheck.IsRefused(inSystem, granted, "System.Communication/Deploy-1",
                new TenantAuthorizationOptions(), out var refusal, out _)
            .Should().BeTrue("a token of the system tenant does not act in a child");
        refusal!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
    }

    // ---------- helpers ----------

    /// <summary>A tenant administrator of the system tenant, as the token validation maps the caller (tenant set).</summary>
    private CkMethodPrincipal Admin(params string[] extraRoles) =>
        new(AdminSubject, ["TenantManagement", .. extraRoles], [ApiScope], null, NormalizedSystemTenantId);

    private async Task<CkMethodOutcome<ClientSetMirrorRolesResult>> SetAsync(RtClient client, string[]? roleNames,
        CkMethodPrincipal caller, CancellationToken ct, bool dryRun = false, string? tenantId = null)
    {
        using var scope = _host.Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<ClientSetMirrorRolesHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<ClientSetMirrorRolesParameters>(
            Request(SystemIdentityCkIds.ClientSetMirrorRolesMethodId, client.RtId.ToString(),
                tenantId ?? NormalizedSystemTenantId),
            new ClientSetMirrorRolesParameters
            {
                RoleNames = roleNames?.ToList()!, DryRun = dryRun
            }) { CallerPrincipal = caller };
        return await handler.HandleAsync(context, ct);
    }

    private async Task<string> AddSecretAsync(RtClient client, CancellationToken ct)
    {
        using var scope = _host.Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<ClientAddSecretHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<ClientAddSecretParameters>(
            Request(SystemIdentityCkIds.ClientAddSecretMethodId, client.RtId.ToString(), NormalizedSystemTenantId),
            new ClientAddSecretParameters()) { CallerPrincipal = Admin() };
        var outcome = await handler.HandleAsync(context, ct);
        outcome.IsSuccess.Should().BeTrue();
        return outcome.Value!.Value!;
    }

    private static CkMethodRequest Request(string methodId, string target, string tenantId) => new(tenantId)
    {
        InvocationId = Guid.NewGuid(),
        MethodId = methodId,
        CkTypeId = "System.Identity/Client",
        TargetRtId = target,
        DeadlineUtc = TestHostMethodDeadlineFloor.DeadlineFromNow(),
        ParametersJson = "{}"
    };

    private async Task<RtClient> CreateClientAsync(Action<RtClientBuilder>? configure = null)
    {
        using var scope = _host.Services.CreateScope();
        await EnsureApiScopeAsync(await RepositoryAsync(NormalizedSystemTenantId));
        var builder = new RtClientBuilder().WithClientId($"m9923-{Guid.NewGuid():N}")
            .WithGrantTypes("client_credentials").WithScopes(ApiScope).RequireClientSecret().RequirePkce(false)
            .WithAutoProvisionInChildTenants();
        configure?.Invoke(builder);
        var client = builder.Build();
        await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().CreateAsync(client);
        return client;
    }

    /// <summary>A child of the system tenant with the seeded roles; its setup provisions every flagged mirror.</summary>
    private async Task<string> CreateChildTenantAsync()
    {
        var childTenantId = $"mrol{Guid.NewGuid():N}"[..20];
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, childTenantId, childTenantId);
            await session.CommitTransactionAsync();
        }

        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IDefaultConfigurationCreatorService>()
                .SetupAsync(childTenantId);
        }

        var repo = await RepositoryAsync(childTenantId);
        await EnsureApiScopeAsync(repo);
        await EnsureRolesAsync(repo);
        await WaitUntilRegistryKnowsAsync(childTenantId);
        return childTenantId;
    }

    private static async Task EnsureApiScopeAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        var existing = await repo.GetRtEntitiesByTypeAsync<RtApiScope>(session, RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiScope.Name), FieldFilterOperator.Equals, ApiScope));
        if (existing.Items.Any())
        {
            return;
        }

        await repo.InsertOneRtEntityAsync(session, new RtApiScope
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = ApiScope,
            DisplayName = "Octo API",
            Enabled = true,
            ShowInDiscoveryDocument = true,
            Claims = new AttributeStringValueList(),
            IsEmphasized = false,
            IsRequired = false
        });
    }

    private static async Task EnsureRolesAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        var existing = (await repo.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create())).Items
            .Select(r => r.NormalizedName).ToHashSet(StringComparer.Ordinal);
        foreach (var name in ChildRoles.Where(n => !existing.Contains(n.ToUpperInvariant())))
        {
            await repo.InsertOneRtEntityAsync(session, new RtRole
            {
                RtId = OctoObjectId.GenerateNewId(), Name = name, NormalizedName = name.ToUpperInvariant()
            });
        }
    }

    private async Task WaitUntilRegistryKnowsAsync(string tenantId)
    {
        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(tenantId) != null)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException($"Tenant '{tenantId}' did not appear in the tenant registry");
    }

    private async Task<ITenantRepository> RepositoryAsync(string tenantId) =>
        (await Factory.Services.GetRequiredService<ISystemContext>().TryFindTenantRepositoryAsync(tenantId))!;

    private async Task<RtClient?> ChildClientAsync(string tenantId, string clientId)
    {
        var repo = await RepositoryAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtClient>(session, RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId))).Items.SingleOrDefault();
    }

    private async Task<List<string>> StoredListAsync(string clientId) =>
        (await ChildClientAsync(NormalizedSystemTenantId, clientId))!.MirrorRoleNames?.ToList() ?? [];

    private async Task<List<string>> MirrorRoleNamesAsync(string tenantId, string clientId)
    {
        var repo = await RepositoryAsync(tenantId);
        var mirror = (await ChildClientAsync(tenantId, clientId))!;
        using var session = await repo.GetSessionAsync();
        var edges = await repo.GetRtAssociationsAsync(session, mirror.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        var names = new List<string>();
        foreach (var edge in edges.Items)
        {
            names.Add((await repo.GetRtEntityByRtIdAsync<RtRole>(session, edge.TargetRtId))?.Name ?? "?");
        }

        return names;
    }

    private async Task RemoveRoleEdgeAsync(string tenantId, string clientId, string roleName)
    {
        var repo = await RepositoryAsync(tenantId);
        var mirror = (await ChildClientAsync(tenantId, clientId))!;
        using var session = await repo.GetSessionAsync();
        var role = (await repo.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtRole.NormalizedName), FieldFilterOperator.Equals, roleName.ToUpperInvariant())))
            .Items.Single();
        session.StartTransaction();
        var result = new OperationResult();
        await repo.ApplyChangesAsync(session,
            [AssociationUpdateInfo.CreateDelete(mirror.ToRtEntityId(), role.ToRtEntityId(),
                IdentityAssociationConstants.AssignedRoleId)], result);
        await session.CommitTransactionAsync();
    }

    /// <summary>
    ///     The caller principal the method gateway maps from a real client-credentials token of the tenant. The token is
    ///     only parsed (the host just issued it), never printed.
    /// </summary>
    private async Task<CkMethodPrincipal> TokenPrincipalAsync(string tenantId, string clientId, string secret,
        CancellationToken ct)
    {
        using var http = _host.CreateClient();
        var response = await http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = secret,
                ["scope"] = ApiScope,
                ["acr_values"] = $"tenant:{tenantId}"
            }), ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, $"a token for tenant '{tenantId}'");
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!;
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(body["access_token"]!.GetValue<string>());
        return CkMethodPrincipal.FromClaimsPrincipal(new ClaimsPrincipal(new ClaimsIdentity(jwt.Claims, "test")));
    }

    private sealed class RecordingAudit : IIdentityMethodAuditWriter
    {
        private readonly List<(string Target, string Outcome, IReadOnlyDictionary<string, string>? Details)> _records =
            [];

        public List<(string Target, string Outcome, IReadOnlyDictionary<string, string>? Details)> For(string target)
        {
            lock (_records)
            {
                return _records.Where(r => r.Target == target).ToList();
            }
        }

        public Task RecordAsync(string tenantId, string methodId, Guid invocationId, string? targetRtId,
            string? callerSubject, string outcome, IReadOnlyDictionary<string, string>? extraDetails = null)
        {
            lock (_records)
            {
                _records.Add((targetRtId ?? string.Empty, outcome, extraDetails));
            }

            return Task.CompletedTask;
        }
    }
}
