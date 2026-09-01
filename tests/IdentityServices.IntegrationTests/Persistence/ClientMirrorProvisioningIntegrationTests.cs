using AutoMapper;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Http;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// End-to-end checks of the cross-tenant client mirroring (Phase 1). Run against a
/// real MongoDB (Testcontainers) with the full Octo runtime engine wired up. Pin the
/// behaviour every consumer of this feature (CI/CD client roll-out, future Studio UI)
/// depends on: mirrors materialize, secrets propagate, cleanup happens on delete.
/// </summary>
[Collection("Sequential")]
public class ClientMirrorProvisioningIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public ClientMirrorProvisioningIntegrationTests(
        IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task FlaggedClient_ProvisionsIntoChildTenant_MirrorPersisted()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-fresh-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"flagged-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);

        var result = await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        result.NewlyProvisioned.Should().BeGreaterThanOrEqualTo(1,
            "the flagged client must reach the new child");
        (await ChildHasClientAsync(systemContext, childTenantId, clientId)).Should().BeTrue();
        (await ParentHasMirrorAsync(systemContext, clientId, childTenantId)).Should().BeTrue();

        // The child-side mirror must carry the marker so sub-tenant admins know
        // it's not their own client (#4050).
        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        childClient!.ProvisionedByParentTenantId.Should().Be(systemContext.TenantId);
        childClient.AutoProvisionInChildTenants.Should().BeFalse(
            "a mirror must never itself trigger further mirroring");
    }

    [Fact]
    public async Task ProvisionForChildTenantAsync_IsIdempotent()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-idem-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"flagged-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);

        var first = await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);
        var second = await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        first.NewlyProvisioned.Should().BeGreaterThanOrEqualTo(1);
        // After the second run, the mirror is already there → AlreadyPresent must include it.
        second.AlreadyPresent.Should().BeGreaterThanOrEqualTo(1);
        second.NewlyProvisioned.Should().Be(0,
            "second run must not create a duplicate tracking row");
    }

    [Fact]
    public async Task ProvisionForAllChildTenantsAsync_Backfill_HitsEveryChild()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var clientId = $"backfill-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);

        // Three pre-existing child tenants — flag is already on, but no per-child
        // provisioning has run yet because we haven't called SetupTenantAsync on them.
        var t1 = await CreateChildTenantAsync($"backfill-a-{Guid.NewGuid():N}".Substring(0, 24));
        var t2 = await CreateChildTenantAsync($"backfill-b-{Guid.NewGuid():N}".Substring(0, 24));
        var t3 = await CreateChildTenantAsync($"backfill-c-{Guid.NewGuid():N}".Substring(0, 24));

        var result = await service.ProvisionForAllChildTenantsAsync(systemContext.TenantId, clientId);

        result.Should().NotBeNull();
        // Multiple sibling tests share the same fixture / system tenant, so other tests'
        // children stick around — only assert that ours are at least covered.
        (await ParentHasMirrorAsync(systemContext, clientId, t1)).Should().BeTrue();
        (await ParentHasMirrorAsync(systemContext, clientId, t2)).Should().BeTrue();
        (await ParentHasMirrorAsync(systemContext, clientId, t3)).Should().BeTrue();
    }

    [Fact]
    public async Task SyncMirrorsForClientAsync_RotatesSecret_BumpsVersion()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-rot-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"rotation-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId, secretHash: "initial-hash");
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var versionBefore = await GetMirrorSecretVersionAsync(systemContext, clientId, childTenantId);

        // Rotate the parent's secret + call sync.
        var rotatedParent = await UpdateParentClientSecretAsync(systemContext, clientId, "rotated-hash");
        var syncResult = await service.SyncMirrorsForClientAsync(systemContext.TenantId, rotatedParent);

        syncResult.MirrorsSynced.Should().BeGreaterThanOrEqualTo(1);
        var versionAfter = await GetMirrorSecretVersionAsync(systemContext, clientId, childTenantId);
        versionAfter.Should().BeGreaterThan(versionBefore);

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        childClient.Should().NotBeNull();
        childClient!.ClientSecrets.Select(s => s.Value).Should().Contain("rotated-hash");
    }

    [Fact]
    public async Task RemoveMirrorsForClientAsync_DeletesChildClientAndTrackingRow()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-del-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"to-delete-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var cleanup = await service.RemoveMirrorsForClientAsync(systemContext.TenantId, clientId);

        cleanup.MirrorsRemoved.Should().BeGreaterThanOrEqualTo(1);
        (await ChildHasClientAsync(systemContext, childTenantId, clientId)).Should().BeFalse();
        (await ParentHasMirrorAsync(systemContext, clientId, childTenantId)).Should().BeFalse();
    }

    [Fact]
    public async Task RemoveMirrorsForChildTenantAsync_DropsTrackingForDeletedTenant()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var doomedTenantId = await CreateChildTenantAsync($"child-tdel-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"tdel-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, doomedTenantId);

        var removed = await service.RemoveMirrorsForChildTenantAsync(systemContext.TenantId, doomedTenantId);

        removed.Should().BeGreaterThanOrEqualTo(1);
        (await ParentHasMirrorAsync(systemContext, clientId, doomedTenantId)).Should().BeFalse();
    }

    /// <summary>
    ///     AB#5058 — the token endpoint must refuse to guess a tenant for a mirrored client id.
    ///     Runs the real <see cref="ClientCredentialsRoleTokenValidator" /> over the real mirror
    ///     bookkeeping in MongoDB: the unit tests stub <c>GetMirrorsAsync</c>, so only this test
    ///     proves that a mirror actually provisioned into a child tenant is what makes the id
    ///     ambiguous.
    /// </summary>
    [Fact]
    public async Task MirroredClient_TokenRequestWithoutAcrValues_IsRefused()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-amb-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"amb-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        // Same client id and secret now live in both tenants — "resolved in the system tenant" no
        // longer implies "belongs to the system tenant".
        (await ChildHasClientAsync(systemContext, childTenantId, clientId)).Should().BeTrue();

        var context = CreateClientCredentialsContext(clientId);
        await CreateTokenValidator(systemContext, clientId, service)
            .ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result!.IsError.Should().BeTrue("a mirrored client id has no unambiguous home tenant");
        context.Result.Error.Should().Be("invalid_request");
        context.Result.ValidatedRequest.ClientClaims.Should()
            .NotContain(c => c.Type == ClientCredentialsRoleTokenValidator.TenantIdClaimType,
                "the system tenant must never be stamped on a guess");
    }

    /// <summary>
    ///     AB#5058 backwards-compatibility twin of the test above: a client that was never mirrored
    ///     keeps the AB#5032 behaviour, so the callers that omit <c>acr_values</c> today are unaffected.
    /// </summary>
    [Fact]
    public async Task UnmirroredClient_TokenRequestWithoutAcrValues_StillCarriesTheSystemTenant()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var clientId = $"solo-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateUnflaggedClientAsync(systemContext, clientId);

        var context = CreateClientCredentialsContext(clientId);
        await CreateTokenValidator(systemContext, clientId, service)
            .ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result!.IsError.Should().BeFalse();
        context.Result.ValidatedRequest.ClientClaims.Should()
            .ContainSingle(c => c.Type == ClientCredentialsRoleTokenValidator.TenantIdClaimType)
            .Which.Value.Should().Be(systemContext.TenantId);
    }

    // ---------- AB#5061: per-tenant mirror secrets ----------

    /// <summary>
    ///     The headline guarantee against a real database: the mirror materialized in the child
    ///     tenant carries a secret that is <b>its own</b>, not the parent's copy.
    /// </summary>
    [Fact]
    public async Task MirrorOfConfidentialClient_CarriesAnOwnSecret_DistinctFromTheParents()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-own-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"ownsec-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId, secretHash: "parent-hash");
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        childClient.Should().NotBeNull();

        var ownSecret = ClientMirrorSecrets.FindOwnSecret(childClient!);
        ownSecret.Should().NotBeNull("the mirror needs a credential that proves this tenant only");
        ownSecret!.Value.Should().NotBe("parent-hash");

        // ⚠️ …and the inherited parent secret is still there. That is the open half of AB#5061:
        // ci-deploy / octo-ai-adapter / claude-agent still authenticate with it against child
        // tenants, so it cannot be dropped in the same step.
        childClient!.ClientSecrets.Select(s => s.Value).Should().Contain("parent-hash");
    }

    /// <summary>
    ///     🔴 The preservation guarantee end to end. A parent-side secret rotation rewrites every
    ///     mirror from the parent's state; the per-tenant credential must survive it, or every
    ///     rotation would silently lock out everyone who was issued one.
    /// </summary>
    [Fact]
    public async Task ParentSecretRotation_DoesNotInvalidateAnIssuedMirrorSecret()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-keep-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"keepsec-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId, secretHash: "initial-hash");
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var issued = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);
        issued.Should().NotBeNull();
        issued!.Secret.Should().NotBeNullOrWhiteSpace();
        var issuedHash = ClientMirrorSecrets.Sha256(issued.Secret!);

        var rotatedParent = await UpdateParentClientSecretAsync(systemContext, clientId, "rotated-hash");
        await service.SyncMirrorsForClientAsync(systemContext.TenantId, rotatedParent);

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        childClient!.ClientSecrets.Select(s => s.Value).Should()
            .Contain("rotated-hash", "the parent's new secret still propagates")
            .And.Contain(issuedHash, "the tenant's own credential must survive a parent rotation");
    }

    /// <summary>
    ///     Rotation is the only path that ever reveals a mirror secret, and it invalidates the
    ///     previous one — this is both the distribution mechanism and the rotation mechanism.
    /// </summary>
    [Fact]
    public async Task RotateMirrorSecret_IssuesAFreshValue_AndRetiresThePreviousOne()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-rot2-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"rotsec-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId, secretHash: "parent-hash");
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var first = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);
        var second = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);

        first!.Secret.Should().NotBe(second!.Secret);

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        var storedValues = childClient!.ClientSecrets.Select(s => s.Value).ToList();

        storedValues.Should().Contain(ClientMirrorSecrets.Sha256(second.Secret!));
        storedValues.Should().NotContain(ClientMirrorSecrets.Sha256(first.Secret!),
            "rotation must retire the superseded credential, not accumulate credentials");
        childClient.ClientSecrets.Count(ClientMirrorSecrets.IsOwnSecret).Should().Be(1);
        storedValues.Should().Contain("parent-hash", "rotation must not touch the inherited secret");
    }

    /// <summary>
    ///     A public client — which is every mirrored client in the shipped seed — has no secret to
    ///     scope per tenant, so there is nothing to issue and the request is refused rather than
    ///     silently turning the mirror confidential.
    /// </summary>
    [Fact]
    public async Task RotateMirrorSecret_ForAPublicClient_ReportsNotApplicable()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-pub-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"pubcli-{Guid.NewGuid():N}".Substring(0, 24);
        await CreatePublicFlaggedClientAsync(systemContext, clientId);
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        childClient!.ClientSecrets.Should().BeEmpty("a public client is mirrored unchanged");

        var result = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);

        result.Should().NotBeNull();
        result!.NotApplicable.Should().BeTrue();
        result.Secret.Should().BeNull();
    }

    /// <summary>
    ///     The tracking row is the authority on "this client is mirrored there". Without that guard,
    ///     rotation would mint a secret onto any unrelated client that happens to share the id in
    ///     the named tenant.
    /// </summary>
    [Fact]
    public async Task RotateMirrorSecret_ForAnUntrackedPair_ReturnsNull()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-untr-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"untracked-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        // Deliberately never provisioned into that tenant.

        var result = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);

        result.Should().BeNull();
    }

    // ---------- helpers ----------

    // ---------- AB#5065: which secret matched? ----------

    /// <summary>
    ///     The link between AB#5061's writer and AB#5065's reader, proven end to end rather than
    ///     assumed: a mirror provisioned into a real database, read back and mapped by the
    ///     <b>production</b> <c>RtClient → Client</c> AutoMapper configuration, still carries the
    ///     marker the telemetry classifies on — and the real
    ///     <see cref="MirrorSecretUsageTelemetryValidator" /> then tells the parent's inherited
    ///     credential apart from the tenant's own one.
    /// </summary>
    /// <remarks>
    ///     🔴 This is the test that catches the dangerous failure. The unit tests hand the validator
    ///     a secret list built by hand; if the mapping ever dropped
    ///     <c>RtSecretRecord.Description</c>, the classification would silently never fire, the
    ///     inherited-use count would read zero for the wrong reason, and step 4 — dropping the
    ///     inherited secret — would be taken on a measurement that never measured anything.
    /// </remarks>
    [Fact]
    public async Task MirrorSecretUsage_DistinguishesInheritedFromOwn_ThroughTheRealMappingPath()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        const string parentPlaintext = "the-parents-shared-secret";
        var childTenantId = await CreateChildTenantAsync($"child-tel-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"telsec-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId,
            secretHash: ClientMirrorSecrets.Sha256(parentPlaintext));
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        // The only path that ever reveals a mirror's own secret in plaintext.
        var issued = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);
        issued!.Secret.Should().NotBeNullOrWhiteSpace();

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        var duendeClient = _fixture.GetService<IMapper>().Map<Client>(childClient);
        duendeClient.ClientSecrets.Should().HaveCount(2,
            "the mirror holds the inherited copy and its own until step 4 removes the former");

        var logger = new CapturingLogger<MirrorSecretUsageTelemetryValidator>();
        var httpContextAccessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext() };
        httpContextAccessor.HttpContext!.Items[InfrastructureCommon.TenantIdName] = childTenantId;
        var sut = new MirrorSecretUsageTelemetryValidator(
            new SecretValidator(TimeProvider.System,
                [new HashedSharedSecretValidator(NullLogger<HashedSharedSecretValidator>.Instance)],
                NullLogger<ISecretsListValidator>.Instance),
            httpContextAccessor, logger);

        var inherited = await sut.ValidateAsync(duendeClient.ClientSecrets,
            ParsedSharedSecret(clientId, parentPlaintext), TestContext.Current.CancellationToken);
        var own = await sut.ValidateAsync(duendeClient.ClientSecrets,
            ParsedSharedSecret(clientId, issued.Secret!), TestContext.Current.CancellationToken);

        inherited.Success.Should().BeTrue();
        own.Success.Should().BeTrue();

        logger.AllText.Should()
            .Contain($"secretKind={MirrorSecretUsageTelemetryValidator.InheritedSecretKind}")
            .And.Contain($"secretKind={MirrorSecretUsageTelemetryValidator.OwnSecretKind}")
            .And.Contain($"clientId={clientId}")
            .And.Contain($"tenantId={childTenantId}");

        // 🔴 Neither credential nor stored hash may reach a sink, asserted against the rendered text.
        logger.AllText.Should().NotContain(parentPlaintext);
        logger.AllText.Should().NotContain(issued.Secret!);
        logger.AllText.Should().NotContain(ClientMirrorSecrets.Sha256(parentPlaintext));
    }

    private static ParsedSecret ParsedSharedSecret(string clientId, string plaintext) => new()
    {
        Id = clientId,
        Credential = plaintext,
        Type = IdentityServerConstants.ParsedSecretTypes.SharedSecret
    };

    private IClientMirrorProvisioningService CreateService(ISystemContext systemContext)
        => new ClientMirrorProvisioningService(NullLogger<ClientMirrorProvisioningService>.Instance, systemContext);

    /// <summary>
    /// Brings the system tenant + the identity CK model online so we can persist
    /// <c>RtClient</c> / <c>RtClientMirror</c> entities. Idempotent across tests.
    /// </summary>
    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        var systemTenantId = _fixture.GetSystemContext().TenantId;
        await setup.SetupAsync(systemTenantId);
    }

    private async Task<string> CreateChildTenantAsync(string tenantId)
    {
        var systemContext = _fixture.GetSystemContext();
        using var session = await systemContext.GetAdminSessionAsync();
        session.StartTransaction();
        try
        {
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }

        // SetupAsync imports the identity CK model into the child + provisions baseline
        // resources, mirroring the production startup loop. Without this, inserting an
        // RtClient into the child later throws "RtCkTypeId not found in CkCache".
        // It also runs the mirror-provisioning hook from #4043 — idempotent.
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(tenantId);
        return tenantId;
    }

    private static async Task CreateFlaggedClientAsync(
        ISystemContext systemContext, string clientId, string secretHash = "test-hash")
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        session.StartTransaction();
        try
        {
            var client = new RtClient
            {
                RtId = OctoObjectId.GenerateNewId(),
                Enabled = true,
                ClientId = clientId,
                ProtocolType = "oidc",
                RequireClientSecret = true,
                AllowedGrantTypes = new AttributeStringValueList { "client_credentials" },
                AllowedScopes = new AttributeStringValueList { "octo_api" },
                ClientSecrets = new AttributeRecordValueList<RtSecretRecord>
                {
                    new() { Value = secretHash, Type = "SharedSecret" }
                },
                AutoProvisionInChildTenants = true
            };
            await parentRepo.InsertOneRtEntityAsync(session, client);
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    /// <summary>
    ///     A flagged client of the shape every mirrored client in the shipped
    ///     <c>System.Identity.Bootstrap</c> seed actually has: public, PKCE, no secret.
    /// </summary>
    private static async Task CreatePublicFlaggedClientAsync(
        ISystemContext systemContext, string clientId)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        session.StartTransaction();
        try
        {
            await parentRepo.InsertOneRtEntityAsync(session, new RtClient
            {
                RtId = OctoObjectId.GenerateNewId(),
                Enabled = true,
                ClientId = clientId,
                ProtocolType = "oidc",
                RequireClientSecret = false,
                RequirePkce = true,
                AllowedGrantTypes = new AttributeStringValueList { "authorization_code" },
                AllowedScopes = new AttributeStringValueList { "openid", "profile" },
                ClientSecrets = new AttributeRecordValueList<RtSecretRecord>(),
                AutoProvisionInChildTenants = true
            });
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    private static async Task<RtClient> UpdateParentClientSecretAsync(
        ISystemContext systemContext, string clientId, string newSecretHash)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        session.StartTransaction();
        try
        {
            var existing = (await parentRepo.GetRtEntitiesByTypeAsync<RtClient>(
                session,
                RtEntityQueryOptions.Create()
                    .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId))).Items
                .First();
            existing.ClientSecrets = new AttributeRecordValueList<RtSecretRecord>
            {
                new() { Value = newSecretHash, Type = "SharedSecret" }
            };
            await parentRepo.ReplaceOneRtEntityByIdAsync(session, existing.RtId, existing);
            await session.CommitTransactionAsync();
            return existing;
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    /// <summary>
    ///     A <c>client_credentials</c> request that carried no <c>acr_values</c>: the middleware
    ///     wrote nothing into <c>HttpContext.Items</c>, so the tenant is exactly what AB#5058 has to
    ///     decide about.
    /// </summary>
    private static CustomTokenRequestValidationContext CreateClientCredentialsContext(string clientId)
    {
        var request = new ValidatedTokenRequest { GrantType = "client_credentials" };
        request.SetClient(new Client { ClientId = clientId });
        return new CustomTokenRequestValidationContext { Result = new TokenRequestValidationResult(request) };
    }

    /// <summary>
    ///     Wires the real validator over the real mirror bookkeeping. Only the two collaborators
    ///     that need an HTTP request scope in production (client store, client role store) are
    ///     stubbed — the ambiguity decision itself runs against MongoDB.
    /// </summary>
    private ClientCredentialsRoleTokenValidator CreateTokenValidator(
        ISystemContext systemContext, string clientId, IClientMirrorProvisioningService mirrorService)
    {
        var parentClient = FindSystemClientAsync(systemContext, clientId).GetAwaiter().GetResult();
        return new ClientCredentialsRoleTokenValidator(
            new StubClientStore(systemContext.TenantId, parentClient),
            new StubClientRoleStore(),
            mirrorService,
            new StubEventService(),
            new HttpContextAccessor(),
            systemContext,
            NullLogger<ClientCredentialsRoleTokenValidator>.Instance);
    }

    private static async Task<RtClient?> FindSystemClientAsync(ISystemContext systemContext, string clientId)
    {
        var repo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        var result = await repo.GetRtEntitiesByTypeAsync<RtClient>(session,
            RtEntityQueryOptions.Create().FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.FirstOrDefault();
    }

    private static async Task CreateUnflaggedClientAsync(ISystemContext systemContext, string clientId)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        session.StartTransaction();
        try
        {
            await parentRepo.InsertOneRtEntityAsync(session, new RtClient
            {
                RtId = OctoObjectId.GenerateNewId(),
                Enabled = true,
                ClientId = clientId,
                ProtocolType = "oidc",
                RequireClientSecret = true,
                AllowedGrantTypes = new AttributeStringValueList { "client_credentials" },
                AllowedScopes = new AttributeStringValueList { "octo_api" },
                ClientSecrets = new AttributeRecordValueList<RtSecretRecord>
                {
                    new() { Value = "test-hash", Type = "SharedSecret" }
                },
                AutoProvisionInChildTenants = false
            });
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    private sealed class StubClientStore(string tenantId, RtClient? client) : IOctoClientStore
    {
        public string TenantId { get; } = tenantId;

        public Task<RtClient?> FindRtClientByIdAsync(string clientId) => Task.FromResult(client);

        public Task<Client?> FindClientByIdAsync(string clientId, CancellationToken ct = default)
            => Task.FromResult<Client?>(null);

        public IAsyncEnumerable<Client> GetAllClientsAsync(CancellationToken ct = default)
            => throw new NotSupportedException();

        public Task<IEnumerable<RtClient>> GetClients() => throw new NotSupportedException();

        public Task CreateAsync(RtClient c) => throw new NotSupportedException();

        public Task UpdateAsync(string clientId, RtClient c) => throw new NotSupportedException();

        public Task DeleteAsync(string clientId) => throw new NotSupportedException();
    }

    private sealed class StubClientRoleStore : IClientRoleStore
    {
        public Task<IReadOnlyList<string>> GetDirectRoleIdsAsync(OctoObjectId clientRtId)
            => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());

        public Task SetRoleIdsAsync(OctoObjectId clientRtId, IReadOnlyList<string> roleIds)
            => Task.CompletedTask;

        public Task AddRoleAsync(OctoObjectId clientRtId, string roleName) => Task.CompletedTask;

        public Task RemoveRoleAsync(OctoObjectId clientRtId, string roleName) => Task.CompletedTask;

        public Task<IReadOnlySet<string>> GetEffectiveRoleNamesAsync(OctoObjectId clientRtId)
            => Task.FromResult<IReadOnlySet<string>>(new HashSet<string>());
    }

    private sealed class StubEventService : IEventService
    {
        public Task RaiseAsync(Event evt, CancellationToken ct = default) => Task.CompletedTask;

        public bool CanRaiseEventType(EventTypes evtType) => true;
    }

    private static async Task<bool> ChildHasClientAsync(
        ISystemContext systemContext, string childTenantId, string clientId)
    {
        var childRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        if (childRepo == null) return false;
        using var session = await childRepo.GetSessionAsync();
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(
            session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.Any();
    }

    private static async Task<RtClient?> FindChildClientAsync(
        ISystemContext systemContext, string childTenantId, string clientId)
    {
        var childRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        if (childRepo == null) return null;
        using var session = await childRepo.GetSessionAsync();
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(
            session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.FirstOrDefault();
    }

    private static async Task<bool> ParentHasMirrorAsync(
        ISystemContext systemContext, string clientId, string childTenantId)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        var result = await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
            session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClientMirror.ParentClientId), FieldFilterOperator.Equals, clientId)
                .FieldFilter(nameof(RtClientMirror.ChildTenantId), FieldFilterOperator.Equals, childTenantId));
        return result.Items.Any();
    }

    private static async Task<int> GetMirrorSecretVersionAsync(
        ISystemContext systemContext, string clientId, string childTenantId)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        var result = await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
            session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClientMirror.ParentClientId), FieldFilterOperator.Equals, clientId)
                .FieldFilter(nameof(RtClientMirror.ChildTenantId), FieldFilterOperator.Equals, childTenantId));
        return result.Items.First().SecretHashVersion;
    }
}
