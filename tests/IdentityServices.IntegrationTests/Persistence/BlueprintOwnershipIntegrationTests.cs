using FluentAssertions;

using IdentityServices.IntegrationTests.Fixtures;

using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.Exchange;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;

using Persistence.IdentityCkModel.Generated.System.Identity.v2;

using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#6324 / AB#6329 (audit AB#6317 findings F2 and F5, incident class AB#6310): what a tenant
///     administrator decides in the product survives a blueprint update, against real MongoDB and the real
///     System.Identity model of this repository.
/// </summary>
/// <remarks>
///     <para>
///         A blueprint update imports its seed with <c>ImportStrategy.Upsert</c>, a full ReplaceOne in the
///         MongoDB layer. The engine keeps an attribute only when its ownership is not seed-owned
///         (<c>AttributeOwnership.IsPreservedOnUpsert</c>). Until System.Identity 2.23.0 the DataPolicy
///         enforcement mode, the client switches (Enabled, AllowedScopes, AllowedGrantTypes,
///         AutoProvisionInChildTenants, Secrets) and Enabled on the resources were seed-owned: an update
///         turned a tenant that had switched to Enforce back to AuditOnly, re-enabled disabled clients and
///         widened narrowed scopes.
///     </para>
///     <para>
///         Layer: the same command (<see cref="IImportRtModelCommand" />) that the blueprint apply and a plain
///         <c>ImportRt -r</c> use. The orchestration above it (Update/Merge selection, preview) belongs to the
///         engine and asset-repository stories of the same Feature (AB#6313, AB#6319). The values below are
///         made up; no real credential appears in the repository.
///     </para>
/// </remarks>
[Collection("Sequential")]
public class BlueprintOwnershipIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public BlueprintOwnershipIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    // ----------------------------------------------------------------------------------------------
    // Compiled model
    // ----------------------------------------------------------------------------------------------

    [Fact]
    public async Task CompiledModel_DeclaresTheTenantDecisionsAsPreservedOnUpsert()
    {
        var repo = await GetRepositoryAsync();

        var policy = await repo.GetCkTypeGraphAsync(RtEntityExtensions.GetRtCkTypeId<RtDataPolicy>());
        Ownership(policy, nameof(RtDataPolicy.EnforcementMode)).Should().Be(AttributeOwnershipDto.TenantOwned);
        Ownership(policy, nameof(RtDataPolicy.Scope)).Should().Be(AttributeOwnershipDto.TenantOwned);
        // Not a credential and part of the tenant's definition: carried in an ExportRt.
        Ownership(policy, nameof(RtDataPolicy.EnforcementMode)).IsExcludedFromExport().Should().BeFalse();

        var client = await repo.GetCkTypeGraphAsync(RtEntityExtensions.GetRtCkTypeId<RtClient>());
        Ownership(client, nameof(RtClient.Enabled)).Should().Be(AttributeOwnershipDto.TenantOwned);
        Ownership(client, nameof(RtClient.AllowedScopes)).Should().Be(AttributeOwnershipDto.TenantOwned);
        Ownership(client, nameof(RtClient.AllowedGrantTypes)).Should().Be(AttributeOwnershipDto.TenantOwned);
        Ownership(client, nameof(RtClient.AutoProvisionInChildTenants)).Should().Be(AttributeOwnershipDto.TenantOwned);
        // Credential: kept on a re-apply, left out of an ExportRt.
        Ownership(client, nameof(RtClient.ClientSecrets)).Should().Be(AttributeOwnershipDto.Secret);

        // AB#6443: the introspection secrets of an API resource are credentials too.
        var apiResource = await repo.GetCkTypeGraphAsync(RtEntityExtensions.GetRtCkTypeId<RtApiResource>());
        Ownership(apiResource, nameof(RtApiResource.ApiSecrets)).Should().Be(AttributeOwnershipDto.Secret);
        Ownership(apiResource, nameof(RtApiResource.ApiSecrets)).IsExcludedFromExport().Should().BeTrue();

        foreach (var resourceType in new[]
                 {
                     RtEntityExtensions.GetRtCkTypeId<RtApiResource>(),
                     RtEntityExtensions.GetRtCkTypeId<RtApiScope>(),
                     RtEntityExtensions.GetRtCkTypeId<RtIdentityResource>()
                 })
        {
            var graph = await repo.GetCkTypeGraphAsync(resourceType);
            Ownership(graph, "Enabled").Should().Be(AttributeOwnershipDto.TenantOwned, resourceType.ToString());
        }
    }

    // ----------------------------------------------------------------------------------------------
    // F2: DataPolicy
    // ----------------------------------------------------------------------------------------------

    /// <summary>
    ///     The shipped seed (<c>seed-data/data-permissions.yaml</c>, the same file the blueprint applies):
    ///     a fresh tenant gets AuditOnly, an administrator flips to Enforce, a blueprint update must not
    ///     turn it back.
    /// </summary>
    [Fact]
    public async Task ShippedPolicySeed_FreshTenantIsAuditOnly_AndAnUpdateKeepsEnforce()
    {
        var repo = await GetRepositoryAsync();
        var seed = await File.ReadAllTextAsync(FindRepoFile(
            "src/Persistence.IdentityCkModel/Blueprints/System.Identity.Bootstrap/seed-data/data-permissions.yaml"),
            TestContext.Current.CancellationToken);
        var policyRtId = new OctoObjectId("660000000000000000000051");

        // Blueprint install: the seed applies.
        await ImportAsync(repo, seed, ImportStrategy.Upsert);
        var installed = await LoadAsync<RtDataPolicy>(repo, policyRtId);
        installed.EnforcementMode.Should().Be(RtDataPolicyEnforcementModeEnum.AuditOnly,
            "a fresh tenant still gets the seed value");

        // The tenant administrator flips the policy (the operator action of AB#4974) and narrows the scope.
        installed.EnforcementMode = RtDataPolicyEnforcementModeEnum.Enforce;
        installed.Scope = RtDataPolicyScopeEnum.OwnedOnly;
        await ReplaceAsync(repo, installed);

        // Blueprint update / re-apply of the unchanged seed.
        await ImportAsync(repo, seed, ImportStrategy.Upsert);

        var afterUpdate = await LoadAsync<RtDataPolicy>(repo, policyRtId);
        afterUpdate.EnforcementMode.Should().Be(RtDataPolicyEnforcementModeEnum.Enforce);
        afterUpdate.Scope.Should().Be(RtDataPolicyScopeEnum.OwnedOnly);
        afterUpdate.TargetCkTypeIds.Should().Contain("System.Identity/Client", "the rest of the seed is intact");
    }

    [Fact]
    public async Task PolicyUpsert_KeepsTenantDecisions_ButStillMovesBlueprintOwnedValues()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();

        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/User", enforcementMode: 1, scope: 0),
            ImportStrategy.Upsert);
        var fresh = await LoadAsync<RtDataPolicy>(repo, rtId);
        fresh.EnforcementMode.Should().Be(RtDataPolicyEnforcementModeEnum.AuditOnly);
        fresh.Scope.Should().Be(RtDataPolicyScopeEnum.All);

        fresh.EnforcementMode = RtDataPolicyEnforcementModeEnum.Enforce;
        fresh.Scope = RtDataPolicyScopeEnum.OwnedOnly;
        await ReplaceAsync(repo, fresh);

        // The seed moved on: another target and (as before) AuditOnly / All.
        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/Role", enforcementMode: 1, scope: 0),
            ImportStrategy.Upsert);

        var updated = await LoadAsync<RtDataPolicy>(repo, rtId);
        updated.EnforcementMode.Should().Be(RtDataPolicyEnforcementModeEnum.Enforce);
        updated.Scope.Should().Be(RtDataPolicyScopeEnum.OwnedOnly);
        // Control: the import really replaced the entity - a blueprint-owned value moved with the seed.
        updated.TargetCkTypeIds.Should().ContainSingle().Which.Should().Be("System.Identity/Role");
    }

    [Fact]
    public async Task PolicyUpsert_SeedOmittingTheModeAndScope_KeepsTheTenantDecisions()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/User", enforcementMode: 1, scope: 0),
            ImportStrategy.Upsert);
        var policy = await LoadAsync<RtDataPolicy>(repo, rtId);
        policy.EnforcementMode = RtDataPolicyEnforcementModeEnum.Enforce;
        policy.Scope = RtDataPolicyScopeEnum.OwnedOnly;
        await ReplaceAsync(repo, policy);

        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/User", enforcementMode: null, scope: null),
            ImportStrategy.Upsert);

        var updated = await LoadAsync<RtDataPolicy>(repo, rtId);
        updated.EnforcementMode.Should().Be(RtDataPolicyEnforcementModeEnum.Enforce);
        updated.Scope.Should().Be(RtDataPolicyScopeEnum.OwnedOnly);
    }

    // ----------------------------------------------------------------------------------------------
    // F5: Client and resources
    // ----------------------------------------------------------------------------------------------

    [Fact]
    public async Task ClientUpsert_KeepsWhatTheAdministratorChanged_ButStillMovesBlueprintOwnedValues()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        var clientId = $"test-{Guid.NewGuid():N}";

        // Fresh tenant: the seed values apply.
        await ImportAsync(repo, ClientSeed(rtId, clientId, "Seeded name"), ImportStrategy.Upsert);
        var fresh = await LoadAsync<RtClient>(repo, rtId);
        fresh.Enabled.Should().BeTrue();
        fresh.AllowedScopes.Should().BeEquivalentTo("openid", "profile", "octo_api");
        fresh.AllowedGrantTypes.Should().BeEquivalentTo("authorization_code", "client_credentials");
        fresh.AutoProvisionInChildTenants.Should().BeTrue();

        // The administrator disables the client, narrows scopes and grants, opts out of provisioning.
        fresh.Enabled = false;
        fresh.AllowedScopes = new AttributeStringValueList(new List<string> { "openid" });
        fresh.AllowedGrantTypes = new AttributeStringValueList(new List<string> { "authorization_code" });
        fresh.AutoProvisionInChildTenants = false;
        await ReplaceAsync(repo, fresh);

        // Blueprint update with the unchanged client plus a changed blueprint-owned value.
        await ImportAsync(repo, ClientSeed(rtId, clientId, "Seeded name v2"), ImportStrategy.Upsert);

        var updated = await LoadAsync<RtClient>(repo, rtId);
        updated.Enabled.Should().BeFalse("an update never re-enables a client");
        updated.AllowedScopes.Should().BeEquivalentTo(new[] { "openid" }, "an update never widens the scopes");
        updated.AllowedGrantTypes.Should().BeEquivalentTo(new[] { "authorization_code" });
        updated.AutoProvisionInChildTenants.Should().BeFalse();
        // Control: the import really replaced the entity.
        updated.ClientName.Should().Be("Seeded name v2");
    }

    [Fact]
    public async Task ClientUpsert_KeepsTheSecretsOfTheClient_WhenTheSeedShipsNone()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        var clientId = $"test-{Guid.NewGuid():N}";
        await ImportAsync(repo, ClientSeed(rtId, clientId, "Seeded name"), ImportStrategy.Upsert);

        var client = await LoadAsync<RtClient>(repo, rtId);
        client.ClientSecrets.Add(new RtSecretRecord
        {
            Value = "test-not-a-real-secret-hash",
            Type = "SharedSecret",
            Description = "added by the administrator"
        });
        await ReplaceAsync(repo, client);

        await ImportAsync(repo, ClientSeed(rtId, clientId, "Seeded name v2"), ImportStrategy.Upsert);

        var updated = await LoadAsync<RtClient>(repo, rtId);
        updated.ClientSecrets.Should().ContainSingle().Which.Value.Should().Be("test-not-a-real-secret-hash");
        updated.ClientName.Should().Be("Seeded name v2");
    }

    [Theory]
    [InlineData("ApiScope")]
    [InlineData("IdentityResource")]
    [InlineData("ApiResource")]
    public async Task ResourceUpsert_KeepsAResourceTheAdministratorDisabled(string typeName)
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        var name = $"res-{Guid.NewGuid():N}";

        await ImportAsync(repo, ResourceSeed(typeName, rtId, name, "Seeded display name"), ImportStrategy.Upsert);
        var fresh = await LoadResourceAsync(repo, typeName, rtId);
        fresh.Enabled.Should().BeTrue("a fresh tenant gets the seed value");

        fresh.Enabled = false;
        await ReplaceAsync(repo, fresh);

        await ImportAsync(repo, ResourceSeed(typeName, rtId, name, "Seeded display name v2"),
            ImportStrategy.Upsert);

        var updated = await LoadResourceAsync(repo, typeName, rtId);
        updated.Enabled.Should().BeFalse("an update never enables a resource the administrator disabled");
        updated.DisplayName.Should().Be("Seeded display name v2");
    }

    /// <summary>
    ///     AB#6443: the Identity.Bootstrap seed writes <c>Secrets</c> on the API resources (empty). The
    ///     secret a tenant administrator set must survive an update, also one whose seed ships a non-empty
    ///     placeholder; a fresh tenant still gets the seed value.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ApiResourceUpsert_KeepsTheSecretTheAdministratorSet(bool seedShipsPlaceholder)
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        var name = $"res-{Guid.NewGuid():N}";

        await ImportAsync(repo, ResourceSeed("ApiResource", rtId, name, "Seeded display name"),
            ImportStrategy.Upsert);
        var fresh = await LoadAsync<RtApiResource>(repo, rtId);
        fresh.ApiSecrets.Should().BeEmpty("a fresh tenant gets the seed value");

        fresh.ApiSecrets.Add(new RtSecretRecord
        {
            Value = "test-not-a-real-secret-hash",
            Type = "SharedSecret",
            Description = "set by the administrator"
        });
        await ReplaceAsync(repo, fresh);

        var seed = seedShipsPlaceholder
            ? ResourceSeed("ApiResource", rtId, name, "Seeded display name v2", placeholderApiSecret: true)
            : ResourceSeed("ApiResource", rtId, name, "Seeded display name v2");
        await ImportAsync(repo, seed, ImportStrategy.Upsert);

        var updated = await LoadAsync<RtApiResource>(repo, rtId);
        updated.ApiSecrets.Should().ContainSingle().Which.Value.Should().Be("test-not-a-real-secret-hash");
        // Control: the import really replaced the entity.
        updated.DisplayName.Should().Be("Seeded display name v2");
    }

    // ----------------------------------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------------------------------

    private static AttributeOwnershipDto Ownership(
        Meshmakers.Octo.ConstructionKit.Contracts.DependencyGraph.CkTypeWithAttributesGraph graph, string attributeName) =>
        graph.AllAttributes.Values
            .Single(a => a.AttributeName.Equals(attributeName, StringComparison.OrdinalIgnoreCase))
            .Ownership;

    private async Task<ITenantRepository> GetRepositoryAsync()
    {
        await _fixture.InitializeAsync();
        await _fixture.GetService<IDefaultConfigurationCreatorService>()
            .SetupAsync(_fixture.GetSystemContext().TenantId);
        return _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
    }

    private async Task ImportAsync(ITenantRepository repo, string yaml, ImportStrategy strategy) =>
        await _fixture.GetService<IImportRtModelCommand>().ImportTextAsync(repo, yaml, strategy);

    private static async Task<T> LoadAsync<T>(ITenantRepository repo, OctoObjectId rtId) where T : RtEntity, new()
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var entity = await repo.GetRtEntityByRtIdAsync<T>(session, rtId);
        await session.CommitTransactionAsync();
        return entity ?? throw new InvalidOperationException($"{typeof(T).Name} {rtId} was not imported.");
    }

    private static async Task<RtResource> LoadResourceAsync(ITenantRepository repo, string typeName, OctoObjectId rtId) =>
        typeName switch
        {
            "ApiScope" => await LoadAsync<RtApiScope>(repo, rtId),
            "IdentityResource" => await LoadAsync<RtIdentityResource>(repo, rtId),
            _ => await LoadAsync<RtApiResource>(repo, rtId)
        };

    /// <summary>The administrator's change: a plain ReplaceOne through the repository, as the product does.</summary>
    private static async Task ReplaceAsync<T>(ITenantRepository repo, T entity) where T : RtEntity, new()
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.ReplaceOneRtEntityByIdAsync(session, entity.RtId, entity);
        await session.CommitTransactionAsync();
    }

    private static string FindRepoFile(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Octo.Identity.sln")))
        {
            dir = dir.Parent;
        }

        return dir == null
            ? throw new FileNotFoundException("Octo.Identity.sln not found above the test binaries.")
            : Path.Combine(dir.FullName, relativePath);
    }

    private static string PolicySeed(OctoObjectId rtId, string targetCkTypeId, int? enforcementMode, int? scope)
    {
        var mode = enforcementMode == null
            ? string.Empty
            : $"\n      - id: System.Identity/PolicyEnforcementMode\n        value: {enforcementMode}";
        var scopeYaml = scope == null
            ? string.Empty
            : $"\n      - id: System.Identity/PolicyScope\n        value: {scope}";
        return $"""
            $schema: https://schemas.meshmakers.cloud/runtime-model.schema.json
            dependencies:
              - System.Identity-2.23.0
            entities:
              - rtId: '{rtId}'
                ckTypeId: System.Identity/DataPolicy
                attributes:
                  - id: System.Identity/TargetCkTypeIds
                    value:
                      - {targetCkTypeId}
                  - id: System.Identity/PolicyActions
                    value:
                      - Read{scopeYaml}{mode}
            """;
    }

    private static string ClientSeed(OctoObjectId rtId, string clientId, string clientName) =>
        $"""
         $schema: https://schemas.meshmakers.cloud/runtime-model.schema.json
         dependencies:
           - System.Identity-2.23.0
         entities:
           - rtId: '{rtId}'
             ckTypeId: System.Identity/Client
             attributes:
               - id: System/Enabled
                 value: true
               - id: System.Identity/ClientId
                 value: {clientId}
               - id: System/Name
                 value: {clientName}
               - id: System.Identity/ProtocolType
                 value: oidc
               - id: System.Identity/RequireClientSecret
                 value: false
               - id: System.Identity/Secrets
                 value: []
               - id: System.Identity/AllowedGrantTypes
                 value:
                   - authorization_code
                   - client_credentials
               - id: System.Identity/AllowedScopes
                 value:
                   - openid
                   - profile
                   - octo_api
               - id: System.Identity/RedirectUris
                 value: []
               - id: System.Identity/PostLogoutRedirectUris
                 value: []
               - id: System.Identity/AllowedCorsOrigins
                 value: []
               - id: System.Identity/AutoProvisionInChildTenants
                 value: true
         """;

    private static string ResourceSeed(string typeName, OctoObjectId rtId, string name, string displayName,
        bool placeholderApiSecret = false)
    {
        var secrets = placeholderApiSecret
            ? """

                          - ckRecordId: System.Identity/Secret
                            attributes:
                              - id: System.Identity/Value
                                value: test-placeholder-from-seed
                              - id: System.Identity/SecretType
                                value: SharedSecret
              """
            : " []";
        var extra = typeName switch
        {
            "ApiResource" => $"""

                      - id: System.Identity/Secrets
                        value:{secrets}
                      - id: System.Identity/Scopes
                        value:
                          - octo_api
                """,
            _ => string.Empty
        };

        return $"""
            $schema: https://schemas.meshmakers.cloud/runtime-model.schema.json
            dependencies:
              - System.Identity-2.23.0
            entities:
              - rtId: '{rtId}'
                ckTypeId: System.Identity/{typeName}
                attributes:
                  - id: System/Enabled
                    value: true
                  - id: System/Name
                    value: {name}
                  - id: System/DisplayName
                    value: {displayName}
                  - id: System.Identity/ResourceClaims
                    value: []
                  - id: System.Identity/ShowInDiscoveryDocument
                    value: true{extra}
            """;
    }
}
