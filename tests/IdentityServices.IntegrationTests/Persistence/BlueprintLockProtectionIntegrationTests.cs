using FluentAssertions;

using IdentityServices.IntegrationTests.Fixtures;

using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.Exchange;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;

using Persistence.IdentityCkModel.Generated.System.Identity.v2;

using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#6384: the System.Identity 2.24.0 DataPolicy attribute <c>ProtectBlueprintLocked</c> (the opt-in of the
///     engine's blueprint-lock write guard), against real MongoDB and the real System.Identity model of this
///     repository.
/// </summary>
/// <remarks>
///     <para>
///         The attribute is <b>seed-owned</b> (blueprint-owned): the blueprint author decides which CK types are
///         protected and every blueprint update re-applies the value — the opposite of
///         <c>PolicyEnforcementMode</c> (tenant-owned, AB#6324). The default is <c>false</c>, so existing
///         policies and tenants are unaffected.
///     </para>
///     <para>
///         Layer: the same command (<see cref="IImportRtModelCommand" />) that the blueprint apply uses. The last
///         test drives the real engine write guard through a non-system session to show the attribute really
///         opts a type in (the engine side is AB#6384 in octo-construction-kit-engine, message number 6384).
///     </para>
/// </remarks>
[Collection("Sequential")]
public class BlueprintLockProtectionIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public BlueprintLockProtectionIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    // ----------------------------------------------------------------------------------------------
    // Compiled model
    // ----------------------------------------------------------------------------------------------

    [Fact]
    public async Task CompiledModel_DeclaresProtectBlueprintLockedAsSeedOwnedBooleanDefaultingToFalse()
    {
        var repo = await GetRepositoryAsync();

        var policy = await repo.GetCkTypeGraphAsync(RtEntityExtensions.GetRtCkTypeId<RtDataPolicy>());
        var attribute = policy.AllAttributes.Values.Single(a =>
            a.AttributeName.Equals(RtBlueprintLockProtectionNames.DataPolicyAttributeName,
                StringComparison.OrdinalIgnoreCase));

        attribute.Ownership.Should().Be(AttributeOwnershipDto.SeedOwned,
            "the blueprint author decides which types are protected; an update re-applies the product's value");
        attribute.Ownership.IsPreservedOnUpsert().Should().BeFalse();
        attribute.Ownership.IsExcludedFromExport().Should().BeFalse();

        // The tenant-owned decisions of AB#6324 are untouched by the opposite choice made here.
        policy.AllAttributes.Values.Single(a => a.AttributeName.Equals(nameof(RtDataPolicy.EnforcementMode),
                StringComparison.OrdinalIgnoreCase)).Ownership
            .Should().Be(AttributeOwnershipDto.TenantOwned);

        new RtDataPolicy().ProtectBlueprintLocked.Should().BeFalse("the default is off");
    }

    // ----------------------------------------------------------------------------------------------
    // Seed ownership against real MongoDB
    // ----------------------------------------------------------------------------------------------

    [Fact]
    public async Task FreshInstall_SetsTheSeedValue()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();

        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/Role", protectBlueprintLocked: true));

        var policy = await LoadAsync<RtDataPolicy>(repo, rtId);
        policy.ProtectBlueprintLocked.Should().BeTrue("a fresh tenant gets the value the blueprint ships");
    }

    [Fact]
    public async Task Update_ReappliesTheProductsValue_EvenWhenSomeoneSwitchedItOff()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/Role", protectBlueprintLocked: true));

        // A tenant user with write access to DataPolicy switches the protection off, and also takes the
        // tenant-owned decision to Enforce.
        var policy = await LoadAsync<RtDataPolicy>(repo, rtId);
        policy.ProtectBlueprintLocked = false;
        policy.EnforcementMode = RtDataPolicyEnforcementModeEnum.Enforce;
        await ReplaceAsync(repo, policy);

        // Blueprint update / forced re-apply of the unchanged seed.
        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/Role", protectBlueprintLocked: true));

        var updated = await LoadAsync<RtDataPolicy>(repo, rtId);
        updated.ProtectBlueprintLocked.Should().BeTrue("a blueprint update always enforces the product's value");
        // Control: the tenant-owned decision survives the very same update (AB#6324).
        updated.EnforcementMode.Should().Be(RtDataPolicyEnforcementModeEnum.Enforce);
    }

    [Fact]
    public async Task Update_FollowsTheBlueprintAuthor_WhenTheSeedChangesTheValue()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/Role", protectBlueprintLocked: false));
        (await LoadAsync<RtDataPolicy>(repo, rtId)).ProtectBlueprintLocked.Should().BeFalse();

        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/Role", protectBlueprintLocked: true));
        (await LoadAsync<RtDataPolicy>(repo, rtId)).ProtectBlueprintLocked.Should().BeTrue("the author opts a type in");

        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/Role", protectBlueprintLocked: false));
        (await LoadAsync<RtDataPolicy>(repo, rtId)).ProtectBlueprintLocked.Should().BeFalse("and can take it back");
    }

    [Fact]
    public async Task SeedOmittingTheAttribute_ReadsAsFalse_AndKeepsAStoredValueOnUpdate()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();

        // Existing policies (shipped before 2.24.0, or written by a user) never mention the attribute.
        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/Role", protectBlueprintLocked: null));
        (await LoadAsync<RtDataPolicy>(repo, rtId)).ProtectBlueprintLocked.Should().BeFalse("missing = false");

        // A seed that merely omits the attribute does not switch a stored protection off: the generic
        // blanking guard of the import (AB#6313, "ResetToDefault ... existing value kept") applies. The
        // blueprint author turns the protection off by shipping an explicit false (previous test).
        var policy = await LoadAsync<RtDataPolicy>(repo, rtId);
        policy.ProtectBlueprintLocked = true;
        await ReplaceAsync(repo, policy);
        await ImportAsync(repo, PolicySeed(rtId, "System.Identity/Role", protectBlueprintLocked: null));

        (await LoadAsync<RtDataPolicy>(repo, rtId)).ProtectBlueprintLocked.Should().BeTrue();
    }

    [Fact]
    public async Task TheShippedBootstrapPolicies_DoNotOptIn()
    {
        var repo = await GetRepositoryAsync();
        var seed = await File.ReadAllTextAsync(FindRepoFile(
                "src/Persistence.IdentityCkModel/Blueprints/System.Identity.Bootstrap/seed-data/data-permissions.yaml"),
            TestContext.Current.CancellationToken);

        await ImportAsync(repo, seed);

        var policy = await LoadAsync<RtDataPolicy>(repo, new OctoObjectId("660000000000000000000051"));
        policy.ProtectBlueprintLocked.Should().BeFalse("existing tenants are unaffected by System.Identity 2.24.0");
    }

    // ----------------------------------------------------------------------------------------------
    // End to end: the flag opts a type in at the engine write guard
    // ----------------------------------------------------------------------------------------------

    /// <summary>
    ///     A policy with <c>ProtectBlueprintLocked</c> on <c>System.Identity/Role</c>, a role granting the
    ///     caller write access, a blueprint-locked role and a tenant-owned one. The caller holds a Write
    ///     grant, so the refusal comes from the lock restriction (6384), not from a missing grant (4973).
    /// </summary>
    [Fact]
    public async Task PolicyWithTheFlag_MakesTheEngineGuardRefuseAUserWrite_OnALockedEntityOnly()
    {
        var repo = await GetRepositoryAsync();
        var roleName = $"locktest-{Guid.NewGuid():N}";
        var lockedRoleRtId = OctoObjectId.GenerateNewId();
        var openRoleRtId = OctoObjectId.GenerateNewId();
        var grantingRoleRtId = OctoObjectId.GenerateNewId();
        var permissionRtId = OctoObjectId.GenerateNewId();
        var policyRtId = OctoObjectId.GenerateNewId();

        await ImportAsync(repo, $"""
            $schema: https://schemas.meshmakers.cloud/runtime-model.schema.json
            dependencies:
              - System.Identity-2.24.0
            entities:
              - rtId: '{permissionRtId}'
                ckTypeId: System.Identity/DataPermission
                attributes:
                  - id: System.Identity/PermissionId
                    value: {roleName}.permission
              - rtId: '{grantingRoleRtId}'
                ckTypeId: System.Identity/Role
                attributes:
                  - id: System/Name
                    value: {roleName}
                  - id: System.Identity/NormalizedName
                    value: {roleName.ToUpperInvariant()}
                associations:
                  - roleId: System.Identity/GrantsPermission
                    targetRtId: '{permissionRtId}'
                    targetCkTypeId: System.Identity/DataPermission
              - rtId: '{policyRtId}'
                ckTypeId: System.Identity/DataPolicy
                attributes:
                  - id: System.Identity/TargetCkTypeIds
                    value:
                      - System.Identity/Role
                  - id: System.Identity/PolicyActions
                    value:
                      - Read
                      - Write
                      - Delete
                  - id: System.Identity/PolicyScope
                    value: 0
                  - id: System.Identity/PolicyEnforcementMode
                    value: 0
                  - id: System.Identity/ProtectBlueprintLocked
                    value: true
                associations:
                  - roleId: System.Identity/PolicyPermission
                    targetRtId: '{permissionRtId}'
                    targetCkTypeId: System.Identity/DataPermission
              - rtId: '{lockedRoleRtId}'
                ckTypeId: System.Identity/Role
                attributes:
                  - id: System/Name
                    value: {roleName}-locked
                  - id: System.Identity/NormalizedName
                    value: {roleName.ToUpperInvariant()}-LOCKED
                  - id: System/RtBlueprintLocked
                    value: true
              - rtId: '{openRoleRtId}'
                ckTypeId: System.Identity/Role
                attributes:
                  - id: System/Name
                    value: {roleName}-open
                  - id: System.Identity/NormalizedName
                    value: {roleName.ToUpperInvariant()}-OPEN
            """);
        // The policy table is cached per tenant (60 s); this test needs the policy now.
        _fixture.GetService<IDataPermissionResolver>().Invalidate(_fixture.GetSystemContext().TenantId);

        var userContext = RtSecurityContext.ForUser("locktest-user", [roleName]);

        // 1. Locked entity: refused with the stable lock error, entity unchanged.
        var refused = await TryRenameAsync(repo, userContext, lockedRoleRtId, "renamed-by-user");
        refused.Should().NotBeNull("a user may not change a blueprint-locked entity of an opted-in type");
        refused!.Message.Should().Contain("6384").And.Contain("locked by blueprint");
        (await LoadAsync<RtRole>(repo, lockedRoleRtId)).Name.Should().Be($"{roleName}-locked");

        // 2. The tenant-owned entity of the same type stays editable (grants unite, the restriction only
        //    bites on RtBlueprintLocked = true).
        (await TryRenameAsync(repo, userContext, openRoleRtId, "renamed-by-user")).Should().BeNull();
        (await LoadAsync<RtRole>(repo, openRoleRtId)).Name.Should().Be("renamed-by-user");

        // 3. The system (blueprint apply, migrations) is exempt.
        (await TryRenameAsync(repo, RtSecurityContext.System, lockedRoleRtId, "renamed-by-system")).Should().BeNull();
        (await LoadAsync<RtRole>(repo, lockedRoleRtId)).Name.Should().Be("renamed-by-system");
    }

    // ----------------------------------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------------------------------

    /// <summary>Updates the role name through the guarded write funnel; returns the exception, if any.</summary>
    private static async Task<RuntimeRepositoryException?> TryRenameAsync(ITenantRepository repo,
        RtSecurityContext securityContext, OctoObjectId roleRtId, string newName)
    {
        using var session = await repo.GetSessionAsync(securityContext);
        session.StartTransaction();
        try
        {
            var update = new RtRole { Name = newName, NormalizedName = newName.ToUpperInvariant() };
            await repo.ApplyChangesAsync(session,
                new List<IEntityUpdateInfo<RtEntity>>
                {
                    EntityUpdateInfo<RtEntity>.CreateUpdate(
                        new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), roleRtId), update)
                }, new OperationResult());
            await session.CommitTransactionAsync();
            return null;
        }
        catch (RuntimeRepositoryException ex)
        {
            await session.AbortTransactionAsync();
            return ex;
        }
    }

    private async Task<ITenantRepository> GetRepositoryAsync()
    {
        await _fixture.InitializeAsync();
        await _fixture.GetService<IDefaultConfigurationCreatorService>()
            .SetupAsync(_fixture.GetSystemContext().TenantId);
        return _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
    }

    private async Task ImportAsync(ITenantRepository repo, string yaml) =>
        await _fixture.GetService<IImportRtModelCommand>().ImportTextAsync(repo, yaml, ImportStrategy.Upsert);

    private static async Task<T> LoadAsync<T>(ITenantRepository repo, OctoObjectId rtId) where T : RtEntity, new()
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var entity = await repo.GetRtEntityByRtIdAsync<T>(session, rtId);
        await session.CommitTransactionAsync();
        return entity ?? throw new InvalidOperationException($"{typeof(T).Name} {rtId} was not imported.");
    }

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

    private static string PolicySeed(OctoObjectId rtId, string targetCkTypeId, bool? protectBlueprintLocked)
    {
        var flag = protectBlueprintLocked == null
            ? string.Empty
            : $"\n      - id: System.Identity/ProtectBlueprintLocked\n        value: {protectBlueprintLocked.Value.ToString().ToLowerInvariant()}";
        return $"""
            $schema: https://schemas.meshmakers.cloud/runtime-model.schema.json
            dependencies:
              - System.Identity-2.24.0
            entities:
              - rtId: '{rtId}'
                ckTypeId: System.Identity/DataPolicy
                attributes:
                  - id: System.Identity/TargetCkTypeIds
                    value:
                      - {targetCkTypeId}
                  - id: System.Identity/PolicyActions
                    value:
                      - Read
                      - Write
                      - Delete
                  - id: System.Identity/PolicyEnforcementMode
                    value: 1{flag}
            """;
    }
}
