using FluentAssertions;

using IdentityServerPersistence.SystemStores;

using IdentityServices.IntegrationTests.Fixtures;

using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;

using Persistence.IdentityCkModel.Generated.System.Identity.v2;

using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// End-to-end checks of the data-permission store (AB#4972) against a real MongoDB: permission
/// CRUD, policy binding via PolicyPermission, role grants via GrantsPermission, the
/// enforcement-mode flip (the AB#4974 operator action) and cascading permission removal.
/// </summary>
[Collection("Sequential")]
public class DataPermissionStoreIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public DataPermissionStoreIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task PermissionLifecycle_CreatePolicyGrantFlipRemove()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (store, repo) = CreateStore();

        var permissionId = NewId("perm");
        var roleName = NewId("role");
        await CreateRoleAsync(repo, roleName);

        // Create permission + policy + grant.
        var permissionRtId = await store.CreateAsync(permissionId, "test permission");
        var policyRtId = await store.CreatePolicyAsync(permissionId,
            ["Test/Continent"], ["Read", "Write"],
            RtDataPolicyScopeEnum.OwnedOnly, RtDataPolicyEnforcementModeEnum.AuditOnly);
        await store.GrantToRoleAsync(permissionId, roleName);

        var found = await store.FindByPermissionIdAsync(permissionId);
        found.Should().NotBeNull();
        found!.RtId.Should().Be(permissionRtId);

        var policies = await store.GetPoliciesAsync(permissionRtId);
        policies.Should().ContainSingle();
        policies[0].RtId.Should().Be(policyRtId);
        policies[0].TargetCkTypeIds.Should().Contain("Test/Continent");
        policies[0].Scope.Should().Be(RtDataPolicyScopeEnum.OwnedOnly);
        policies[0].EnforcementMode.Should().Be(RtDataPolicyEnforcementModeEnum.AuditOnly);

        var roleNames = await store.GetGrantedRoleNamesAsync(permissionRtId);
        roleNames.Should().Contain(roleName);

        // The operator flip (AuditOnly -> Enforce).
        await store.SetPolicyEnforcementModeAsync(policyRtId, RtDataPolicyEnforcementModeEnum.Enforce);
        var flipped = await store.GetPoliciesAsync(permissionRtId);
        flipped[0].EnforcementMode.Should().Be(RtDataPolicyEnforcementModeEnum.Enforce);
        flipped[0].TargetCkTypeIds.Should().Contain("Test/Continent"); // partial update kept the rest

        // Revoke + remove (policies go with the permission).
        await store.RevokeFromRoleAsync(permissionId, roleName);
        (await store.GetGrantedRoleNamesAsync(permissionRtId)).Should().NotContain(roleName);

        await store.RemoveAsync(permissionId);
        (await store.FindByPermissionIdAsync(permissionId)).Should().BeNull();
    }

    [Fact]
    public async Task CreateDuplicatePermission_Throws()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (store, _) = CreateStore();

        var permissionId = NewId("dup");
        await store.CreateAsync(permissionId, null);
        var act = () => store.CreateAsync(permissionId, null);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24];

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);
    }

    private (DataPermissionStore store, ITenantRepository repo) CreateStore()
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        var resolver = new FixedTenantResolver(repo);
        return (new DataPermissionStore(resolver), repo);
    }

    private static async Task CreateRoleAsync(ITenantRepository repo, string name)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = name,
            NormalizedName = name.ToUpperInvariant()
        });
        await session.CommitTransactionAsync();
    }
}
