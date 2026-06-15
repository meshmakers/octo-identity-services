using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.Migrations;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     End-to-end coverage for the defensive role-name index added to
///     <c>DefaultConfigurationCreatorService.RestorePendingRoleAssignmentsAsync</c> after the
///     test-2 2026-06-15 incident. Reproduces the exact DB shape that crashed Identity startup
///     (a duplicate <c>AdminPanelManagement</c> role — one pre-blueprint random rtId, one
///     blueprint-range 660…05) and asserts:
///     <list type="bullet">
///         <item><see cref="IDefaultConfigurationCreatorService.SetupAsync"/> completes without
///             the historical <c>ArgumentException: An item with the same key has already been
///             added. Key: AdminPanelManagement</c> crash;</item>
///         <item>the post-blueprint restore picks the <strong>blueprint-range</strong> rtId
///             (660…05) as the target of the rebuilt <c>AssignedRole</c> edge, not the
///             pre-blueprint duplicate.</item>
///     </list>
///     <para>
///         Whole pipeline path: imperative-seed role injection → pending-assignment config row
///         → <c>SetupAsync</c> → <c>RestorePendingRoleAssignmentsAsync</c> → emitted
///         <c>AssignedRole</c> edge → MongoDB assertion. Backed by Testcontainers because the
///         crash hid inside the LINQ-to-Mongo materialisation of <c>roles.Items</c>; a unit-test
///         mock cannot exercise the same path.
///     </para>
/// </summary>
[Collection("Sequential")]
public class PreBlueprintRestoreDefensiveIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public PreBlueprintRestoreDefensiveIntegrationTests(
        IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task SetupAsync_DuplicateRoleAndPendingAssignment_CompletesAndRestoresOntoBlueprintRtId()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        // 1. Fresh child tenant. CreateChildTenantAsync already runs SetupAsync once so the CK
        // model + 14 blueprint roles (660…01..0E) are present and migrations are at HEAD.
        var childTenantId = await CreateChildTenantAsync($"defensive-{Guid.NewGuid():N}".Substring(0, 24));

        var childRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        childRepo.Should().NotBeNull("the child tenant repo must be reachable for the test setup");

        // 2. Inject the exact test-2 incident shape: a second role with attributes.name =
        // "AdminPanelManagement" and a random rtId OUTSIDE the 660…00..67…00 range. This is
        // what the broken hotfix #93 whitelist gate left on every test-2 tenant: the blueprint
        // role (660…05) plus an orphan pre-blueprint imperative-seed role with the same name.
        var duplicateRoleRtId = new OctoObjectId("686a5f60fd3e5972ff5693cd");
        var duplicateRole = new RtRole
        {
            RtId = duplicateRoleRtId,
            Name = "AdminPanelManagement",
            NormalizedName = "ADMINPANELMANAGEMENT",
            // RtWellKnownName intentionally not set — mirrors the pre-PR-#4 imperative seed.
        };
        using (var insertSession = await childRepo!.GetSessionAsync())
        {
            insertSession.StartTransaction();
            await childRepo.InsertOneRtEntityAsync(insertSession, duplicateRole);
            await insertSession.CommitTransactionAsync();
        }

        // 3. Inject a user so the restore has something to re-attach.
        var userRtId = OctoObjectId.GenerateNewId();
        var user = new RtUser
        {
            RtId = userRtId,
            UserName = $"restore-target-{Guid.NewGuid():N}".Substring(0, 24),
            NormalizedUserName = "RESTORE-TARGET",
            Email = "restore-target@example.local",
            NormalizedEmail = "RESTORE-TARGET@EXAMPLE.LOCAL",
            EmailConfirmed = true,
            SecurityStamp = Guid.NewGuid().ToString("N"),
        };
        using (var insertSession = await childRepo.GetSessionAsync())
        {
            insertSession.StartTransaction();
            await childRepo.InsertOneRtEntityAsync(insertSession, user);
            await insertSession.CommitTransactionAsync();
        }

        // 4. Inject the pending-role-assignments configuration row that
        // PreBlueprintCleanupMigration normally writes (and which Identity later consumes in
        // RestorePendingRoleAssignmentsAsync). The migration has already run in this test
        // tenant, so we synthesize the row directly to put the restore step into play.
        var pending = new PendingPostBlueprintRoleAssignments
        {
            UserRoles = new Dictionary<string, List<string>>
            {
                [userRtId.ToString()] = new() { "AdminPanelManagement" }
            }
        };
        var tenantContext = await _fixture.GetSystemContext()
            .GetChildTenantContextAsync(
                await _fixture.GetSystemContext().GetAdminSessionAsync(),
                childTenantId);
        using (var configSession = await tenantContext.GetAdminSessionAsync())
        {
            await tenantContext.SetConfigurationAsync(
                configSession,
                IdentityServiceConstants.PendingPostBlueprintRoleAssignmentsKey,
                pending);
        }

        // 5. Re-run SetupAsync. This re-enters SetupTenantAsync → RestorePendingRoleAssignmentsAsync,
        // which builds the rolesByName index across the duplicate state.
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        var act = async () => await setup.SetupAsync(childTenantId);
        await act.Should().NotThrowAsync(
            "the defensive BuildRoleNameIndex must tolerate duplicate role names instead " +
            "of re-creating the test-2 2026-06-15 startup crash");

        // 6. Verify the rebuilt AssignedRole edge points at the BLUEPRINT-range rtId (660…05),
        // not the operator/legacy duplicate (686…cd). The restore must always rebuild against
        // the authoritative blueprint identity even when the data is dirty.
        var freshChildRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        freshChildRepo.Should().NotBeNull();
        using var assertSession = await freshChildRepo!.GetSessionAsync();
        var edges = await freshChildRepo.GetRtAssociationsAsync(
            assertSession,
            new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtUser>(), userRtId),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));

        var assignedRoleTargets = edges.Items.Select(e => e.TargetRtId.ToString()).ToList();
        assignedRoleTargets.Should().Contain("660000000000000000000005",
            "the post-blueprint restore must wire the user against the blueprint-range " +
            "AdminPanelManagement (660…05), not the pre-blueprint duplicate");
        assignedRoleTargets.Should().NotContain(duplicateRoleRtId.ToString(),
            "the pre-blueprint duplicate must never be picked as the AssignedRole target — " +
            "the index prefers blueprint-range entries even when both exist");
    }

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

        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(tenantId);
        return tenantId;
    }
}
