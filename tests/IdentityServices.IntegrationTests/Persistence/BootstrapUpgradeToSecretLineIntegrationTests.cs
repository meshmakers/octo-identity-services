using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.SecretManagement;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.Exchange;
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
///     AB#5544: upgrade path of the <c>System.Identity.Bootstrap</c> SECRET line (1.7.0) from tenants that run
///     the Files line (1.5.0 before the System.Files data policies, 1.6.0 with them), against a real MongoDB
///     (Testcontainers). A tenant on the old version is built from FROZEN copies of that version's seed files
///     (<c>BootstrapSnapshots/&lt;version&gt;/</c>, taken from git — roles, groups, data permissions/policies),
///     filled with tenant data, then upgraded exactly the way the blueprint update and the identity startup do:
///     the shipped 1.7.0 seed files are imported with the Upsert strategy (the blueprint apply) and
///     <c>SetupAsync</c> runs the one-time grants.
/// </summary>
/// <remarks>
///     The fixture does not register the blueprint catalog (Program.cs-only), so the blueprint apply is
///     reproduced at the level of its seed import. The blueprint version-key gate and the blueprint history
///     are covered by the local-stack run of the Files line (AB#6482); what is asserted here is the data
///     result: nothing the tenant had is lost and the SECRET delta is exactly the role, its TenantOwners edge
///     and the grants to the existing administrators.
/// </remarks>
[Collection("Sequential")]
public class BootstrapUpgradeToSecretLineIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private static readonly OctoObjectId TenantManagementRtId = new("660000000000000000000001");
    private static readonly OctoObjectId AdminPanelManagementRtId = new("660000000000000000000005");
    private static readonly OctoObjectId SecretManagementRtId = new("660000000000000000000060");
    private static readonly OctoObjectId FileManagementRtId = new("660000000000000000000061");
    private static readonly OctoObjectId TenantOwnersRtId = new("660000000000000000000040");

    // Files line seeds that appear with 1.6.0 (AB#6467): permissions 52/53, policies 54/55.
    private static readonly string[] FilesLineSeedRtIds =
    [
        "660000000000000000000052", "660000000000000000000053", "660000000000000000000054", "660000000000000000000055"
    ];

    private static readonly string[] SeedFiles = ["roles.yaml", "groups.yaml", "data-permissions.yaml"];

    private readonly IdentityServicesFixture _fixture;

    public BootstrapUpgradeToSecretLineIntegrationTests(IdentityServicesFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Theory]
    [InlineData("1.5.0")]
    [InlineData("1.6.0")]
    public async Task UpgradeTo170_LosesNothing_AndAddsExactlyTheSecretDelta(string fromVersion)
    {
        var (tenantContext, repo) = await CreateTenantAsync();

        // --- the tenant as it is on the old version ---------------------------------------------------
        await ImportSeedsAsync(repo, SnapshotPath(fromVersion));
        var adminUser = await InsertUserAsync(repo, "admin");
        var adminPanelOnlyUser = await InsertUserAsync(repo, "adminpanel-only");
        var customRoleUser = await InsertUserAsync(repo, "custom");
        var groupMember = await InsertUserAsync(repo, "group-member");
        var ownerUser = await InsertUserAsync(repo, "owner");
        var customRole = await InsertRoleAsync(repo, OctoObjectId.GenerateNewId(), $"custom-{Guid.NewGuid():N}");
        var adminGroup = await InsertGroupAsync(repo, OctoObjectId.GenerateNewId(), $"admins-{Guid.NewGuid():N}");

        await LinkAsync(repo, User(adminUser), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(adminUser), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(adminPanelOnlyUser), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(customRoleUser), Role(customRole), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(adminGroup), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(adminGroup), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(adminGroup), User(groupMember), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, Group(TenantOwnersRtId), User(ownerUser), IdentityAssociationConstants.GroupMemberId);
        // Non-human members of TenantOwners: a provisioned parent-tenant administrator (xt_ shadow user, AB#5708)
        // and a client service account. Neither may end up with SecretManagement.
        var shadowUser = await InsertUserAsync(repo, "xt_parent_gerald");
        var serviceAccount = await InsertClientAsync(repo, "octo-pipeline-sa-");
        await LinkAsync(repo, Group(TenantOwnersRtId), User(shadowUser), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, Group(TenantOwnersRtId), Client(serviceAccount), IdentityAssociationConstants.GroupMemberId);

        OctoObjectId? pipelineAccount = null;
        if (fromVersion == "1.6.0")
        {
            // A pipeline service account that holds FileManagement since 1.6.0 (AB#6467).
            pipelineAccount = await InsertClientAsync(repo, "octo-pipeline-sa-");
            await LinkAsync(repo, Client(pipelineAccount.Value), Role(FileManagementRtId),
                IdentityAssociationConstants.AssignedRoleId);
        }

        // The old version has run its own setup (grants of its time); the SECRET role does not exist yet,
        // so the SECRET grant ends as RoleMissing and records no marker.
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantContext.TenantId);
        (await ReadMarkerAsync(tenantContext)).Should().BeNull("1.7.0 has not been applied yet");
        var before = await CaptureAsync(repo);
        before.Entities.Should().NotContain($"{nameof(RtRole)}:{SecretManagementRtId}");

        // --- the upgrade: blueprint 1.7.0 seed import + identity setup ----------------------------------
        await ImportSeedsAsync(repo, SeedPath());
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantContext.TenantId);
        var after = await CaptureAsync(repo);

        using (new FluentAssertions.Execution.AssertionScope())
        {
            // Nothing is lost.
            before.Entities.Except(after.Entities).Should().BeEmpty("no entity may disappear in the upgrade");
            before.Edges.Except(after.Edges).Should().BeEmpty("no role, group, permission or policy edge may disappear");

            // The SECRET delta: the role itself ...
            var newEntities = after.Entities.Except(before.Entities).ToList();
            var secretEntities = newEntities.Where(e => e.EndsWith(SecretManagementRtId.ToString())).ToList();
            secretEntities.Should().Equal($"{nameof(RtRole)}:{SecretManagementRtId}");

            // ... and direct grants to the existing HUMAN administrators only: no group (TenantOwners included),
            // no client, no cross-tenant shadow user, nobody holding AdminPanelManagement alone.
            var secretEdges = after.Edges.Except(before.Edges)
                .Where(e => e.EndsWith($"|{SecretManagementRtId}")).ToList();
            secretEdges.Should().BeEquivalentTo(new[]
            {
                Edge(User(adminUser), SecretManagementRtId),
                Edge(User(groupMember), SecretManagementRtId),
                Edge(User(ownerUser), SecretManagementRtId)
            }, "local users holding both AdminPanelManagement and TenantManagement, directly or via a group / TenantOwners");

            // Everything else that is new is the Files line (only from 1.5.0), and nothing at all from 1.6.0.
            var otherNewEntities = newEntities.Except(secretEntities).ToList();
            var otherNewEdges = after.Edges.Except(before.Edges).Except(secretEdges).ToList();
            if (fromVersion == "1.6.0")
            {
                otherNewEntities.Should().BeEmpty("from 1.6.0 the SECRET line adds exactly the SECRET delta");
                otherNewEdges.Should().BeEmpty("from 1.6.0 the SECRET line adds exactly the SECRET delta");
            }
            else
            {
                otherNewEntities.Should().OnlyContain(e => FilesLineSeedRtIds.Any(id => e.EndsWith(id)),
                    "from 1.5.0 the only additional seeds are the Files-line permissions and policies");
                otherNewEdges.Should().OnlyContain(e => FilesLineSeedRtIds.Any(id => e.Contains(id)) ||
                                                        e.Contains(FileManagementRtId.ToString()) ||
                                                        e.Contains("660000000000000000000062"),
                    "from 1.5.0 the only additional edges belong to the Files-line permissions and policies");
            }

            // Who does NOT receive SecretManagement.
            (await HasRoleAsync(repo, User(adminPanelOnlyUser), SecretManagementRtId)).Should().BeFalse(
                "AdminPanelManagement alone does not grant secret sweeps");
            (await HasRoleAsync(repo, User(customRoleUser), SecretManagementRtId)).Should().BeFalse();
            (await HasRoleAsync(repo, User(groupMember), SecretManagementRtId)).Should().BeTrue(
                "a human holding both roles through a group gets a direct edge");
            (await HasRoleAsync(repo, User(ownerUser), SecretManagementRtId)).Should().BeTrue(
                "a human member of TenantOwners gets a direct edge");
            (await HasRoleAsync(repo, Group(TenantOwnersRtId), SecretManagementRtId)).Should().BeFalse(
                "TenantOwners also holds clients and provisioned administrators, who would inherit it");
            (await HasRoleAsync(repo, Group(adminGroup), SecretManagementRtId)).Should().BeFalse("no group grant");
            (await HasRoleAsync(repo, User(shadowUser), SecretManagementRtId)).Should().BeFalse(
                "a provisioned parent-tenant administrator (xt_ shadow user) is no local human administrator");
            (await HasRoleAsync(repo, Client(serviceAccount), SecretManagementRtId)).Should().BeFalse(
                "a client in TenantOwners does not inherit it");
            (await HasRoleAsync(repo, User(customRoleUser), customRole)).Should().BeTrue("custom assignments stay");

            if (pipelineAccount != null)
            {
                (await HasRoleAsync(repo, Client(pipelineAccount.Value), FileManagementRtId)).Should().BeTrue(
                    "the pipeline service account keeps FileManagement");
                (await HasRoleAsync(repo, Client(pipelineAccount.Value), SecretManagementRtId)).Should().BeFalse(
                    "a client is not an administrator");
            }

            // The run-once marker is recorded.
            var marker = await ReadMarkerAsync(tenantContext);
            marker.Should().NotBeNull();
            marker!.GrantedUserIds.Should().BeEquivalentTo(
                new[] { adminUser.ToString(), groupMember.ToString(), ownerUser.ToString() });
        }

        // A second identity start / tenant update changes nothing (idempotent, run-once).
        await ImportSeedsAsync(repo, SeedPath());
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantContext.TenantId);
        var again = await CaptureAsync(repo);
        again.Entities.Should().BeEquivalentTo(after.Entities);
        again.Edges.Should().BeEquivalentTo(after.Edges);
    }

    // ---------- seeds ----------

    private async Task ImportSeedsAsync(ITenantRepository repo, string directory)
    {
        // The blueprint applies all seed files as ONE import, so an association may point at an entity of a
        // later file (roles -> data permissions). Importing the files one by one needs two passes for the same
        // result: the second pass materialises the edges whose target did not exist in the first.
        var import = _fixture.GetService<IImportRtModelCommand>();
        for (var pass = 0; pass < 2; pass++)
        {
            foreach (var file in SeedFiles)
            {
                var yaml = await File.ReadAllTextAsync(Path.Combine(directory, file),
                    TestContext.Current.CancellationToken);
                await import.ImportTextAsync(repo, yaml, ImportStrategy.Upsert);
            }
        }
    }

    private static string SnapshotPath(string version) =>
        FindRepoFile($"tests/IdentityServices.IntegrationTests/BootstrapSnapshots/{version}");

    private static string SeedPath() =>
        FindRepoFile("src/Persistence.IdentityCkModel/Blueprints/System.Identity.Bootstrap/seed-data");

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

    // ---------- state capture ----------

    private sealed record TenantState(HashSet<string> Entities, HashSet<string> Edges);

    private static async Task<TenantState> CaptureAsync(ITenantRepository repo)
    {
        var entities = new HashSet<string>();
        var edges = new HashSet<string>();

        async Task CollectAsync<T>(Func<T, OctoObjectId> rtId) where T : RtEntity, new()
        {
            using var session = await repo.GetSessionAsync();
            session.StartTransaction();
            var all = await repo.GetRtEntitiesByTypeAsync<T>(session, RtEntityQueryOptions.Create());
            foreach (var entity in all.Items)
            {
                var id = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<T>(), rtId(entity));
                entities.Add($"{typeof(T).Name}:{rtId(entity)}");
                var outbound = await repo.GetRtAssociationsAsync(session, id,
                    RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound, 0, 5000));
                foreach (var edge in outbound.Items)
                {
                    edges.Add(Edge(id, edge.TargetRtId, edge.AssociationRoleId?.ToString()));
                }
            }

            await session.CommitTransactionAsync();
        }

        await CollectAsync<RtRole>(e => e.RtId);
        await CollectAsync<RtGroup>(e => e.RtId);
        await CollectAsync<RtUser>(e => e.RtId);
        await CollectAsync<RtClient>(e => e.RtId);
        await CollectAsync<RtDataPermission>(e => e.RtId);
        await CollectAsync<RtDataPolicy>(e => e.RtId);
        return new TenantState(entities, edges);
    }

    /// <summary>Edge key: <c>origin|role|target</c>; the role defaults to AssignedRole.</summary>
    private static string Edge(RtEntityId origin, OctoObjectId target, string? role = null) =>
        $"{(origin.CkTypeId.ToString() ?? string.Empty).Split('/').Last()}:{origin.RtId}|{role ?? IdentityAssociationConstants.AssignedRoleId.ToString()}|{target}";

    // ---------- tenant plumbing (same approach as SecretManagementAdminGrantIntegrationTests) ----------

    private async Task<(ITenantContext TenantContext, ITenantRepository Repo)> CreateTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"bsup-{Guid.NewGuid():N}"[..24];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        // Imports the Identity CK model; no blueprint catalog is registered, so no seed role exists yet.
        await setup.SetupAsync(tenantId);

        var tenantContext = await systemContext.GetChildTenantContextAsync(tenantId);
        return (tenantContext, tenantContext.GetTenantRepositoryAsAdmin());
    }

    private static async Task<SecretManagementAdminGrantMarker?> ReadMarkerAsync(ITenantContext tenantContext)
    {
        using var session = await tenantContext.GetAdminSessionAsync();
        return await tenantContext.GetConfigurationAsync<SecretManagementAdminGrantMarker>(
            session, IdentityServiceConstants.SecretManagementAdminGrantKey, defaultValue: null);
    }

    private static RtEntityId User(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtUser>(), id);
    private static RtEntityId Group(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtGroup>(), id);
    private static RtEntityId Role(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtRole>(), id);
    private static RtEntityId Client(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtClient>(), id);

    private static async Task<OctoObjectId> InsertRoleAsync(ITenantRepository repo, OctoObjectId rtId, string name)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = rtId, Name = name, NormalizedName = name.ToUpperInvariant(), RtWellKnownName = name
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<OctoObjectId> InsertUserAsync(ITenantRepository repo, string prefix)
    {
        var rtId = OctoObjectId.GenerateNewId();
        var userName = $"{prefix}-{Guid.NewGuid():N}";
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtUser
        {
            RtId = rtId,
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = $"{userName}@example.com",
            NormalizedEmail = $"{userName}@example.com".ToUpperInvariant(),
            SecurityStamp = Guid.NewGuid().ToString()
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<OctoObjectId> InsertGroupAsync(ITenantRepository repo, OctoObjectId rtId, string name)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtGroup
        {
            RtId = rtId, GroupName = name, NormalizedGroupName = name.ToUpperInvariant()
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<OctoObjectId> InsertClientAsync(ITenantRepository repo, string prefix)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = rtId,
            Enabled = true,
            ClientId = $"{prefix}{Guid.NewGuid():N}",
            ProtocolType = "oidc",
            RequireClientSecret = true,
            AllowedGrantTypes = new AttributeStringValueList { "client_credentials" },
            AllowedScopes = new AttributeStringValueList { "octo_api" }
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task LinkAsync(
        ITenantRepository repo, RtEntityId origin, RtEntityId target, RtCkId<CkAssociationRoleId> roleId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.ApplyChangesAsync(session,
            new[] { AssociationUpdateInfo.CreateInsert(origin, target, roleId) }, new OperationResult());
        await session.CommitTransactionAsync();
    }

    private static async Task<bool> HasRoleAsync(ITenantRepository repo, RtEntityId origin, OctoObjectId roleRtId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var edges = await repo.GetRtAssociationsAsync(session, origin,
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        await session.CommitTransactionAsync();
        return edges.Items.Any(e => e.TargetRtId == roleRtId);
    }
}
