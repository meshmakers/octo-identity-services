using FluentAssertions;

using IdentityServices.IntegrationTests.Fixtures;

using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.Exchange;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;

using Persistence.IdentityCkModel.Generated.System.Identity.v3;

using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     System.Identity 3.6.0: every type of the model is written only by system sessions (the identity service's own stores,
///     blueprint seeds, the system path of ImportRt, tenant restores). The model declares
///     <c>writeAccess: { channels: [ System.Identity/IdentityService ] }</c> on every root type, no service opens a session
///     on that channel, so every caller-scoped write - the generic GraphQL mutations, the caller path of ImportRt, adapter
///     write nodes - is refused by the engine with message 144 before anything is written. Real MongoDB, the real model of
///     this repository.
/// </summary>
[Collection("Sequential")]
public class IdentityTypeWriteAccessIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private const string IdentityWriteChannel = "System.Identity/IdentityService";
    private const int WriteAccessRefusedMessageNumber = 144;

    private static readonly string[] AdministratorRoles = ["TenantManagement", "UserManagement", "SecretManagement"];

    private readonly IdentityServicesFixture _fixture;

    public IdentityTypeWriteAccessIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    public static TheoryData<RtPrincipalKind> CallerKinds =>
        new() { RtPrincipalKind.Interactive, RtPrincipalKind.Client, RtPrincipalKind.Unknown };

    // ----------------------------------------------------------------------------------------------
    // Compiled model
    // ----------------------------------------------------------------------------------------------

    [Fact]
    public async Task CompiledModel_EveryIdentityType_IsWrittenOnlyThroughTheIdentityChannel()
    {
        var repo = await GetRepositoryAsync();
        var types = typeof(RtRole).Assembly.GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false } && t.Namespace == typeof(RtRole).Namespace &&
                        typeof(RtEntity).IsAssignableFrom(t))
            .ToList();
        types.Should().Contain([typeof(RtRole), typeof(RtClient), typeof(RtApiScope), typeof(RtOctoTenantIdentityProvider)]);

        foreach (var type in types)
        {
            var ckTypeId = CkTypeIdOf(type);
            var graph = await repo.GetCkTypeGraphAsync(ckTypeId);

            // The block is declared on the root types and inherited by the resources and identity providers.
            var declaring = graph.WriteAccess != null
                ? graph
                : await repo.GetCkTypeGraphAsync(VersionLess(graph.DerivedFromCkTypeId!.ToString()));
            declaring.WriteAccess.Should().NotBeNull($"{ckTypeId} must not be writable by a caller-scoped session");
            declaring.WriteAccess!.Principals.Should().BeNullOrEmpty($"{ckTypeId}: no principal kind may write it");
            declaring.WriteAccess.Channels.Should().Equal([IdentityWriteChannel], $"{ckTypeId}: only the identity channel");
        }
    }

    // ----------------------------------------------------------------------------------------------
    // Caller-scoped writes are refused (the generic GraphQL / adapter write path)
    // ----------------------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(CallerKinds))]
    public async Task CallerSession_CreatingARole_IsRefusedWithMessage144_AndNothingIsWritten(RtPrincipalKind kind)
    {
        var repo = await GetRepositoryAsync();
        var name = $"generic-role-{Guid.NewGuid():N}";
        var role = new RtRole { RtId = OctoObjectId.GenerateNewId(), Name = name, NormalizedName = name.ToUpperInvariant() };

        var refused = await TryApplyAsync(repo, Caller(kind),
            [EntityUpdateInfo<RtEntity>.CreateInsert(role)]);

        AssertRefused(refused, "System.Identity/Role");
        (await FindAsync<RtRole>(repo, role.RtId)).Should().BeNull("nothing is written");
    }

    [Theory]
    [MemberData(nameof(CallerKinds))]
    public async Task CallerSession_RenamingOrDeletingAnExistingRole_IsRefused_AndTheRoleIsUnchanged(RtPrincipalKind kind)
    {
        var repo = await GetRepositoryAsync();
        var name = $"existing-role-{Guid.NewGuid():N}";
        var rtId = OctoObjectId.GenerateNewId();
        await ImportAsync(repo, RoleSeed(rtId, name));
        var roleId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), rtId);

        var renamed = await TryApplyAsync(repo, Caller(kind),
        [
            EntityUpdateInfo<RtEntity>.CreateUpdate(roleId,
                new RtRole { Name = "TenantManagement", NormalizedName = "TENANTMANAGEMENT" })
        ]);
        AssertRefused(renamed, "System.Identity/Role");

        var deleted = await TryApplyAsync(repo, Caller(kind), [EntityUpdateInfo<RtEntity>.CreateDelete(roleId)]);
        AssertRefused(deleted, "System.Identity/Role");

        var stored = await FindAsync<RtRole>(repo, rtId);
        stored.Should().NotBeNull("the delete was refused");
        stored!.Name.Should().Be(name, "the rename was refused");
    }

    [Fact]
    public async Task CallerSession_DerivedTypes_InheritTheRestriction()
    {
        var repo = await GetRepositoryAsync();
        var caller = Caller(RtPrincipalKind.Interactive);

        var scope = new RtApiScope { RtId = OctoObjectId.GenerateNewId(), Name = $"generic-scope-{Guid.NewGuid():N}" };
        AssertRefused(await TryApplyAsync(repo, caller, [EntityUpdateInfo<RtEntity>.CreateInsert(scope)]),
            "System.Identity/ApiScope");
        (await FindAsync<RtApiScope>(repo, scope.RtId)).Should().BeNull();

        var provider = new RtOctoTenantIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(), Name = $"generic-idp-{Guid.NewGuid():N}", IsEnabled = true
        };
        AssertRefused(await TryApplyAsync(repo, caller, [EntityUpdateInfo<RtEntity>.CreateInsert(provider)]),
            "System.Identity/OctoTenantIdentityProvider");
        (await FindAsync<RtOctoTenantIdentityProvider>(repo, provider.RtId)).Should().BeNull();
    }

    [Fact]
    public async Task CallerSession_WritingTheSecretsOfASeededClient_IsRefused()
    {
        var repo = await GetRepositoryAsync();
        await ImportBootstrapSeedsAsync(repo);
        var client = await FirstAsync<RtClient>(repo);
        var secretsBefore = client.ClientSecrets.Count;

        var update = new RtClient();
        update.ClientSecrets.Add(new RtSecretRecord { Value = "a-hash-the-caller-chose", Type = "SharedSecret" });
        var refused = await TryApplyAsync(repo, Caller(RtPrincipalKind.Interactive),
        [
            EntityUpdateInfo<RtEntity>.CreateUpdate(
                new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtClient>(), client.RtId), update)
        ]);

        AssertRefused(refused, "System.Identity/Client");
        (await FindAsync<RtClient>(repo, client.RtId))!.ClientSecrets.Count.Should().Be(secretsBefore);
    }

    [Fact]
    public async Task CallerSession_SwitchingTheEnforcementModeOfADataPolicy_IsRefused()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        await ImportAsync(repo, PolicySeed(rtId));
        var policyId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtDataPolicy>(), rtId);

        var refused = await TryApplyAsync(repo, Caller(RtPrincipalKind.Interactive),
        [
            EntityUpdateInfo<RtEntity>.CreateUpdate(policyId,
                new RtDataPolicy { EnforcementMode = RtDataPolicyEnforcementModeEnum.Enforce })
        ]);

        AssertRefused(refused, "System.Identity/DataPolicy");
        (await FindAsync<RtDataPolicy>(repo, rtId))!.EnforcementMode.Should().Be(RtDataPolicyEnforcementModeEnum.AuditOnly);
    }

    [Fact]
    public async Task CallerSession_AnAssociationBetweenIdentityEntities_IsRefused()
    {
        var repo = await GetRepositoryAsync();
        var policyRtId = OctoObjectId.GenerateNewId();
        var permissionRtId = OctoObjectId.GenerateNewId();
        await ImportAsync(repo, PolicySeed(policyRtId));
        await ImportAsync(repo, PermissionSeed(permissionRtId));

        // PolicyPermission is not one of the identity-owned association roles; the type restriction covers it.
        var association = AssociationUpdateInfo.CreateInsert(
            new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtDataPolicy>(), policyRtId),
            new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtDataPermission>(), permissionRtId),
            new RtCkId<CkAssociationRoleId>("System.Identity/PolicyPermission"));

        var refused = await TryApplyAsync(repo, Caller(RtPrincipalKind.Interactive), [], [association]);

        refused.Should().NotBeNull();
        refused!.OperationResult!.Messages.Should().Contain(m => m.MessageNumber == WriteAccessRefusedMessageNumber);

        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var edges = await repo.GetRtAssociationsAsync(session,
            new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtDataPolicy>(), policyRtId),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: new RtCkId<CkAssociationRoleId>("System.Identity/PolicyPermission")));
        await session.CommitTransactionAsync();
        edges.Items.Should().BeEmpty("the refused association is not stored");
    }

    // ----------------------------------------------------------------------------------------------
    // Caller path of ImportRt (bot-services ImportModelJob) is refused, atomically
    // ----------------------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(CallerKinds))]
    public async Task CallerImport_OfAnIdentityEntity_IsRefusedWithMessage144_BeforeAnyWrite(RtPrincipalKind kind)
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        var file = Path.Combine(Path.GetTempPath(), $"identity-caller-import-{Guid.NewGuid():N}.yaml");
        await File.WriteAllTextAsync(file, RoleSeed(rtId, $"imported-role-{Guid.NewGuid():N}"),
            TestContext.Current.CancellationToken);
        try
        {
            var act = () => _fixture.GetService<IImportRtModelCommand>().ImportAsCallerAsync(repo, file,
                ExchangeMimeTypes.MimeTypeYaml, ImportStrategy.Upsert,
                RtImportCallerContext.UserInitiated("importing-user", kind));

            var refused = await act.Should().ThrowAsync<ExchangeException>();
            refused.Which.MessageNumber.Should().Be(WriteAccessRefusedMessageNumber);
            (await FindAsync<RtRole>(repo, rtId)).Should().BeNull("the preflight refuses the whole file before any write");
        }
        finally
        {
            File.Delete(file);
        }
    }

    // ----------------------------------------------------------------------------------------------
    // System writes keep working
    // ----------------------------------------------------------------------------------------------

    [Fact]
    public async Task BootstrapSeeds_AreInstalled_ThroughTheSystemImport()
    {
        var repo = await GetRepositoryAsync();

        // The seed files of System.Identity.Bootstrap (those without blueprint variables), through the import the blueprint
        // apply uses. Upsert, so a re-run on the shared database re-applies them.
        await ImportBootstrapSeedsAsync(repo);

        (await FirstAsync<RtRole>(repo)).Should().NotBeNull("the bootstrap blueprint seeds the roles");
        (await FirstAsync<RtClient>(repo)).Should().NotBeNull("and the clients");
        (await FirstAsync<RtApiScope>(repo)).Should().NotBeNull("and the API scopes");
        (await FirstAsync<RtDataPermission>(repo)).Should().NotBeNull("and the data permissions");
    }

    [Fact]
    public async Task SystemImport_AndSystemSession_StillWriteIdentityTypes()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        var name = $"system-role-{Guid.NewGuid():N}";

        await ImportAsync(repo, RoleSeed(rtId, name));
        (await FindAsync<RtRole>(repo, rtId))!.Name.Should().Be(name, "the system import (blueprint seed) writes");

        var renamed = await TryApplyAsync(repo, RtSecurityContext.System,
        [
            EntityUpdateInfo<RtEntity>.CreateUpdate(new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), rtId),
                new RtRole { Name = name + "-renamed", NormalizedName = (name + "-renamed").ToUpperInvariant() })
        ]);
        renamed.Should().BeNull("a system session (the identity stores) is never restricted");
        (await FindAsync<RtRole>(repo, rtId))!.Name.Should().Be(name + "-renamed");
    }

    [Fact]
    public async Task TenantRestore_BringsBackIdentityData_AndTheRestoredTenantKeepsTheRestriction()
    {
        await GetRepositoryAsync();
        var systemContext = _fixture.GetSystemContext();
        var originalTenantId = $"wabackup{Guid.NewGuid():N}"[..20];
        var restoredTenantId = $"warestore{Guid.NewGuid():N}"[..20];
        var backupDirectory = Path.Combine(Path.GetTempPath(), $"identity-write-access-{Guid.NewGuid():N}");
        var archivePath = Path.Combine(backupDirectory, "backup.tar.gz");
        var rtId = OctoObjectId.GenerateNewId();
        var name = $"restored-role-{Guid.NewGuid():N}";

        try
        {
            using (var session = await systemContext.GetAdminSessionAsync())
            {
                session.StartTransaction();
                await systemContext.CreateChildTenantAsync(session, originalTenantId, originalTenantId);
                await session.CommitTransactionAsync();
            }

            await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(originalTenantId);
            var original = await systemContext.FindTenantRepositoryAsync(originalTenantId)
                           ?? throw new InvalidOperationException("The child tenant was not created.");
            await ImportAsync(original, RoleSeed(rtId, name));

            Directory.CreateDirectory(backupDirectory);
            var backup = await systemContext.BackupTenantAsync(originalTenantId, archivePath);
            backup.Success.Should().BeTrue(backup.Error);

            // A restore is a database restore (mongorestore) plus attach: no engine write path, so writeAccess cannot refuse it.
            var restore = await systemContext.RestoreTenantAsync(restoredTenantId, restoredTenantId, archivePath,
                sourceDatabaseName: originalTenantId, dropExistingTenant: true, attachTenant: true,
                timeout: TimeSpan.FromMinutes(5));
            restore.Success.Should().BeTrue(restore.Error);

            var restored = await systemContext.FindTenantRepositoryAsync(restoredTenantId)
                           ?? throw new InvalidOperationException("The restored tenant was not attached.");
            (await FindAsync<RtRole>(restored, rtId))!.Name.Should().Be(name, "the restore brings the identity data back");

            var roleId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), rtId);
            (await TryApplyAsync(restored, RtSecurityContext.System,
            [
                EntityUpdateInfo<RtEntity>.CreateUpdate(roleId,
                    new RtRole { Name = name + "-system", NormalizedName = (name + "-system").ToUpperInvariant() })
            ])).Should().BeNull("the identity stores (system sessions) write the restored tenant");

            AssertRefused(await TryApplyAsync(restored, Caller(RtPrincipalKind.Interactive),
            [
                EntityUpdateInfo<RtEntity>.CreateUpdate(roleId,
                    new RtRole { Name = "TenantManagement", NormalizedName = "TENANTMANAGEMENT" })
            ]), "System.Identity/Role");
            (await FindAsync<RtRole>(restored, rtId))!.Name.Should().Be(name + "-system");
        }
        finally
        {
            foreach (var tenantId in new[] { originalTenantId, restoredTenantId })
            {
                try
                {
                    using var session = await systemContext.GetAdminSessionAsync();
                    session.StartTransaction();
                    if (await systemContext.IsChildTenantExistingAsync(session, tenantId))
                    {
                        await systemContext.DropChildTenantAsync(session, tenantId);
                    }

                    await session.CommitTransactionAsync();
                }
                catch (Exception)
                {
                    // Best effort: the shared test database is dropped with the container.
                }
            }

            if (Directory.Exists(backupDirectory))
            {
                Directory.Delete(backupDirectory, true);
            }
        }
    }

    [Fact]
    public async Task ASessionOnTheIdentityChannel_IsAdmitted()
    {
        var repo = await GetRepositoryAsync();
        var name = $"channel-role-{Guid.NewGuid():N}";
        var role = new RtRole { RtId = OctoObjectId.GenerateNewId(), Name = name, NormalizedName = name.ToUpperInvariant() };

        var result = await TryApplyAsync(repo,
            Caller(RtPrincipalKind.Interactive).WithWriteChannel(IdentityWriteChannel),
            [EntityUpdateInfo<RtEntity>.CreateInsert(role)]);

        result.Should().BeNull("the channel named in the model admits the write");
        (await FindAsync<RtRole>(repo, role.RtId)).Should().NotBeNull();
    }

    // ----------------------------------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------------------------------

    private static RtSecurityContext Caller(RtPrincipalKind kind) =>
        RtSecurityContext.ForUser("generic-caller", AdministratorRoles, kind);

    private static void AssertRefused(RuntimeRepositoryException? refused, string ckTypeId)
    {
        refused.Should().NotBeNull($"a caller-scoped write of {ckTypeId} must be refused");
        refused!.OperationResult.Should().NotBeNull();
        refused.OperationResult!.Messages.Should().Contain(m => m.MessageNumber == WriteAccessRefusedMessageNumber,
            "the engine's writeAccess refusal (message 144)");
    }

    // "System.Identity-3.6.0/Resource" -> "System.Identity/Resource" (the CK cache is keyed by the version-less id).
    private static RtCkId<CkTypeId> VersionLess(string ckTypeId)
    {
        var slash = ckTypeId.IndexOf('/');
        var model = ckTypeId[..slash];
        var dash = model.LastIndexOf('-');
        if (dash > 0 && dash < model.Length - 1 && char.IsDigit(model[dash + 1]))
        {
            model = model[..dash];
        }

        return new RtCkId<CkTypeId>(model + ckTypeId[slash..]);
    }

    private async Task ImportBootstrapSeedsAsync(ITenantRepository repo)
    {
        // AB#9042: the data permissions too - the creates of Client and DataPermission are methods since System.Identity 3.8.0,
        // without replacesGenericCreate, so the blueprint's system import keeps seeding them.
        foreach (var file in new[] { "roles.yaml", "api-scopes.yaml", "clients/octo-tool.yaml", "data-permissions.yaml" })
        {
            await ImportAsync(repo, await File.ReadAllTextAsync(FindRepoFile(
                    $"src/Persistence.IdentityCkModel/Blueprints/System.Identity.Bootstrap/seed-data/{file}"),
                TestContext.Current.CancellationToken));
        }
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

    private static RtCkId<CkTypeId> CkTypeIdOf(Type type) =>
        (RtCkId<CkTypeId>)typeof(RtEntityExtensions).GetMethods()
            .Single(m => m.Name == nameof(RtEntityExtensions.GetRtCkTypeId) && m.GetParameters().Length == 0)
            .MakeGenericMethod(type).Invoke(null, null)!;

    private static async Task<RuntimeRepositoryException?> TryApplyAsync(ITenantRepository repo,
        RtSecurityContext securityContext, List<IEntityUpdateInfo<RtEntity>> updates,
        List<AssociationUpdateInfo>? associations = null)
    {
        using var session = await repo.GetSessionAsync(securityContext);
        session.StartTransaction();
        try
        {
            await repo.ApplyChangesAsync(session, updates, associations ?? [], new OperationResult());
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

    private static async Task<T?> FindAsync<T>(ITenantRepository repo, OctoObjectId rtId) where T : RtEntity, new()
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var entity = await repo.GetRtEntityByRtIdAsync<T>(session, rtId);
        await session.CommitTransactionAsync();
        return entity;
    }

    private static async Task<T> FirstAsync<T>(ITenantRepository repo) where T : RtEntity, new()
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var result = await repo.GetRtEntitiesByTypeAsync<T>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return result.Items.First();
    }

    private static string RoleSeed(OctoObjectId rtId, string name) => $"""
        $schema: https://schemas.meshmakers.cloud/runtime-model.schema.json
        dependencies:
          - System.Identity-3.0.0
        entities:
          - rtId: '{rtId}'
            ckTypeId: System.Identity/Role
            attributes:
              - id: System/Name
                value: {name}
              - id: System.Identity/NormalizedName
                value: {name.ToUpperInvariant()}
        """;

    private static string PermissionSeed(OctoObjectId rtId) => $"""
        $schema: https://schemas.meshmakers.cloud/runtime-model.schema.json
        dependencies:
          - System.Identity-3.0.0
        entities:
          - rtId: '{rtId}'
            ckTypeId: System.Identity/DataPermission
            attributes:
              - id: System.Identity/PermissionId
                value: write-access-{rtId}
        """;

    // PolicyEnforcementMode 1 = AuditOnly: the policy restricts nobody, so it cannot disturb other tests of the shared database.
    private static string PolicySeed(OctoObjectId rtId) => $"""
        $schema: https://schemas.meshmakers.cloud/runtime-model.schema.json
        dependencies:
          - System.Identity-3.0.0
        entities:
          - rtId: '{rtId}'
            ckTypeId: System.Identity/DataPolicy
            attributes:
              - id: System.Identity/TargetCkTypeIds
                value:
                  - System.Identity/EmailDomainGroupRule
              - id: System.Identity/PolicyActions
                value:
                  - Read
              - id: System.Identity/PolicyEnforcementMode
                value: 1
        """;
}
