using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.ShadowUserCleanup;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#8305: the cleanup of rights-less cross-tenant shadow users (Off / DryRun / Apply) against a real MongoDB
///     (Testcontainers). Each test uses its own child tenants.
/// </summary>
[Collection("Sequential")]
public class ShadowUserCleanupIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public ShadowUserCleanupIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    private sealed record Arranged(
        string TenantId,
        ITenantRepository Repo,
        OctoObjectId Candidate,
        OctoObjectId WithRole,
        OctoObjectId InGroup,
        OctoObjectId Mapped,
        OctoObjectId WithPassword,
        OctoObjectId Local);

    /// <summary>One candidate and one kept user per rule, plus a local user that is never looked at.</summary>
    private async Task<Arranged> ArrangeTenantAsync()
    {
        var (tenantId, repo) = await CreateTenantAsync();
        var role = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtRole { RtId = role, Name = "SomeRole", NormalizedName = "SOMEROLE" });
        var group = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtGroup { RtId = group, GroupName = "SomeGroup", NormalizedGroupName = "SOMEGROUP" });

        var candidate = await InsertUserAsync(repo, $"xt_octosystem_{Suffix()}");
        var withRole = await InsertUserAsync(repo, $"xt_octosystem_{Suffix()}");
        await LinkAsync(repo, User(withRole), new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), role),
            IdentityAssociationConstants.AssignedRoleId);
        var inGroup = await InsertUserAsync(repo, $"xt_octosystem_{Suffix()}");
        await LinkAsync(repo, new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtGroup>(), group), User(inGroup),
            IdentityAssociationConstants.GroupMemberId);
        var mappedSource = Suffix();
        var mapped = await InsertUserAsync(repo, $"xt_octosystem_{mappedSource}");
        await InsertMappingAsync(repo, "octosystem", OctoObjectId.GenerateNewId().ToString(), mappedSource);
        var withPassword = await InsertUserAsync(repo, $"xt_octosystem_{Suffix()}", passwordHash: "hash");
        var local = await InsertUserAsync(repo, $"local-{Suffix()}");

        return new Arranged(tenantId, repo, candidate, withRole, inGroup, mapped, withPassword, local);
    }

    [Fact]
    public async Task DryRun_ReportsTheCandidateAndEveryKeptUsersReason_AndWritesNothing()
    {
        var t = await ArrangeTenantAsync();
        var before = await SnapshotAsync(t.Repo);
        var audits = new List<string>();

        var results = await RunAsync(ShadowUserCleanupMode.DryRun, audits, (t.TenantId, t.Repo));

        var result = results.Should().ContainSingle().Subject;
        result.Mode.Should().Be(ShadowUserCleanupMode.DryRun);
        result.Decisions.Where(d => d.IsCandidate).Select(d => d.RtId).Should().Equal(t.Candidate.ToString());
        result.Decisions.Single(d => d.IsCandidate).CreatedAt.Should().NotBeNull();
        Reasons(result, t.WithRole).Should().Equal("role");
        Reasons(result, t.InGroup).Should().Equal("group");
        Reasons(result, t.Mapped).Should().Equal("mapping");
        Reasons(result, t.WithPassword).Should().Equal("direct-use:password");
        result.Decisions.Should().NotContain(d => d.RtId == t.Local.ToString(), "only xt_ users are considered");
        result.Deleted.Should().BeEmpty();
        audits.Should().BeEmpty();
        (await SnapshotAsync(t.Repo)).Should().BeEquivalentTo(before, "DryRun writes nothing");
    }

    [Fact]
    public async Task Apply_DeletesExactlyTheDryRunCandidates_AuditsEach_AndARerunFindsNothing()
    {
        var t = await ArrangeTenantAsync();
        var dryRun = (await RunAsync(ShadowUserCleanupMode.DryRun, [], (t.TenantId, t.Repo))).Single();
        var audits = new List<string>();

        var apply = (await RunAsync(ShadowUserCleanupMode.Apply, audits, (t.TenantId, t.Repo))).Single();

        apply.Deleted.Should().BeEquivalentTo(dryRun.Decisions.Where(d => d.IsCandidate).Select(d => d.RtId));
        apply.Deleted.Should().Equal(t.Candidate.ToString());
        audits.Should().ContainSingle().Which.Should().Contain(TenantShadowUserCleanup.AuditEventName)
            .And.Contain(t.Candidate.ToString()).And.Contain(t.TenantId);
        (await UserExistsAsync(t.Repo, t.Candidate)).Should().BeFalse();
        foreach (var kept in new[] { t.WithRole, t.InGroup, t.Mapped, t.WithPassword, t.Local })
        {
            (await UserExistsAsync(t.Repo, kept)).Should().BeTrue();
        }

        var rerun = (await RunAsync(ShadowUserCleanupMode.Apply, audits, (t.TenantId, t.Repo))).Single();
        rerun.CandidateCount.Should().Be(0);
        rerun.Deleted.Should().BeEmpty();
        audits.Should().HaveCount(1);
    }

    [Fact]
    public async Task Apply_KeepsAUserThatIsTheSourceOfAMappingInAnotherTenant()
    {
        var parent = await ArrangeTenantAsync();
        var (childId, childRepo) = await CreateTenantAsync();
        var parentShadowName = await UserNameAsync(parent.Repo, parent.Candidate);
        await InsertMappingAsync(childRepo, parent.TenantId, parent.Candidate.ToString(), parentShadowName);

        var results = await RunAsync(ShadowUserCleanupMode.Apply, [],
            (parent.TenantId, parent.Repo), (childId, childRepo));

        Reasons(results.Single(r => r.TenantId == parent.TenantId), parent.Candidate).Should().Equal("chain-source");
        (await UserExistsAsync(parent.Repo, parent.Candidate)).Should().BeTrue();
    }

    [Fact]
    public async Task Off_ReadsNothing()
    {
        var repository = Substitute.For<ITenantRepository>();

        var results = await RunAsync(ShadowUserCleanupMode.Off, [], ("any", repository));

        results.Should().BeEmpty();
        repository.ReceivedCalls().Should().BeEmpty();
    }

    [Fact]
    public async Task AFailingTenant_IsLogged_AndTheOtherTenantsAreStillCleanedUp()
    {
        var good = await ArrangeTenantAsync();
        var (brokenId, brokenRepo) = await CreateTenantAsync();

        var results = await ShadowUserCleanupJob.RunAsync(
            [(brokenId, brokenRepo), (good.TenantId, good.Repo)],
            ShadowUserCleanupMode.Apply,
            repository => repository == brokenRepo
                ? throw new InvalidOperationException("simulated tenant failure")
                : NewStore(repository),
            null, NullLogger.Instance, TestContext.Current.CancellationToken);

        results.Select(r => r.TenantId).Should().Equal(good.TenantId);
        results.Single().Deleted.Should().Equal(good.Candidate.ToString());
    }

    [Fact]
    public async Task UnreadableMappingsOfOneTenant_DowngradeApplyToDryRun_ForAllTenants()
    {
        var good = await ArrangeTenantAsync();
        var broken = Substitute.For<ITenantRepository>();
        broken.When(r => r.GetSessionAsync()).Do(_ => throw new InvalidOperationException("unreachable"));

        var results = await RunAsync(ShadowUserCleanupMode.Apply, [], ("broken", broken), (good.TenantId, good.Repo));

        var result = results.Single(r => r.TenantId == good.TenantId);
        result.Mode.Should().Be(ShadowUserCleanupMode.DryRun);
        result.Deleted.Should().BeEmpty();
        (await UserExistsAsync(good.Repo, good.Candidate)).Should().BeTrue();
    }

    // ---------- helpers ----------

    private static IReadOnlyList<string> Reasons(ShadowUserCleanupTenantResult result, OctoObjectId rtId) =>
        result.Decisions.Single(d => d.RtId == rtId.ToString()).SkipReasons;

    private static Task<IReadOnlyList<ShadowUserCleanupTenantResult>> RunAsync(
        ShadowUserCleanupMode mode, List<string> audits, params (string TenantId, ITenantRepository Repo)[] tenants) =>
        ShadowUserCleanupJob.RunAsync(
            tenants.Select(t => (t.TenantId, t.Repo)).ToList(), mode, NewStore,
            (tenantId, message) =>
            {
                audits.Add($"{tenantId}: {message}");
                return Task.CompletedTask;
            },
            NullLogger.Instance,
            TestContext.Current.CancellationToken);

    private static IUserStore<RtUser> NewStore(ITenantRepository repository) =>
        new OctoUserStore(new FixedTenantResolver(repository), Substitute.For<IGroupRoleResolver>(), null);

    private sealed class FixedTenantResolver(ITenantRepository repository) : IMultiTenancyResolverService
    {
        public ITenantRepository GetTenantRepository() => repository;
        public string GetTenantId() => repository.TenantId;
    }

    private async Task<(string TenantId, ITenantRepository Repo)> CreateTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"xtclean-{Guid.NewGuid():N}"[..24];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        await setup.SetupAsync(tenantId);
        var tenantContext = await systemContext.GetChildTenantContextAsync(tenantId);
        return (tenantId, tenantContext.GetTenantRepositoryAsAdmin());
    }

    private static string Suffix() => Guid.NewGuid().ToString("N")[..12];

    private static RtEntityId User(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtUser>(), id);

    private static async Task InsertAsync<T>(ITenantRepository repo, T entity) where T : RtEntity, new()
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, entity);
        await session.CommitTransactionAsync();
    }

    private static async Task<OctoObjectId> InsertUserAsync(ITenantRepository repo, string userName, string? passwordHash = null)
    {
        var rtId = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtUser
        {
            RtId = rtId,
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            EmailConfirmed = true,
            PasswordHash = passwordHash,
            SecurityStamp = Guid.NewGuid().ToString()
        });
        return rtId;
    }

    private static Task InsertMappingAsync(
        ITenantRepository repo, string sourceTenantId, string sourceUserId, string sourceUserName) =>
        InsertAsync(repo, new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = sourceTenantId,
            SourceUserId = sourceUserId,
            SourceUserName = sourceUserName
        });

    private static async Task LinkAsync(
        ITenantRepository repo, RtEntityId origin, RtEntityId target, RtCkId<CkAssociationRoleId> roleId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.ApplyChangesAsync(session, [AssociationUpdateInfo.CreateInsert(origin, target, roleId)],
            new OperationResult());
        await session.CommitTransactionAsync();
    }

    private static async Task<bool> UserExistsAsync(ITenantRepository repo, OctoObjectId rtId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var user = await repo.GetRtEntityByRtIdAsync<RtUser>(session, rtId);
        await session.CommitTransactionAsync();
        return user != null;
    }

    private static async Task<string> UserNameAsync(ITenantRepository repo, OctoObjectId rtId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var user = await repo.GetRtEntityByRtIdAsync<RtUser>(session, rtId);
        await session.CommitTransactionAsync();
        return user!.UserName!;
    }

    /// <summary>Users (rtId, name, version), mappings and the association edges of every user.</summary>
    private static async Task<List<string>> SnapshotAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var lines = new List<string>();
        var users = await repo.GetRtEntitiesByTypeAsync<RtUser>(session, RtEntityQueryOptions.Create());
        foreach (var user in users.Items)
        {
            lines.Add($"user {user.RtId} {user.UserName} {user.RtChangedDateTime:o}");
            var edges = await repo.GetRtAssociationsAsync(session, User(user.RtId),
                RtAssociationExtendedQueryOptions.Create(GraphDirections.Any));
            lines.AddRange(edges.Items.Select(e => $"edge {e.OriginRtId} {e.AssociationRoleId} {e.TargetRtId}"));
        }

        var mappings = await repo.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session,
            RtEntityQueryOptions.Create());
        lines.AddRange(mappings.Items.Select(m => $"mapping {m.RtId} {m.RtChangedDateTime:o}"));
        await session.CommitTransactionAsync();
        lines.Sort(StringComparer.Ordinal);
        return lines;
    }
}
