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
        OctoObjectId MappedViaGroup,
        OctoObjectId EmptyMapped,
        OctoObjectId EmptyMapping,
        OctoObjectId WithPassword,
        OctoObjectId Local)
    {
        /// <summary>The candidates, in plan order (rtId).</summary>
        public IReadOnlyList<string> Candidates =>
            new[] { Candidate.ToString(), EmptyMapped.ToString() }.OrderBy(id => id, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    ///     Two candidates (one bare, one with an empty auto-created mapping — rule A), one kept user per rule, plus a local
    ///     user that is never looked at.
    /// </summary>
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
        // Rule A: a mapping keeps its user only when it grants a role — via MappedRoleIds or a group with a role.
        var mappedSource = Suffix();
        var mapped = await InsertUserAsync(repo, $"xt_octosystem_{mappedSource}");
        await InsertMappingAsync(repo, "octosystem", OctoObjectId.GenerateNewId().ToString(), mappedSource,
            mappedRoleIds: [role.ToString()]);
        var owners = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtGroup { RtId = owners, GroupName = "Owners", NormalizedGroupName = "OWNERS" });
        await LinkAsync(repo, Group(owners), new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), role),
            IdentityAssociationConstants.AssignedRoleId);
        var viaGroupSource = Suffix();
        var mappedViaGroup = await InsertUserAsync(repo, $"xt_octosystem_{viaGroupSource}");
        var groupMapping = await InsertMappingAsync(repo, "octosystem", OctoObjectId.GenerateNewId().ToString(),
            viaGroupSource);
        await LinkAsync(repo, Group(owners), Mapping(groupMapping), IdentityAssociationConstants.GroupMemberId);
        // The left-over of a refused exchange / interactive sign-in: user plus an empty mapping, created together.
        // Its mapping is even a member of a group without any role, which grants nothing either.
        var emptySource = Suffix();
        var emptyMapped = await InsertUserAsync(repo, $"xt_octosystem_{emptySource}");
        var emptyMapping = await InsertMappingAsync(repo, "octosystem", OctoObjectId.GenerateNewId().ToString(),
            emptySource);
        await LinkAsync(repo, Group(group), Mapping(emptyMapping), IdentityAssociationConstants.GroupMemberId);
        var withPassword = await InsertUserAsync(repo, $"xt_octosystem_{Suffix()}", passwordHash: "hash");
        var local = await InsertUserAsync(repo, $"local-{Suffix()}");

        return new Arranged(tenantId, repo, candidate, withRole, inGroup, mapped, mappedViaGroup, emptyMapped,
            emptyMapping, withPassword, local);
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
        result.Decisions.Where(d => d.IsCandidate).Select(d => d.RtId).Should().Equal(t.Candidates);
        result.Decisions.Where(d => d.IsCandidate).Should().OnlyContain(d => d.CreatedAt != null);
        Decision(result, t.EmptyMapped).EmptyMappingIds.Should().Equal(t.EmptyMapping.ToString());
        Decision(result, t.Candidate).EmptyMappingIds.Should().BeEmpty();
        Reasons(result, t.WithRole).Should().Equal("role");
        Reasons(result, t.InGroup).Should().Equal("group");
        Reasons(result, t.Mapped).Should().Equal("mapping");
        Reasons(result, t.MappedViaGroup).Should().Equal("mapping");
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
        apply.Deleted.Should().Equal(t.Candidates);
        apply.DeletedMappings.Should().Equal(t.EmptyMapping.ToString());
        audits.Should().HaveCount(2).And.OnlyContain(a => a.Contains(TenantShadowUserCleanup.AuditEventName)
                                                          && a.Contains(t.TenantId));
        audits.Should().ContainSingle(a => a.Contains(t.Candidate.ToString()));
        audits.Should().ContainSingle(a => a.Contains(t.EmptyMapped.ToString()))
            .Which.Should().Contain(t.EmptyMapping.ToString(), "the audit names the deleted mapping id");
        (await UserExistsAsync(t.Repo, t.Candidate)).Should().BeFalse();
        (await UserExistsAsync(t.Repo, t.EmptyMapped)).Should().BeFalse();
        (await MappingIdsAsync(t.Repo)).Should().NotContain(t.EmptyMapping.ToString()).And.HaveCount(2,
            "the role-granting mappings (MappedRoleIds, group with a role) stay");
        foreach (var kept in new[] { t.WithRole, t.InGroup, t.Mapped, t.MappedViaGroup, t.WithPassword, t.Local })
        {
            (await UserExistsAsync(t.Repo, kept)).Should().BeTrue();
        }

        var rerun = (await RunAsync(ShadowUserCleanupMode.Apply, audits, (t.TenantId, t.Repo))).Single();
        rerun.CandidateCount.Should().Be(0);
        rerun.Deleted.Should().BeEmpty();
        rerun.DeletedMappings.Should().BeEmpty();
        audits.Should().HaveCount(2);
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
    public async Task Apply_DeletesAnEmptyAutoCreatedMappingWithItsUser_AndARoleGrantingMappingKeepsItsUser()
    {
        var (tenantId, repo) = await CreateTenantAsync();
        var role = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtRole { RtId = role, Name = "Owner", NormalizedName = "OWNER" });
        var emptySource = Suffix();
        var leftOver = await InsertUserAsync(repo, $"xt_octosystem_{emptySource}");
        var emptyMapping = await InsertMappingAsync(repo, "octosystem", OctoObjectId.GenerateNewId().ToString(),
            emptySource);
        var grantedSource = Suffix();
        var granted = await InsertUserAsync(repo, $"xt_octosystem_{grantedSource}");
        var grantingMapping = await InsertMappingAsync(repo, "octosystem", OctoObjectId.GenerateNewId().ToString(),
            grantedSource, mappedRoleIds: [role.ToString()]);

        var result = (await RunAsync(ShadowUserCleanupMode.Apply, [], (tenantId, repo))).Single();

        result.Deleted.Should().Equal(leftOver.ToString());
        result.DeletedMappings.Should().Equal(emptyMapping.ToString());
        Reasons(result, granted).Should().Equal("mapping");
        (await UserExistsAsync(repo, leftOver)).Should().BeFalse();
        (await UserExistsAsync(repo, granted)).Should().BeTrue();
        (await MappingIdsAsync(repo)).Should().Equal(grantingMapping.ToString());
    }

    [Fact]
    public async Task Apply_TwoTierChain_DeletesTheChainedCandidatesEmptyMapping_AndKeepsTheNearestTierMappingOfAKeptUser()
    {
        // AB#8305 DryRun 2 on test-2 (gastrodemo/handelsdemo): xt_accountingmanagement_xt_octosystem_<n> and the longer
        // kept xt_karlplus_xt_accountingmanagement_xt_octosystem_<n> both match the empty mapping
        // accountingmanagement/xt_octosystem_<n>. The kept user has its own role-granting mapping, so the empty one
        // belongs to the candidate alone and goes with it.
        var (tenantId, repo) = await CreateTenantAsync();
        var role = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtRole { RtId = role, Name = "Owner", NormalizedName = "OWNER" });
        var group = await InsertGroupAsync(repo, "Members");

        var person = Suffix();
        var candidate = await InsertUserAsync(repo, $"xt_accountingmanagement_xt_octosystem_{person}");
        var candidateMapping = await InsertMappingAsync(repo, "accountingmanagement",
            OctoObjectId.GenerateNewId().ToString(), $"xt_octosystem_{person}");
        var keptLonger = await InsertUserAsync(repo, $"xt_karlplus_xt_accountingmanagement_xt_octosystem_{person}");
        await LinkAsync(repo, Group(group), User(keptLonger), IdentityAssociationConstants.GroupMemberId);
        var keptLongerMapping = await InsertMappingAsync(repo, "karlplus", OctoObjectId.GenerateNewId().ToString(),
            $"xt_accountingmanagement_xt_octosystem_{person}", mappedRoleIds: [role.ToString()]);

        // The other way round: the empty mapping is the nearest tier (the grant) of the kept shorter user and only a
        // deeper tier of the rights-less longer one — it stays.
        var other = Suffix();
        var longerCandidate = await InsertUserAsync(repo, $"xt_karlplus_xt_accountingmanagement_xt_octosystem_{other}");
        var keptShorter = await InsertUserAsync(repo, $"xt_accountingmanagement_xt_octosystem_{other}");
        await LinkAsync(repo, Group(group), User(keptShorter), IdentityAssociationConstants.GroupMemberId);
        var keptShorterMapping = await InsertMappingAsync(repo, "accountingmanagement",
            OctoObjectId.GenerateNewId().ToString(), $"xt_octosystem_{other}");

        var dryRun = (await RunAsync(ShadowUserCleanupMode.DryRun, [], (tenantId, repo))).Single();
        Decision(dryRun, candidate).EmptyMappingIds.Should().Equal(candidateMapping.ToString());
        Decision(dryRun, longerCandidate).EmptyMappingIds.Should().BeEmpty();

        var audits = new List<string>();
        var result = (await RunAsync(ShadowUserCleanupMode.Apply, audits, (tenantId, repo))).Single();

        result.Deleted.Should().BeEquivalentTo(candidate.ToString(), longerCandidate.ToString());
        result.DeletedMappings.Should().Equal(candidateMapping.ToString());
        Reasons(result, keptLonger).Should().Equal("group", "mapping");
        Reasons(result, keptShorter).Should().Equal("group");
        (await UserExistsAsync(repo, keptLonger)).Should().BeTrue();
        (await UserExistsAsync(repo, keptShorter)).Should().BeTrue();
        (await MappingIdsAsync(repo)).Should().BeEquivalentTo(keptLongerMapping.ToString(), keptShorterMapping.ToString());
    }

    [Fact]
    public async Task Apply_AMappingInAGroupWhoseChildGroupHoldsARole_KeepsItsUser_ARoleLessGroupTreeDoesNot()
    {
        // Same walk as GroupRoleResolver at token time: a group grants the roles of its ChildGroup targets.
        var (tenantId, repo) = await CreateTenantAsync();
        var role = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtRole { RtId = role, Name = "Owner", NormalizedName = "OWNER" });
        var parentWithRole = await InsertGroupAsync(repo, "ParentWithRole");
        var childWithRole = await InsertGroupAsync(repo, "ChildWithRole");
        await LinkAsync(repo, Group(parentWithRole), Group(childWithRole), IdentityAssociationConstants.ChildGroupId);
        await LinkAsync(repo, Group(childWithRole), new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), role),
            IdentityAssociationConstants.AssignedRoleId);
        var parentWithout = await InsertGroupAsync(repo, "ParentWithout");
        var childWithout = await InsertGroupAsync(repo, "ChildWithout");
        await LinkAsync(repo, Group(parentWithout), Group(childWithout), IdentityAssociationConstants.ChildGroupId);

        var nestedSource = Suffix();
        var nested = await InsertUserAsync(repo, $"xt_octosystem_{nestedSource}");
        var nestedMapping = await InsertMappingAsync(repo, "octosystem", OctoObjectId.GenerateNewId().ToString(),
            nestedSource);
        await LinkAsync(repo, Group(parentWithRole), Mapping(nestedMapping), IdentityAssociationConstants.GroupMemberId);
        var emptyTreeSource = Suffix();
        var emptyTree = await InsertUserAsync(repo, $"xt_octosystem_{emptyTreeSource}");
        var emptyTreeMapping = await InsertMappingAsync(repo, "octosystem", OctoObjectId.GenerateNewId().ToString(),
            emptyTreeSource);
        await LinkAsync(repo, Group(parentWithout), Mapping(emptyTreeMapping), IdentityAssociationConstants.GroupMemberId);

        var audits = new List<string>();
        var result = (await RunAsync(ShadowUserCleanupMode.Apply, audits, (tenantId, repo))).Single();

        Reasons(result, nested).Should().Equal("mapping");
        result.Deleted.Should().Equal(emptyTree.ToString());
        result.DeletedMappings.Should().Equal(emptyTreeMapping.ToString());
        audits.Should().ContainSingle().Which.Should().Contain(emptyTreeMapping.ToString());
        (await UserExistsAsync(repo, nested)).Should().BeTrue();
        (await MappingIdsAsync(repo)).Should().Equal(nestedMapping.ToString());
    }

    [Fact]
    public async Task Apply_OAuthTokensAndAuthorizationsDoNotKeepARightsLessUser_AndAreRevokedWithIt()
    {
        var (tenantId, repo) = await CreateTenantAsync();
        var role = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtRole { RtId = role, Name = "SomeRole", NormalizedName = "SOMEROLE" });

        var withToken = await InsertUserAsync(repo, $"xt_octosystem_{Suffix()}");
        var validToken = await InsertTokenAsync(repo, withToken, "valid", DateTime.UtcNow.AddDays(20));
        var redeemedToken = await InsertTokenAsync(repo, withToken, "redeemed", DateTime.UtcNow.AddDays(20));
        var withAuthorization = await InsertUserAsync(repo, $"xt_octosystem_{Suffix()}");
        var authorization = await InsertAuthorizationAsync(repo, withAuthorization, "valid");
        var withExpired = await InsertUserAsync(repo, $"xt_octosystem_{Suffix()}");
        await InsertTokenAsync(repo, withExpired, "valid", DateTime.UtcNow.AddDays(-1));
        var withRevoked = await InsertUserAsync(repo, $"xt_octosystem_{Suffix()}");
        await InsertAuthorizationAsync(repo, withRevoked, "revoked");
        // A user who can obtain a role keeps its user AND its token.
        var keptWithToken = await InsertUserAsync(repo, $"xt_octosystem_{Suffix()}");
        await LinkAsync(repo, User(keptWithToken), new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), role),
            IdentityAssociationConstants.AssignedRoleId);
        var keptToken = await InsertTokenAsync(repo, keptWithToken, "valid", DateTime.UtcNow.AddDays(20));

        var dryRun = (await RunAsync(ShadowUserCleanupMode.DryRun, [], (tenantId, repo))).Single();
        Decision(dryRun, withToken).OAuth.Should().Be(new ShadowUserOAuthUse(1, 1, 0, 0));
        Decision(dryRun, withAuthorization).OAuth.Should().Be(new ShadowUserOAuthUse(0, 0, 1, 0));
        Decision(dryRun, withExpired).OAuth.Should().Be(new ShadowUserOAuthUse(0, 1, 0, 0));
        Decision(dryRun, withRevoked).OAuth.Should().Be(new ShadowUserOAuthUse(0, 0, 0, 1));
        (await StatusAsync<RtOAuthToken>(repo, validToken)).Should().Be("valid", "DryRun writes nothing");

        var audits = new List<string>();
        var result = (await RunAsync(ShadowUserCleanupMode.Apply, audits, (tenantId, repo))).Single();

        result.Deleted.Should().BeEquivalentTo(new[] { withToken, withAuthorization, withExpired, withRevoked }
            .Select(id => id.ToString()));
        Reasons(result, keptWithToken).Should().Equal("role");
        foreach (var gone in new[] { withToken, withAuthorization, withExpired, withRevoked })
        {
            (await UserExistsAsync(repo, gone)).Should().BeFalse();
        }

        (await StatusAsync<RtOAuthToken>(repo, validToken)).Should().Be("revoked");
        (await StatusAsync<RtOAuthToken>(repo, redeemedToken)).Should().Be("revoked");
        (await StatusAsync<RtOAuthAuthorization>(repo, authorization)).Should().Be("revoked");
        (await StatusAsync<RtOAuthToken>(repo, keptToken)).Should().Be("valid");
        (await UserExistsAsync(repo, keptWithToken)).Should().BeTrue();
        audits.Should().ContainSingle(a => a.Contains(withToken.ToString()))
            .Which.Should().Contain("revoked 2 OAuth token(s)");
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
        results.Single().Deleted.Should().Equal(good.Candidates);
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
        result.DeletedMappings.Should().BeEmpty();
        (await UserExistsAsync(good.Repo, good.Candidate)).Should().BeTrue();
        (await UserExistsAsync(good.Repo, good.EmptyMapped)).Should().BeTrue();
        (await MappingIdsAsync(good.Repo)).Should().Contain(good.EmptyMapping.ToString());
    }

    // ---------- helpers ----------

    private static IReadOnlyList<string> Reasons(ShadowUserCleanupTenantResult result, OctoObjectId rtId) =>
        Decision(result, rtId).SkipReasons;

    private static ShadowUserCleanupDecision Decision(ShadowUserCleanupTenantResult result, OctoObjectId rtId) =>
        result.Decisions.Single(d => d.RtId == rtId.ToString());

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

    private static RtEntityId Group(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtGroup>(), id);

    private static RtEntityId Mapping(OctoObjectId id) =>
        new(RtEntityExtensions.GetRtCkTypeId<RtExternalTenantUserMapping>(), id);

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

    private static async Task<OctoObjectId> InsertGroupAsync(ITenantRepository repo, string name)
    {
        var rtId = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtGroup { RtId = rtId, GroupName = name, NormalizedGroupName = name.ToUpperInvariant() });
        return rtId;
    }

    private static async Task<OctoObjectId> InsertMappingAsync(
        ITenantRepository repo, string sourceTenantId, string sourceUserId, string sourceUserName,
        string[]? mappedRoleIds = null)
    {
        var rtId = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtExternalTenantUserMapping
        {
            RtId = rtId,
            SourceTenantId = sourceTenantId,
            SourceUserId = sourceUserId,
            SourceUserName = sourceUserName,
            MappedRoleIds = mappedRoleIds == null ? null : new AttributeStringValueList(mappedRoleIds.ToList())
        });
        return rtId;
    }

    private static async Task<OctoObjectId> InsertTokenAsync(
        ITenantRepository repo, OctoObjectId subject, string status, DateTime expiresAt)
    {
        var rtId = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtOAuthToken
        {
            RtId = rtId, SubjectId = subject.ToString(), TokenType = "refresh_token", Status = status,
            ExpirationDateTime = expiresAt
        });
        return rtId;
    }

    private static async Task<OctoObjectId> InsertAuthorizationAsync(
        ITenantRepository repo, OctoObjectId subject, string status)
    {
        var rtId = OctoObjectId.GenerateNewId();
        await InsertAsync(repo, new RtOAuthAuthorization
        {
            RtId = rtId, SubjectId = subject.ToString(), ClientId = "test-client",
            Scopes = new AttributeStringValueList { "openid" }, Status = status
        });
        return rtId;
    }

    private static async Task<string?> StatusAsync<T>(ITenantRepository repo, OctoObjectId rtId)
        where T : RtEntity, new()
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var entity = await repo.GetRtEntityByRtIdAsync<T>(session, rtId);
        await session.CommitTransactionAsync();
        return entity switch
        {
            RtOAuthToken token => token.Status,
            RtOAuthAuthorization authorization => authorization.Status,
            _ => null
        };
    }

    private static async Task<List<string>> MappingIdsAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var mappings = await repo.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session,
            RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return mappings.Items.Select(m => m.RtId.ToString()).ToList();
    }

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
