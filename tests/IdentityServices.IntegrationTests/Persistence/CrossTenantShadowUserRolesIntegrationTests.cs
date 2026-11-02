using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#5708 against a real MongoDB (Testcontainers): the effective roles of a cross-tenant shadow
///     user are resolved at token time from the groups its <c>ExternalTenantUserMapping</c> is a member
///     of (e.g. <c>TenantOwners</c>) and the mapping's <c>MappedRoleIds</c> — so a role a blueprint adds
///     to such a group later reaches the user on the next token, and a removed membership takes its role
///     away while manually assigned roles stay. Also pins one shadow user per person across login paths.
/// </summary>
/// <remarks>
///     Roles are read through <see cref="OctoUserStore.GetRolesAsync" /> — the store that stamps the
///     token's <c>role</c> claims (<c>OctoTokenClaimsService</c>) on every issuance and refresh.
/// </remarks>
public class CrossTenantShadowUserRolesIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public CrossTenantShadowUserRolesIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task BlueprintAddsRoleToOwnersGroupLater_CrossTenantUserGetsItOnNextToken()
    {
        var ctx = await ArrangeChildWithOwnersGroupAsync();

        var shadow = await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(ctx.HomeLogin, ctx.ChildTenantId);
        shadow.Should().NotBeNull();

        (await GetRolesAsync(ctx.ChildRepo, shadow!)).Should().BeEquivalentTo([ctx.OwnerRoleName]);

        // A blueprint installed later (e.g. MeshmakersAccounting) adds its role to TenantOwners —
        // what IdentityAssociationMigration.EnsureTenantOwnersGroupAsync does for new roles.
        var (accountingRoleId, accountingRoleName) = await CreateRoleAsync(ctx.ChildRepo, "AccountingManagement");
        await ctx.GroupStore.SetRoleIdsAsync(ctx.OwnersGroupId, [ctx.OwnerRoleId.ToString(), accountingRoleId.ToString()]);

        (await GetRolesAsync(ctx.ChildRepo, shadow!)).Should().BeEquivalentTo(
            [ctx.OwnerRoleName, accountingRoleName],
            "group roles of the mapping are resolved on every token, never snapshotted");

        // Nothing was materialised on the shadow user.
        (await CreateUserStore(ctx.ChildRepo).GetDirectRolesAsync(shadow!, TestContext.Current.CancellationToken))
            .Should().BeEmpty();
    }

    [Fact]
    public async Task MappingRemovedFromGroup_GroupRoleGone_ManuallyAssignedRoleKept()
    {
        var ctx = await ArrangeChildWithOwnersGroupAsync();
        var shadow = (await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(ctx.HomeLogin, ctx.ChildTenantId))!;

        var (_, manualRoleName) = await CreateRoleAsync(ctx.ChildRepo, "Manual");
        await CreateUserStore(ctx.ChildRepo).AddToRoleAsync(
            shadow, manualRoleName.ToUpperInvariant(), TestContext.Current.CancellationToken);

        (await GetRolesAsync(ctx.ChildRepo, shadow)).Should().BeEquivalentTo([ctx.OwnerRoleName, manualRoleName]);

        await ctx.GroupStore.RemoveMemberExternalUserAsync(ctx.OwnersGroupId, ctx.MappingId.ToString());

        (await GetRolesAsync(ctx.ChildRepo, shadow)).Should().BeEquivalentTo(
            [manualRoleName],
            "the group role goes with the membership; the manual direct role stays");

        // The shadow user's next login must not bring the group role back.
        await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(ctx.HomeLogin, ctx.ChildTenantId);
        (await GetRolesAsync(ctx.ChildRepo, shadow)).Should().BeEquivalentTo([manualRoleName]);
    }

    [Fact]
    public async Task MappedRoleIds_AreResolvedLive_AndRemovalTakesEffect()
    {
        var ctx = await ArrangeChildWithOwnersGroupAsync(mappingInOwnersGroup: false);
        var (mappedRoleId, mappedRoleName) = await CreateRoleAsync(ctx.ChildRepo, "Mapped");
        var mappingStore = new ExternalTenantUserMappingStore(new FixedTenantResolver(ctx.ChildRepo));
        var mapping = (await mappingStore.GetByIdAsync(ctx.MappingId))!;
        mapping.MappedRoleIds = new AttributeStringValueList([mappedRoleId.ToString()]);
        await mappingStore.StoreAsync(mapping);

        var shadow = (await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(ctx.HomeLogin, ctx.ChildTenantId))!;
        (await GetRolesAsync(ctx.ChildRepo, shadow)).Should().BeEquivalentTo([mappedRoleName]);

        mapping.MappedRoleIds = new AttributeStringValueList();
        await mappingStore.StoreAsync(mapping);

        (await GetRolesAsync(ctx.ChildRepo, shadow)).Should().BeEmpty(
            "a role removed from the mapping is not left behind on the user");
    }

    [Fact]
    public async Task LoginViaParentShadow_And_PasswordLogin_ShareOneShadowUser_WithHomeMappingRoles()
    {
        var ctx = await ArrangeChildWithOwnersGroupAsync();

        // Tenant switch / auto-login from an intermediate parent: the source is the parent's shadow
        // user of the same person. The admin mapping exists only for the home identity.
        // The intermediate tenant must be registered: the name chain is only unwound at real tenant ids.
        var intermediateTenantId = await CreateChildTenantAsync(NewId("intermediate"));
        var parentShadowLogin = new CrossTenantAuthResult
        {
            SourceTenantId = intermediateTenantId,
            SourceUserId = OctoObjectId.GenerateNewId().ToString(),
            SourceUserName = CrossTenantShadowUserName.Build(ctx.HomeLogin.SourceTenantId, ctx.HomeLogin.SourceUserName)
        };

        var viaParent = (await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(parentShadowLogin, ctx.ChildTenantId))!;
        viaParent.UserName.Should().Be($"xt_{intermediateTenantId}_xt_{ctx.HomeLogin.SourceTenantId}_{ctx.HomeLogin.SourceUserName}");
        (await GetRolesAsync(ctx.ChildRepo, viaParent)).Should().BeEquivalentTo(
            [ctx.OwnerRoleName],
            "the home identity's mapping applies to every tier of the shadow user's chain");

        // The password login unwinds to the home tenant — it must land on the same shadow user.
        var viaPassword = (await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(ctx.HomeLogin, ctx.ChildTenantId))!;
        viaPassword.RtId.Should().Be(viaParent.RtId);

        (await CountShadowUsersAsync(ctx.ChildRepo, ctx.HomeLogin.SourceUserName)).Should().Be(1);
        (await ctx.Provisioning.IsExplicitlyProvisionedAsync(parentShadowLogin)).Should().BeTrue();
    }

    [Fact]
    public async Task ForeignIdentityMapping_DoesNotGrantRoles()
    {
        // Privilege-escalation guard: another person's mapping (in the owners group) must not reach
        // this shadow user, even though both come from the same source tenant.
        var ctx = await ArrangeChildWithOwnersGroupAsync(mappingInOwnersGroup: false);
        var mappingStore = new ExternalTenantUserMappingStore(new FixedTenantResolver(ctx.ChildRepo));
        var foreignMapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = ctx.HomeLogin.SourceTenantId,
            SourceUserId = OctoObjectId.GenerateNewId().ToString(),
            SourceUserName = $"{ctx.HomeLogin.SourceUserName}-other"
        };
        await mappingStore.StoreAsync(foreignMapping);
        await ctx.GroupStore.AddMemberExternalUserAsync(ctx.OwnersGroupId, foreignMapping.RtId.ToString());

        var shadow = (await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(ctx.HomeLogin, ctx.ChildTenantId))!;

        (await GetRolesAsync(ctx.ChildRepo, shadow)).Should().BeEmpty();
    }

    [Fact]
    public async Task UnderscoreTenantUser_NamedLikeANestedChain_DoesNotGetForeignMappingRoles()
    {
        // AB#5708 review: tenant ids may contain '_'. An ordinary user "{home}_{gerald}" of tenant
        // "{evil}_xt" gets the shadow name xt_{evil}_xt_{home}_{gerald}, which a naive split unwinds to
        // gerald@home — whose mapping sits in the owners group. It must grant nothing.
        var ctx = await ArrangeChildWithOwnersGroupAsync();
        var evilTenantId = await CreateChildTenantAsync($"{NewId("evil")}_xt");
        var attackerLogin = new CrossTenantAuthResult
        {
            SourceTenantId = evilTenantId,
            SourceUserId = OctoObjectId.GenerateNewId().ToString(),
            SourceUserName = $"{ctx.HomeLogin.SourceTenantId}_{ctx.HomeLogin.SourceUserName}"
        };

        // Not explicitly provisioned (self-registration gate), before JIT creates the attacker's own mapping.
        (await ctx.Provisioning.IsExplicitlyProvisionedAsync(attackerLogin)).Should().BeFalse();

        var attackerShadow = (await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(attackerLogin, ctx.ChildTenantId))!;

        attackerShadow.UserName.Should().Be(
            $"xt_{evilTenantId}_{ctx.HomeLogin.SourceTenantId}_{ctx.HomeLogin.SourceUserName}",
            "the attacker's shadow name ends exactly like the victim's nested chain");
        (await GetRolesAsync(ctx.ChildRepo, attackerShadow)).Should().BeEmpty();

        // ...and the victim's first login neither lands on the attacker's shadow user.
        var victimShadow = (await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(ctx.HomeLogin, ctx.ChildTenantId))!;
        victimShadow.RtId.Should().NotBe(attackerShadow.RtId);
        (await GetRolesAsync(ctx.ChildRepo, victimShadow)).Should().BeEquivalentTo([ctx.OwnerRoleName]);
    }

    [Fact]
    public async Task UnderscoreTenantUser_GetsOwnMappingRoles()
    {
        var ctx = await ArrangeChildWithOwnersGroupAsync(mappingInOwnersGroup: false);
        var sourceTenantId = await CreateChildTenantAsync($"{NewId("src")}_tenant");
        var login = new CrossTenantAuthResult
        {
            SourceTenantId = sourceTenantId,
            SourceUserId = OctoObjectId.GenerateNewId().ToString(),
            SourceUserName = NewId("user")
        };
        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = login.SourceTenantId,
            SourceUserId = login.SourceUserId,
            SourceUserName = login.SourceUserName
        };
        await new ExternalTenantUserMappingStore(new FixedTenantResolver(ctx.ChildRepo)).StoreAsync(mapping);
        await ctx.GroupStore.AddMemberExternalUserAsync(ctx.OwnersGroupId, mapping.RtId.ToString());

        var shadow = (await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(login, ctx.ChildTenantId))!;

        (await GetRolesAsync(ctx.ChildRepo, shadow)).Should().BeEquivalentTo([ctx.OwnerRoleName]);
    }

    // ---------- arrangement ----------

    private sealed record ChildContext(
        string ChildTenantId,
        ITenantRepository ChildRepo,
        CrossTenantUserProvisioningService Provisioning,
        GroupStore GroupStore,
        OctoObjectId OwnersGroupId,
        OctoObjectId OwnerRoleId,
        string OwnerRoleName,
        OctoObjectId MappingId,
        CrossTenantAuthResult HomeLogin);

    /// <summary>
    ///     Child tenant with an owners group holding one role and an admin-created mapping for a home
    ///     user — the shape <c>AdminProvisioningController.ProvisionCurrentUser</c> produces.
    /// </summary>
    private async Task<ChildContext> ArrangeChildWithOwnersGroupAsync(bool mappingInOwnersGroup = true)
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(systemContext.TenantId);

        var homeTenantId = systemContext.TenantId;
        var homeUserName = NewId("gerald");
        var homeUserId = OctoObjectId.GenerateNewId().ToString();

        var childTenantId = await CreateChildTenantAsync(NewId("child"));
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var resolver = new FixedTenantResolver(childRepo);
        var groupStore = new GroupStore(resolver);

        var (ownerRoleId, ownerRoleName) = await CreateRoleAsync(childRepo, "Owner");
        var ownersGroup = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(),
            GroupName = NewId("Owners"),
            NormalizedGroupName = NewId("OWNERS").ToUpperInvariant()
        };
        await groupStore.StoreAsync(ownersGroup);
        await groupStore.SetRoleIdsAsync(ownersGroup.RtId, [ownerRoleId.ToString()]);

        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = homeTenantId,
            SourceUserId = homeUserId,
            SourceUserName = homeUserName
        };
        await new ExternalTenantUserMappingStore(resolver).StoreAsync(mapping);
        if (mappingInOwnersGroup)
        {
            await groupStore.AddMemberExternalUserAsync(ownersGroup.RtId, mapping.RtId.ToString());
        }

        return new ChildContext(
            childTenantId, childRepo, CreateProvisioningService(childRepo), groupStore,
            ownersGroup.RtId, ownerRoleId, ownerRoleName, mapping.RtId,
            new CrossTenantAuthResult
            {
                SourceTenantId = homeTenantId,
                SourceUserId = homeUserId,
                SourceUserName = homeUserName,
                Email = $"{homeUserName}@example.com"
            });
    }

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..20];

    private async Task<string> CreateChildTenantAsync(string tenantId)
    {
        var systemContext = _fixture.GetSystemContext();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
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
        }

        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantId);
        return tenantId;
    }

    private static async Task<(OctoObjectId Id, string Name)> CreateRoleAsync(ITenantRepository repo, string prefix)
    {
        var name = NewId(prefix);
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = rtId,
            Name = name,
            NormalizedName = name.ToUpperInvariant()
        });
        await session.CommitTransactionAsync();
        return (rtId, name);
    }

    private static async Task<int> CountShadowUsersAsync(ITenantRepository repo, string homeUserName)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var query = RtEntityQueryOptions.Create();
        query.FieldEndsWith(nameof(RtUser.NormalizedUserName), $"_{homeUserName}".ToUpperInvariant());
        var result = await repo.GetRtEntitiesByTypeAsync<RtUser>(session, query);
        await session.CommitTransactionAsync();
        return result.Items.Count();
    }

    private OctoUserStore CreateUserStore(ITenantRepository repo)
    {
        var resolver = new FixedTenantResolver(repo);
        return new OctoUserStore(
            resolver,
            new GroupRoleResolver(new GroupStore(resolver), new ExternalTenantUserMappingStore(resolver), new CrossTenantShadowUserChainResolver(_fixture.GetSystemContext())),
            null);
    }

    private async Task<IList<string>> GetRolesAsync(ITenantRepository repo, RtUser user)
        => await CreateUserStore(repo).GetRolesAsync(user, TestContext.Current.CancellationToken);

    private CrossTenantUserProvisioningService CreateProvisioningService(ITenantRepository childRepo)
    {
        var resolver = new FixedTenantResolver(childRepo);
        var userManager = new UserManager<RtUser>(
            CreateUserStore(childRepo),
            Microsoft.Extensions.Options.Options.Create(new IdentityOptions()),
            new PasswordHasher<RtUser>(),
            Array.Empty<IUserValidator<RtUser>>(),
            Array.Empty<IPasswordValidator<RtUser>>(),
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            services: null!,
            NullLogger<UserManager<RtUser>>.Instance);
        return new CrossTenantUserProvisioningService(
            userManager,
            new ExternalTenantUserMappingStore(resolver),
            resolver,
            new CrossTenantShadowUserChainResolver(_fixture.GetSystemContext()),
            NullLogger<CrossTenantUserProvisioningService>.Instance);
    }
}
