using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using IdentityServices.IntegrationTests.Persistence;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#8343: an administrator of T grants a user of a sibling tenant S (no registry ancestor of T) with chosen T groups
///     through <c>POST ExternalTenantUserMappings</c>; the user's first token exchange from S into T creates one
///     <c>xt_</c> shadow user with exactly the roles of those groups. Real HTTP route for the create, the real
///     <see cref="TenantExchangeProcessor" /> for the exchange.
/// </summary>
/// <remarks>
///     Registry: system → S and system → T (siblings). S permits T through the arranged test policy, or through the
///     production allow-list (<c>PUT CrossTenantGrantPermissions</c> in S) where a test withdraws the permission. Every test
///     creates its own tenants, users, roles and groups.
/// </remarks>
public class SiblingTenantGrantTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    private const string UserManagement = "UserManagement";

    [Fact]
    public async Task SiblingUserGrantedWithAGroup_GetsExactlyTheGroupsRolesOnTheFirstExchange_AndOneShadowUser()
    {
        var (source, target) = await SiblingsAsync(permitted: true);
        var bob = await InsertUserAsync(source, "bob");
        await GiveSourceRoleAsync(source, bob.Id, "srcadmin");
        var r1 = await InsertRoleAsync(target, "r1");
        var r2 = await InsertRoleAsync(target, "r2");
        var other = await InsertRoleAsync(target, "r3");
        var group = await InsertGroupAsync(target, "grp", r1.Id, r2.Id);
        await InsertGroupAsync(target, "oth", other.Id);
        var providersBefore = await CountLoginProvidersAsync(target);

        var create = await CreateAsync(target, source, bob, groupIds: [group.Id.ToString()]);

        create.StatusCode.Should().Be(HttpStatusCode.Created,
            await create.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var dto = (await create.Content.ReadFromJsonAsync<ExternalTenantUserMappingDto>(
            TestContext.Current.CancellationToken))!;
        dto.GroupNames.Should().Equal(group.Name);
        dto.SourceTenantId.Should().Be(source);
        dto.SourceUserName.Should().Be(bob.UserName);

        var (outcome, roles) = await ExchangeAsync(target, source, bob.Id.ToString());

        outcome.Error.Should().BeNull(outcome.ErrorDescription);
        outcome.TargetTenantId.Should().Be(target, "the issued token is stamped tenant_id=T");
        roles.Should().BeEquivalentTo([r1.Name, r2.Name], "exactly the group's roles: nothing from S, no other T role");
        (await ShadowUsersAsync(target)).Should().ContainSingle()
            .Which.UserName.Should().Be(CrossTenantShadowUserName.Build(source, bob.UserName));
        (await CountLoginProvidersAsync(target)).Should().Be(providersBefore,
            "a sibling grant creates no RtOctoTenantIdentityProvider (T offers no 'Login via S')");
    }

    [Fact]
    public async Task CreateFromANonPermittedSibling_Is403_AndStoresNothing()
    {
        var (source, target) = await SiblingsAsync(permitted: false);
        var bob = await InsertUserAsync(source, "bob");
        var group = await InsertGroupAsync(target, "grp", (await InsertRoleAsync(target, "r1")).Id);

        var create = await CreateAsync(target, source, bob, groupIds: [group.Id.ToString()]);

        await AssertProblemAsync(create, HttpStatusCode.Forbidden, CrossTenantGrantProblemCodes.SourceTenantNotPermitted);
        (await MappingsAsync(target)).Should().BeEmpty();
    }

    [Fact]
    public async Task CreateForAUserAbsentOrBlockedInTheSource_Is403_WithTheSameBody_AsAnUnknownTenant()
    {
        var (source, target) = await SiblingsAsync(permitted: true);
        var locked = await InsertUserAsync(source, "lock", lockedOut: true);
        var shadow = await InsertUserAsync(source, "xt_other_x");
        var absent = new TestUser(OctoObjectId.GenerateNewId(), "ghost", "ghost@user.example");

        var bodies = new List<string>();
        foreach (var (tenant, user) in new[]
                 {
                     (source, absent), (source, locked), (source, shadow), ($"absent{Guid.NewGuid():N}"[..20], absent)
                 })
        {
            var response = await CreateAsync(target, tenant, user);
            await AssertProblemAsync(response, HttpStatusCode.Forbidden,
                CrossTenantGrantProblemCodes.SourceTenantNotPermitted);
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        bodies.Distinct().Should().ContainSingle("one answer for every refusal reveals nothing about S");
        (await MappingsAsync(target)).Should().BeEmpty();
    }

    [Fact]
    public async Task ExchangeAfterTheSourceWithdrawsThePermission_IsAccessDenied_AndCreatesNoShadowUser()
    {
        var (source, target) = await SiblingsAsync(permitted: false);
        var bob = await InsertUserAsync(source, "bob");
        var group = await InsertGroupAsync(target, "grp", (await InsertRoleAsync(target, "r1")).Id);

        await SetAllowListAsync(source, [target]);
        (await CreateAsync(target, source, bob, groupIds: [group.Id.ToString()])).StatusCode.Should()
            .Be(HttpStatusCode.Created);
        await SetAllowListAsync(source, []);

        var (outcome, _) = await ExchangeAsync(target, source, bob.Id.ToString());

        outcome.Error.Should().Be(Errors.AccessDenied);
        outcome.ErrorDescription.Should().StartWith(TenantExchangeProcessor.GrantNotPermittedMarker);
        (await ShadowUsersAsync(target)).Should().BeEmpty("a refused exchange leaves T untouched (AB#8304)");

        // The permission back: the same grant works again at the next exchange.
        await SetAllowListAsync(source, [target]);
        (await ExchangeAsync(target, source, bob.Id.ToString())).Outcome.Error.Should().BeNull();
    }

    [Fact]
    public async Task ExchangeFromAShadowUserOfTheGrantedUser_FollowsTheHomeGrant_AndIsAccessDeniedOnceWithdrawn()
    {
        // The caller holds a token of tenant A as xt_{S}_{bob} (bob switched into A earlier). The grant in T names the
        // home identity (S, bob); the exchange judges that candidate too (AB#4966), also for the withdrawn case.
        var (source, target) = await SiblingsAsync(permitted: false);
        var other = await CreateTenantAsync("sga");
        var bob = await InsertUserAsync(source, "bob");
        var shadowInOther = await InsertUserAsync(other, CrossTenantShadowUserName.Build(source, bob.UserName),
            exactName: true);
        var group = await InsertGroupAsync(target, "grp", (await InsertRoleAsync(target, "r1")).Id);

        await SetAllowListAsync(source, [target]);
        (await CreateAsync(target, source, bob, groupIds: [group.Id.ToString()])).StatusCode.Should()
            .Be(HttpStatusCode.Created);

        (await ExchangeAsync(target, other, shadowInOther.Id.ToString())).Outcome.Error.Should()
            .BeNull("the home identity holds a permitted grant");

        await SetAllowListAsync(source, []);
        var (refused, _) = await ExchangeAsync(target, other, shadowInOther.Id.ToString());

        refused.Error.Should().Be(Errors.AccessDenied);
        refused.ErrorDescription.Should().StartWith(TenantExchangeProcessor.GrantNotPermittedMarker);
    }

    [Fact]
    public async Task ExchangeWithoutAGrantInTheTarget_IsRefused_AndLeavesTheTargetUnchanged()
    {
        var (source, target) = await SiblingsAsync(permitted: true);
        var bob = await InsertUserAsync(source, "bob");

        var (outcome, _) = await ExchangeAsync(target, source, bob.Id.ToString());

        outcome.Error.Should().Be(Errors.UnauthorizedClient, "a sibling without a grant is refused as before");
        (await ShadowUsersAsync(target)).Should().BeEmpty();
        (await MappingsAsync(target)).Should().BeEmpty();
    }

    [Fact]
    public async Task UnknownGroupId_Is400_ListsTheUnknownIds_AndStoresNothing()
    {
        var (source, target) = await SiblingsAsync(permitted: true);
        var bob = await InsertUserAsync(source, "bob");
        var group = await InsertGroupAsync(target, "grp", (await InsertRoleAsync(target, "r1")).Id);
        var groupOfS = await InsertGroupAsync(source, "sgr");
        var missing = OctoObjectId.GenerateNewId().ToString();

        var create = await CreateAsync(target, source, bob,
            groupIds: [group.Id.ToString(), missing, groupOfS.Id.ToString(), "not-an-id"]);

        var body = await AssertProblemAsync(create, HttpStatusCode.BadRequest, CrossTenantGrantProblemCodes.UnknownGroup);
        body["unknownGroupIds"]!.AsArray().Select(n => n!.GetValue<string>()).Should()
            .BeEquivalentTo([missing, groupOfS.Id.ToString(), "not-an-id"], "a group of S is no group of T");
        (await MappingsAsync(target)).Should().BeEmpty("nothing is stored when one group id is unknown");
    }

    [Fact]
    public async Task DuplicateGrant_Is409_AsBefore()
    {
        var (source, target) = await SiblingsAsync(permitted: true);
        var bob = await InsertUserAsync(source, "bob");
        var group = await InsertGroupAsync(target, "grp", (await InsertRoleAsync(target, "r1")).Id);

        (await CreateAsync(target, source, bob, groupIds: [group.Id.ToString()])).StatusCode.Should()
            .Be(HttpStatusCode.Created);
        var second = await CreateAsync(target, source, bob, groupIds: [group.Id.ToString()]);

        await AssertProblemAsync(second, HttpStatusCode.Conflict,
            ExternalTenantUserMappingProblems.AlreadyExistsCode);
        (await MappingsAsync(target)).Should().ContainSingle();
    }

    [Fact]
    public async Task GroupCarryingABuiltInRoleTheCallerDoesNotHold_IsRefusedByTheRoleChangeGuard()
    {
        // AB#7927 applies to the groups' roles as to direct roles: a caller with UserManagement only may not hand out
        // TenantManagement through a group either.
        var (source, target) = await SiblingsAsync(permitted: true);
        var bob = await InsertUserAsync(source, "bob");
        var tenantManagement = await FindRoleByNameAsync(target, "TenantManagement");
        var group = await InsertGroupAsync(target, "adm", tenantManagement);

        var create = await CreateAsync(target, source, bob, groupIds: [group.Id.ToString()]);

        create.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await create.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Should()
            .Contain("TenantManagement");
        (await MappingsAsync(target)).Should().BeEmpty();
    }

    // ------------------------------------------------------------------ revocation (AB#8344)

    [Fact]
    public async Task DeletingTheGrant_RefusesTheNextExchangeWithAccessDenied_AndLeavesNoEdgeOfTheMapping()
    {
        var g = await GrantedAndSwitchedInAsync();

        var delete = await AdminClient().DeleteAsync($"/{g.Target}/v1/ExternalTenantUserMappings/{g.Mapping.RtId}",
            TestContext.Current.CancellationToken);
        delete.StatusCode.Should().Be(HttpStatusCode.OK);

        await AssertRevokedAsync(g, "the grant was deleted");
        await AssertNoEdgeOfAsync(g.Target, g.Mapping, g.Group);
    }

    [Fact]
    public async Task DeletingTheGrantThroughAdminProvisioning_RefusesTheNextExchange_AndLeavesNoEdgeOfTheMapping()
    {
        var g = await GrantedAndSwitchedInAsync();

        var delete = await AdminClient().DeleteAsync(
            $"/{NormalizedSystemTenantId}/v1/AdminProvisioning/{g.Target}/{g.Mapping.RtId}",
            TestContext.Current.CancellationToken);
        delete.StatusCode.Should().Be(HttpStatusCode.OK);

        await AssertRevokedAsync(g, "the grant was deleted through the AdminProvisioning route");
        await AssertNoEdgeOfAsync(g.Target, g.Mapping, g.Group);
    }

    [Fact]
    public async Task RemovingTheGrantsOnlyGroupMembership_RefusesTheNextExchange()
    {
        var g = await GrantedAndSwitchedInAsync();
        await GiveDirectRoleToShadowUserAsync(g);

        await GroupsOf(g.Target).RemoveMemberExternalUserAsync(g.Group.Id, g.Mapping.RtId.ToString());

        await AssertRevokedAsync(g, "the mapping stays, but is member of no group any more");
        (await MappingsAsync(g.Target)).Should().ContainSingle("removing the membership does not delete the grant");
    }

    [Fact]
    public async Task EmptyingTheGroupsRoles_RefusesTheNextExchange()
    {
        var g = await GrantedAndSwitchedInAsync();
        await GiveDirectRoleToShadowUserAsync(g);

        await GroupsOf(g.Target).SetRoleIdsAsync(g.Group.Id, []);

        await AssertRevokedAsync(g, "the mapping's only group grants no role any more");
    }

    [Fact]
    public async Task RemovingOneOfTwoGroups_KeepsTheRolesOfTheOtherGroup()
    {
        var g = await GrantedAndSwitchedInAsync();
        var r3 = await InsertRoleAsync(g.Target, "r3");
        var second = await InsertGroupAsync(g.Target, "gr2", r3.Id);
        await GroupsOf(g.Target).AddMemberExternalUserAsync(second.Id, g.Mapping.RtId.ToString());

        await GroupsOf(g.Target).RemoveMemberExternalUserAsync(g.Group.Id, g.Mapping.RtId.ToString());
        var (outcome, roles) = await ExchangeAsync(g.Target, g.Source, g.Bob.Id.ToString());

        outcome.Error.Should().BeNull("another group of the grant still grants a role: {0}", outcome.ErrorDescription);
        roles.Should().BeEquivalentTo([r3.Name], "only the remaining group's roles");
    }

    [Fact]
    public async Task WithdrawingThePermission_AfterTheUserSwitchedIn_RefusesTheNextExchangeWithGrantNotPermitted()
    {
        var (source, target) = await SiblingsAsync(permitted: false);
        await SetAllowListAsync(source, [target]);
        var g = await GrantedAndSwitchedInAsync(source, target);

        await SetAllowListAsync(source, []);
        var (outcome, _) = await ExchangeAsync(g.Target, g.Source, g.Bob.Id.ToString());

        outcome.Error.Should().Be(Errors.AccessDenied);
        outcome.ErrorDescription.Should().StartWith(TenantExchangeProcessor.GrantNotPermittedMarker);
        outcome.ShadowUser.Should().BeNull();
        (await MappingsAsync(g.Target)).Should().ContainSingle("the grant stays; S's permission decides");
    }

    [Fact]
    public async Task ARoleGivenDirectlyToTheShadowUser_DoesNotOutliveTheGrant()
    {
        // The mapping is the grant of a sibling user: a role a T administrator attached to the xt_ user directly
        // counts only while the mapping itself grants a role (concept §8). It is neither removed nor honoured after.
        var g = await GrantedAndSwitchedInAsync();
        var direct = await InsertRoleAsync(g.Target, "dir");
        await GiveDirectRoleAsync(g.Target, g.ShadowUser, direct.Name);
        (await ExchangeAsync(g.Target, g.Source, g.Bob.Id.ToString())).Roles.Should()
            .BeEquivalentTo([g.R1.Name, g.R2.Name, direct.Name], "while the grant holds, the direct role adds to it");

        await GroupsOf(g.Target).RemoveMemberExternalUserAsync(g.Group.Id, g.Mapping.RtId.ToString());
        await AssertRevokedAsync(g, "the mapping grants nothing; the shadow user's direct role does not keep bob in T");

        (await AdminClient().DeleteAsync($"/{g.Target}/v1/ExternalTenantUserMappings/{g.Mapping.RtId}",
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.OK);
        await AssertRevokedAsync(g, "the grant is gone; the shadow user's direct role does not keep bob in T");
    }

    [Fact]
    public async Task AMappedRoleThatNoLongerExists_GrantsNothing()
    {
        // MappedRoleIds is a free string list, not an association: deleting the role leaves its id behind. A dead id
        // grants no role in T (as in OctoUserStore.GetRolesAsync), so it must not keep the grant alive either.
        var g = await GrantedAndSwitchedInAsync();
        await GiveDirectRoleToShadowUserAsync(g);
        var mapped = await InsertRoleAsync(g.Target, "map");
        await SetMappedRoleIdsAsync(g.Target, g.Mapping.RtId, [mapped.Id.ToString()]);
        await GroupsOf(g.Target).RemoveMemberExternalUserAsync(g.Group.Id, g.Mapping.RtId.ToString());
        var (admitted, _) = await ExchangeAsync(g.Target, g.Source, g.Bob.Id.ToString());
        admitted.Error.Should().BeNull("the mapping's own role grants access: {0}", admitted.ErrorDescription);

        await DeleteRoleAsync(g.Target, mapped.Id);

        await AssertRevokedAsync(g, "the mapping names only a role that no longer exists in T");
        (await MappingsAsync(g.Target)).Should().ContainSingle().Which.MappedRoleIds.Should()
            .Contain(mapped.Id.ToString(), "the dead id stays in the list; only the gate ignores it");
    }

    [Fact]
    public async Task RegrantingAfterDeletion_IsACreate_AndYieldsOnlyTheNewGroupsRoles()
    {
        var g = await GrantedAndSwitchedInAsync();
        (await AdminClient().DeleteAsync($"/{g.Target}/v1/ExternalTenantUserMappings/{g.Mapping.RtId}",
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.OK);
        await AssertRevokedAsync(g, "the grant was deleted");

        var r3 = await InsertRoleAsync(g.Target, "r3");
        var newGroup = await InsertGroupAsync(g.Target, "new", r3.Id);
        var create = await CreateAsync(g.Target, g.Source, g.Bob, groupIds: [newGroup.Id.ToString()]);

        create.StatusCode.Should().Be(HttpStatusCode.Created, "no 409 from the deleted mapping: {0}",
            await create.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var (outcome, roles) = await ExchangeAsync(g.Target, g.Source, g.Bob.Id.ToString());
        outcome.Error.Should().BeNull(outcome.ErrorDescription);
        outcome.ShadowUser!.RtId.Should().Be(g.ShadowUser.RtId, "the existing shadow user is used again");
        roles.Should().BeEquivalentTo([r3.Name], "only the new group's roles, nothing of the removed grant");
    }

    // ------------------------------------------------------------------ helpers

    private sealed record TestUser(OctoObjectId Id, string UserName, string Email);

    private sealed record Named(OctoObjectId Id, string Name);

    private sealed record Granted(
        string Source,
        string Target,
        TestUser Bob,
        Named R1,
        Named R2,
        Named Group,
        RtExternalTenantUserMapping Mapping,
        RtUser ShadowUser);

    /// <summary>AB#8344 arrangement: bob of S, granted in T with one group (roles R1, R2), switched into T once.</summary>
    private async Task<Granted> GrantedAndSwitchedInAsync(string? source = null, string? target = null)
    {
        if (source == null || target == null)
        {
            (source, target) = await SiblingsAsync(permitted: true);
        }

        var bob = await InsertUserAsync(source, "bob");
        var r1 = await InsertRoleAsync(target, "r1");
        var r2 = await InsertRoleAsync(target, "r2");
        var group = await InsertGroupAsync(target, "grp", r1.Id, r2.Id);
        (await CreateAsync(target, source, bob, groupIds: [group.Id.ToString()])).StatusCode.Should()
            .Be(HttpStatusCode.Created);

        var (outcome, roles) = await ExchangeAsync(target, source, bob.Id.ToString());
        outcome.Error.Should().BeNull(outcome.ErrorDescription);
        roles.Should().BeEquivalentTo([r1.Name, r2.Name]);

        var mapping = (await MappingsAsync(target)).Should().ContainSingle().Subject;
        return new Granted(source, target, bob, r1, r2, group, mapping, outcome.ShadowUser!);
    }

    /// <summary>
    ///     The next exchange is refused with <c>access_denied</c> (<c>tenant_not_provisioned</c>), issues nothing and creates
    ///     nothing; the left-over shadow user stays for the cleanup of AB#8305.
    /// </summary>
    private async Task AssertRevokedAsync(Granted g, string because)
    {
        var (outcome, _) = await ExchangeAsync(g.Target, g.Source, g.Bob.Id.ToString());

        outcome.Error.Should().Be(Errors.AccessDenied, because);
        outcome.ErrorDescription.Should().StartWith(TenantExchangeProcessor.NotProvisionedMarker, because);
        outcome.ErrorDescription.Should().Contain("must grant the user access again", "a sibling user needs a new grant")
            .And.NotContain("ProvisionCurrentUser", "that route serves ancestor sources only");
        outcome.ShadowUser.Should().BeNull(because);
        (await ShadowUsersAsync(g.Target)).Should().ContainSingle(because)
            .Which.RtId.Should().Be(g.ShadowUser.RtId, "this story does not delete the shadow user (AB#8305 does)");
    }

    /// <summary>No association of any role (GroupMember, AssignedRole, …) still points at or from the deleted mapping.</summary>
    private async Task AssertNoEdgeOfAsync(string tenantId, RtExternalTenantUserMapping mapping, Named group)
    {
        (await MappingsAsync(tenantId)).Should().BeEmpty();
        var repo = await RepositoryOfAsync(tenantId);
        using (var session = await repo.GetSessionAsync())
        {
            session.StartTransaction();
            var edges = await repo.GetRtAssociationsAsync(session, mapping.ToRtEntityId(),
                RtAssociationExtendedQueryOptions.Create(GraphDirections.Any));
            await session.CommitTransactionAsync();
            edges.Items.Should().BeEmpty("the delete takes every edge of the mapping with it");
        }

        (await GroupsOf(tenantId).GetAllMemberSubjectIdsAsync(group.Id)).Should()
            .NotContain(mapping.RtId.ToString(), "the group lists no member that does not exist");
    }

    private GroupStore GroupsOf(string tenantId)
        => new(new FixedTenantResolver(RepositoryOfAsync(tenantId).GetAwaiter().GetResult()));

    private async Task GiveDirectRoleAsync(string tenantId, RtUser user, string roleName)
    {
        var repo = await RepositoryOfAsync(tenantId);
        var resolver = new FixedTenantResolver(repo);
        var chainResolver = new CrossTenantShadowUserChainResolver(Factory.Services.GetRequiredService<ISystemContext>());
        var userStore = new OctoUserStore(resolver,
            new GroupRoleResolver(new GroupStore(resolver), new ExternalTenantUserMappingStore(resolver), chainResolver),
            null);
        await userStore.AddToRoleAsync(user, roleName.ToUpperInvariant(), TestContext.Current.CancellationToken);
    }

    /// <summary>
    ///     A role a T administrator attached to bob's <c>xt_</c> user directly. It keeps the user's role set non-empty, so
    ///     a refusal afterwards comes from the sibling gate (AB#8344) and not from the no-role check of the exchange.
    /// </summary>
    private async Task GiveDirectRoleToShadowUserAsync(Granted g)
    {
        var direct = await InsertRoleAsync(g.Target, "dir");
        await GiveDirectRoleAsync(g.Target, g.ShadowUser, direct.Name);
    }

    private async Task SetMappedRoleIdsAsync(string tenantId, OctoObjectId mappingId, List<string> roleIds)
    {
        var repo = await RepositoryOfAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var mapping = await repo.GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, mappingId);
        mapping!.MappedRoleIds = new AttributeStringValueList(roleIds);
        await repo.ReplaceOneRtEntityByIdAsync(session, mapping.RtId, mapping);
        await session.CommitTransactionAsync();
    }

    /// <summary>Removes the role entity only — no store, so nothing strips its id from a mapping's <c>MappedRoleIds</c>.</summary>
    private async Task DeleteRoleAsync(string tenantId, OctoObjectId roleId)
    {
        var repo = await RepositoryOfAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.DeleteOneRtEntityByRtIdAsync<RtRole>(session, roleId, DeleteOptions.Erase);
        await session.CommitTransactionAsync();
    }

    private HttpClient AdminClient()
    {
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, OctoObjectId.GenerateNewId().ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, $"admin{Guid.NewGuid():N}"[..20]);
        client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, UserManagement);
        return client;
    }

    private Task<HttpResponseMessage> CreateAsync(string target, string source, TestUser user,
        List<string>? groupIds = null)
        => AdminClient().PostAsJsonAsync($"/{target}/v1/ExternalTenantUserMappings",
            new CreateExternalTenantUserMappingDto
            {
                SourceTenantId = source, SourceUserId = user.Id.ToString(), SourceUserName = user.UserName,
                GroupIds = groupIds
            }, TestContext.Current.CancellationToken);

    private static async Task<JsonNode> AssertProblemAsync(HttpResponseMessage response, HttpStatusCode status,
        string code)
    {
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        response.StatusCode.Should().Be(status, raw);
        var body = JsonNode.Parse(raw)!;
        body["code"]!.GetValue<string>().Should().Be(code);
        return body;
    }

    private async Task SetAllowListAsync(string source, List<string> targets)
    {
        var client = AdminClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, "TenantManagement");
        (await client.PutAsJsonAsync($"/{source}/v1/CrossTenantGrantPermissions",
                new CrossTenantGrantPermissionsDto { TargetTenantIds = targets }, TestContext.Current.CancellationToken))
            .StatusCode.Should().Be(HttpStatusCode.OK);
    }

    /// <summary>The real exchange (after subject-token validation) with T wired into the request; the roles of the result.</summary>
    private async Task<(TenantExchangeProcessor.ExchangeOutcome Outcome, IList<string> Roles)> ExchangeAsync(
        string target, string source, string sourceUserId)
    {
        var targetRepo = await RepositoryOfAsync(target);
        var accessor = Factory.Services.GetRequiredService<IHttpContextAccessor>();
        using var scope = Factory.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Items[InfrastructureCommon.TenantIdName] = target;
        context.Items[InfrastructureCommon.TenantRepositoryName] = targetRepo;
        accessor.HttpContext = context;
        try
        {
            var outcome = await scope.ServiceProvider.GetRequiredService<TenantExchangeProcessor>()
                .ExchangeAsync(source, sourceUserId, target, subjectHasSecondFactor: false);
            IList<string> roles = outcome.ShadowUser == null ? [] : await RolesInAsync(targetRepo, outcome.ShadowUser);
            return (outcome, roles);
        }
        finally
        {
            accessor.HttpContext = null;
        }
    }

    /// <summary>The roles the token of <paramref name="user" /> carries: the store that stamps the role claims.</summary>
    private Task<IList<string>> RolesInAsync(ITenantRepository repo, RtUser user)
    {
        var resolver = new FixedTenantResolver(repo);
        var chainResolver = new CrossTenantShadowUserChainResolver(Factory.Services.GetRequiredService<ISystemContext>());
        var userStore = new OctoUserStore(resolver,
            new GroupRoleResolver(new GroupStore(resolver), new ExternalTenantUserMappingStore(resolver), chainResolver),
            null);
        return userStore.GetRolesAsync(user, TestContext.Current.CancellationToken);
    }

    private async Task<(string Source, string Target)> SiblingsAsync(bool permitted)
    {
        var source = await CreateTenantAsync("sgs");
        var target = await CreateTenantAsync("sgt");
        if (permitted)
        {
            Factory.SourceTenantGrantPolicy.Permit(source, target);
        }

        return (source, target);
    }

    private async Task<string> CreateTenantAsync(string prefix)
    {
        var tenantId = $"{prefix}{Guid.NewGuid():N}"[..20];
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IDefaultConfigurationCreatorService>().SetupAsync(tenantId);
        }

        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(tenantId) != null)
            {
                return tenantId;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException($"Tenant '{tenantId}' did not appear in the tenant registry");
    }

    private async Task<ITenantRepository> RepositoryOfAsync(string tenantId)
        => (await Factory.Services.GetRequiredService<ISystemContext>().TryFindTenantRepositoryAsync(tenantId))!;

    private async Task<TestUser> InsertUserAsync(string tenantId, string prefix, bool lockedOut = false,
        bool exactName = false)
    {
        var userName = exactName
            ? prefix
            : prefix.StartsWith("xt_", StringComparison.Ordinal)
                ? $"{prefix}{Guid.NewGuid():N}"[..24]
                : $"{prefix}{Guid.NewGuid():N}"[..20];
        var email = $"{userName}@user.example";
        var user = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            EmailConfirmed = true,
            FirstName = "Sibling",
            LastName = "User",
            SecurityStamp = Guid.NewGuid().ToString(),
            LockoutEnabled = lockedOut,
            LockoutEnd = lockedOut ? DateTime.UtcNow.AddHours(1) : null
        };
        await InsertAsync(tenantId, user);
        return new TestUser(user.RtId, userName, email);
    }

    private async Task GiveSourceRoleAsync(string tenantId, OctoObjectId userId, string prefix)
    {
        var role = await InsertRoleAsync(tenantId, prefix);
        var repo = await RepositoryOfAsync(tenantId);
        var resolver = new FixedTenantResolver(repo);
        var chainResolver = new CrossTenantShadowUserChainResolver(Factory.Services.GetRequiredService<ISystemContext>());
        var userStore = new OctoUserStore(resolver,
            new GroupRoleResolver(new GroupStore(resolver), new ExternalTenantUserMappingStore(resolver), chainResolver),
            null);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var user = await repo.GetRtEntityByRtIdAsync<RtUser>(session, userId);
        await session.CommitTransactionAsync();
        await userStore.AddToRoleAsync(user!, role.Name.ToUpperInvariant(), TestContext.Current.CancellationToken);
        (await userStore.GetRolesAsync(user!, TestContext.Current.CancellationToken)).Should().Contain(role.Name);
    }

    private async Task<Named> InsertRoleAsync(string tenantId, string prefix)
    {
        var name = $"{prefix}{Guid.NewGuid():N}"[..16];
        var role = new RtRole { RtId = OctoObjectId.GenerateNewId(), Name = name, NormalizedName = name.ToUpperInvariant() };
        await InsertAsync(tenantId, role);
        return new Named(role.RtId, name);
    }

    private async Task<OctoObjectId> FindRoleByNameAsync(string tenantId, string name)
    {
        var repo = await RepositoryOfAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var roles = await repo.GetRtEntitiesByTypeAsync<RtRole>(session,
            RtEntityQueryOptions.Create().FieldEquals(nameof(RtRole.NormalizedName), name.ToUpperInvariant()));
        await session.CommitTransactionAsync();
        return roles.Items.Single().RtId;
    }

    private async Task<Named> InsertGroupAsync(string tenantId, string prefix, params OctoObjectId[] roleIds)
    {
        var name = $"{prefix}{Guid.NewGuid():N}"[..16];
        var group = new RtGroup { RtId = OctoObjectId.GenerateNewId(), GroupName = name, NormalizedGroupName = name.ToUpperInvariant() };
        await InsertAsync(tenantId, group);
        if (roleIds.Length > 0)
        {
            await new GroupStore(new FixedTenantResolver(await RepositoryOfAsync(tenantId)))
                .SetRoleIdsAsync(group.RtId, roleIds.Select(r => r.ToString()).ToList());
        }

        return new Named(group.RtId, name);
    }

    private async Task InsertAsync<T>(string tenantId, T entity) where T : Meshmakers.Octo.Runtime.Contracts.RepositoryEntities.RtEntity, new()
    {
        var repo = await RepositoryOfAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, entity);
        await session.CommitTransactionAsync();
    }

    private async Task<List<RtUser>> ShadowUsersAsync(string tenantId)
    {
        var repo = await RepositoryOfAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var users = await repo.GetRtEntitiesByTypeAsync<RtUser>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return users.Items.Where(u => CrossTenantShadowUserName.IsShadowUserName(u.UserName)).ToList();
    }

    private async Task<List<RtExternalTenantUserMapping>> MappingsAsync(string tenantId)
    {
        var repo = await RepositoryOfAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var mappings = await repo.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session,
            RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return mappings.Items.ToList();
    }

    private async Task<int> CountLoginProvidersAsync(string tenantId)
    {
        var repo = await RepositoryOfAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var providers = await repo.GetRtEntitiesByTypeAsync<RtOctoTenantIdentityProvider>(session,
            RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return providers.Items.Count();
    }
}
