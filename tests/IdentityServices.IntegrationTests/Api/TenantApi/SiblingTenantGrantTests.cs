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
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
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

    // ------------------------------------------------------------------ helpers

    private sealed record TestUser(OctoObjectId Id, string UserName, string Email);

    private sealed record Named(OctoObjectId Id, string Name);

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

    private async Task<TestUser> InsertUserAsync(string tenantId, string prefix, bool lockedOut = false)
    {
        var userName = prefix.StartsWith("xt_", StringComparison.Ordinal)
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
