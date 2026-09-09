using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     End-to-end checks of the delegation ("on-behalf-of") role intersection (AB#5026) against a
///     real MongoDB (Testcontainers) with the full Octo runtime engine.
/// </summary>
/// <remarks>
///     <para>
///         The unit suite pins the intersection arithmetic over substituted stores; what can only be
///         proven here is that <b>both sides really resolve the same way the token pipeline does</b> —
///         direct <c>AssignedRole</c> edges <b>and</b> roles inherited through group membership,
///         for a <c>Client</c> (via <see cref="ClientRoleStore" />, the store
///         <c>TokenEndpointController.HandleClientCredentialsAsync</c> uses) and for a <c>User</c> (via
///         <c>OctoUserStore</c>, the store that stamps a login token's <c>role</c> claims).
///     </para>
///     <para>
///         Roles, clients, groups and users are created in-test so the assertions do not depend on
///         what the blueprint seed provisions in the fixture.
///     </para>
/// </remarks>
[Collection("Sequential")]
public class DelegatedIdentityIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public DelegatedIdentityIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    /// <summary>
    ///     THE delegation invariant, over real role graphs: the effective set is exactly the
    ///     intersection — including roles either side only holds through a group — and neither
    ///     party's exclusive roles leak into it.
    /// </summary>
    [Fact]
    public async Task Delegation_ResolvesIntersection_IncludingGroupInheritedRolesOnBothSides()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, groupStore, repo) = CreateFixtureStores();

        // Four roles: shared-direct, service-account-only, user-only, and shared-via-groups.
        var sharedDirect = NewId("shared");
        var serviceAccountOnly = NewId("saOnly");
        var userOnly = NewId("usrOnly");
        var sharedViaGroups = NewId("grpBoth");

        var sharedDirectId = await CreateRoleAsync(repo, sharedDirect);
        var serviceAccountOnlyId = await CreateRoleAsync(repo, serviceAccountOnly);
        var userOnlyId = await CreateRoleAsync(repo, userOnly);
        var sharedViaGroupsId = await CreateRoleAsync(repo, sharedViaGroups);

        // Service account: two direct roles + one inherited from a group it is a member of.
        var clientId = NewId("sa");
        var clientRtId = await CreateClientAsync(repo, clientId);
        var saGroup = await CreateGroupAsync(repo, NewId("gSa"));
        await groupStore.SetRoleIdsAsync(saGroup, [sharedViaGroupsId.ToString(), serviceAccountOnlyId.ToString()]);
        await groupStore.AddMemberClientAsync(saGroup, clientRtId.ToString());

        var clientRoleStore = CreateClientRoleStore(repo);
        await clientRoleStore.AddRoleAsync(clientRtId, sharedDirect);

        // User: one direct role + one from a DIFFERENT group that grants the same shared role.
        var (userRtId, _) = await CreateUserAsync(repo, "alice");
        var userGroup = await CreateGroupAsync(repo, NewId("gUsr"));
        await groupStore.SetRoleIdsAsync(userGroup, [sharedViaGroupsId.ToString()]);
        await groupStore.AddMemberUserAsync(userGroup, userRtId.ToString());

        var userStore = CreateUserStore(repo);
        await AssignRoleToUserAsync(repo, userStore, userRtId, sharedDirectId);
        await AssignRoleToUserAsync(repo, userStore, userRtId, userOnlyId);

        var result = await resolver.ResolveAsync(clientId, userRtId.ToString(),
            TestContext.Current.CancellationToken);

        result.IsGranted.Should().BeTrue();
        result.EffectiveRoleNames.Should().BeEquivalentTo([sharedDirect, sharedViaGroups],
            "the intersection covers both the directly assigned and the group-inherited shared roles");
        result.EffectiveRoleNames.Should().NotContain(serviceAccountOnly,
            "the service account's exclusive authority must not travel with the user's identity");
        result.EffectiveRoleNames.Should().NotContain(userOnly,
            "the user's exclusive authority must not be reachable through a narrower service account");

        // Sanity: both inputs really did resolve their group-inherited roles.
        result.ServiceAccountRoleNames.Should()
            .BeEquivalentTo([sharedDirect, sharedViaGroups, serviceAccountOnly]);
        result.UserRoleNames.Should().BeEquivalentTo([sharedDirect, sharedViaGroups, userOnly]);
    }

    /// <summary>
    ///     Disjoint role sets are a grant with no roles — not a denial. The token would be issued and
    ///     simply authorize nothing.
    /// </summary>
    [Fact]
    public async Task Delegation_DisjointRoles_GrantsNoRoles()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, _, repo) = CreateFixtureStores();

        var saRole = NewId("saX");
        var userRole = NewId("usrX");
        await CreateRoleAsync(repo, saRole);
        var userRoleId = await CreateRoleAsync(repo, userRole);

        var clientId = NewId("saD");
        var clientRtId = await CreateClientAsync(repo, clientId);
        await CreateClientRoleStore(repo).AddRoleAsync(clientRtId, saRole);

        var (userRtId, _) = await CreateUserAsync(repo, "bob");
        await AssignRoleToUserAsync(repo, CreateUserStore(repo), userRtId, userRoleId);

        var result = await resolver.ResolveAsync(clientId, userRtId.ToString(),
            TestContext.Current.CancellationToken);

        result.IsGranted.Should().BeTrue();
        result.DenialReason.Should().Be(DelegationDenialReason.None);
        result.EffectiveRoleNames.Should().BeEmpty();
    }

    /// <summary>An unknown service account is denied — it cannot be provisioned implicitly.</summary>
    [Fact]
    public async Task Delegation_UnknownServiceAccount_IsDenied()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, _, repo) = CreateFixtureStores();

        var (userRtId, _) = await CreateUserAsync(repo, "carol");

        var result = await resolver.ResolveAsync("no-such-service-account", userRtId.ToString(),
            TestContext.Current.CancellationToken);

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(DelegationDenialReason.ServiceAccountNotFound);
    }

    /// <summary>An unknown subject is denied — the subject token must name a user of this tenant.</summary>
    [Fact]
    public async Task Delegation_UnknownUser_IsDenied()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, _, repo) = CreateFixtureStores();

        var clientId = NewId("saU");
        await CreateClientAsync(repo, clientId);

        var result = await resolver.ResolveAsync(clientId, OctoObjectId.GenerateNewId().ToString(),
            TestContext.Current.CancellationToken);

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(DelegationDenialReason.UserNotFound);
    }

    // ---------- helpers ----------

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24];

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);
    }

    /// <summary>
    ///     Wires the real resolver to the system tenant repository, exactly as the DI graph does per
    ///     request — the client store, both role stores and the group role resolver all read through
    ///     the same tenant repository.
    /// </summary>
    private (DelegatedIdentityResolver resolver, GroupStore groupStore, ITenantRepository repo)
        CreateFixtureStores()
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        var tenantResolver = new FixedTenantResolver(repo);
        var groupStore = new GroupStore(tenantResolver);
        var clientStore = new ClientStore(tenantResolver);

        var resolver = new DelegatedIdentityResolver(
            clientStore,
            CreateClientRoleStore(repo),
            CreateUserStore(repo),
            NullLogger<DelegatedIdentityResolver>.Instance);

        return (resolver, groupStore, repo);
    }

    private static ClientRoleStore CreateClientRoleStore(ITenantRepository repo)
    {
        var tenantResolver = new FixedTenantResolver(repo);
        return new ClientRoleStore(
            tenantResolver,
            new GroupRoleResolver(new GroupStore(tenantResolver)),
            NullLogger<ClientRoleStore>.Instance);
    }

    private static OctoUserStore CreateUserStore(ITenantRepository repo)
    {
        var tenantResolver = new FixedTenantResolver(repo);
        return new OctoUserStore(
            tenantResolver, new GroupRoleResolver(new GroupStore(tenantResolver)), null);
    }

    private static async Task<OctoObjectId> CreateRoleAsync(ITenantRepository repo, string name)
    {
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
        return rtId;
    }

    private static async Task<OctoObjectId> CreateClientAsync(ITenantRepository repo, string clientId)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = rtId,
            Enabled = true,
            ClientId = clientId,
            ProtocolType = "oidc",
            RequireClientSecret = true,
            // The delegating client must opt into the grant explicitly — the server rejects the request
            // before the validator runs otherwise.
            AllowedGrantTypes = new AttributeStringValueList
            {
                "client_credentials",
                "urn:meshmakers:params:oauth:grant-type:on-behalf-of"
            },
            AllowedScopes = new AttributeStringValueList { "octo_api" }
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<OctoObjectId> CreateGroupAsync(ITenantRepository repo, string name)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtGroup
        {
            RtId = rtId,
            GroupName = name,
            NormalizedGroupName = name.ToUpperInvariant()
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<(OctoObjectId userId, string userName)> CreateUserAsync(
        ITenantRepository repo, string userNamePrefix)
    {
        var userName = NewId(userNamePrefix);
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtUser
        {
            RtId = rtId,
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = $"{userName}@example.com",
            NormalizedEmail = $"{userName}@example.com".ToUpperInvariant(),
            EmailConfirmed = true,
            SecurityStamp = Guid.NewGuid().ToString()
        });
        await session.CommitTransactionAsync();
        return (rtId, userName);
    }

    private static async Task AssignRoleToUserAsync(
        ITenantRepository repo, OctoUserStore userStore, OctoObjectId userRtId, OctoObjectId roleRtId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var user = await repo.GetRtEntityByRtIdAsync<RtUser>(session, userRtId);
        var role = await repo.GetRtEntityByRtIdAsync<RtRole>(session, roleRtId);
        await session.CommitTransactionAsync();

        // AddToRoleAsync writes the AssignedRole association OctoUserStore.GetRolesAsync reads back.
        await userStore.AddToRoleAsync(user!, role!.NormalizedName!, TestContext.Current.CancellationToken);
    }
}
