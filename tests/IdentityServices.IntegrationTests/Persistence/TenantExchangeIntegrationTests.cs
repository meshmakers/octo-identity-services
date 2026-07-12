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
///     End-to-end checks of the cross-tenant RFC 8693 token-exchange role resolution (AB#4338)
///     against a real MongoDB (Testcontainers) with the full Octo runtime engine. These pin the
///     <b>security linchpin</b> of <c>TenantExchangeGrantValidator</c>: the token minted for the
///     home-tenant (A) user runs on the <b>B-shadow user's</b> subject and therefore carries the
///     roles re-resolved <b>in B</b> — the subset granted by the child's
///     <c>RtExternalTenantUserMapping</c>, <b>not</b> A's full role set.
/// </summary>
/// <remarks>
///     The integration fixture is service/store level (no HTTP host), so — like the sibling
///     <c>ClientRoleAssignmentIntegrationTests</c> / <c>ClientMirrorProvisioningIntegrationTests</c>
///     — these tests drive the exact services the validator composes:
///     <see cref="CrossTenantAuthenticationService.ValidateCrossTenantAccessAsync" /> (the B-auth
///     gate) and <see cref="CrossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync" />
///     (the B-shadow user), then read the shadow user's effective roles through
///     <see cref="OctoUserStore.GetRolesAsync" /> — the same store that produces the token's
///     <c>role</c> claims — wired to the B tenant repository. This is the precise chain the grant
///     validator relies on; only the Duende <c>subject_token</c> validation and
///     <see cref="Duende.IdentityServer.Validation.GrantValidationResult" /> construction (unit
///     behaviour) are out of scope here.
/// </remarks>
[Collection("Sequential")]
public class TenantExchangeIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public TenantExchangeIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    /// <summary>
    ///     THE load-bearing privilege-escalation regression. A user in parent tenant A holds roles
    ///     rA1 + rA2. Child tenant B has a mapping granting the user only the B-side subset rB1.
    ///     After exchange, the B-shadow user's resolved roles must be exactly {rB1} — never A's full
    ///     set — because the token runs on the B-shadow sub with B-resolved roles.
    /// </summary>
    [Fact]
    public async Task Exchange_ResolvesBSubsetRoles_NotParentFullRoles()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;

        // Parent user in A with two roles.
        var (parentUserId, parentUserName) = await CreateUserAsync(
            systemContext, parentTenantId, "alice");
        var rA1 = await CreateRoleAsync(systemContext, parentTenantId, NewId("rA1"));
        var rA2 = await CreateRoleAsync(systemContext, parentTenantId, NewId("rA2"));
        await AssignRoleToUserAsync(systemContext, parentTenantId, parentUserId, rA1);
        await AssignRoleToUserAsync(systemContext, parentTenantId, parentUserId, rA2);

        // Child tenant B with A as parent, and a mapping granting ONLY the B subset (one role).
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        var rB1 = await CreateRoleAsync(systemContext, childTenantId, NewId("rB1"));
        // A B-only role the user is NOT mapped to — must never appear in the exchanged token.
        await CreateRoleAsync(systemContext, childTenantId, NewId("rB2unmapped"));
        await CreateMappingAsync(systemContext, childTenantId, parentTenantId, parentUserId, parentUserName,
            mappedRoleIds: [rB1.ToString()]);

        var crossTenantAuth = CreateCrossTenantAuthService(systemContext);
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var provisioning = CreateProvisioningService(childRepo);

        // B-auth gate: A must be an ancestor of B and the A user must exist.
        var authResult = await crossTenantAuth.ValidateCrossTenantAccessAsync(
            childTenantId, parentTenantId, parentUserId.ToString());
        authResult.Should().NotBeNull("A is an ancestor of B and the A user exists");

        // Provision (or find) the B-shadow user — the subject the token is issued for.
        var shadowUser = await provisioning.FindOrCreateCrossTenantUserAsync(authResult!, childTenantId);
        shadowUser.Should().NotBeNull();
        shadowUser!.UserName.Should().Be($"xt_{parentTenantId}_{parentUserName}",
            "the token must run on the B-shadow sub, not the A user");

        // Resolve the shadow user's roles through the SAME store that stamps the token's role claims,
        // wired to the B tenant repository.
        var rB1Name = await NameOfRoleInTenantAsync(rB1, childRepo);
        var resolvedRoles = await ResolveRolesInTenantAsync(childRepo, shadowUser);

        resolvedRoles.Should().Contain(rB1Name, "the mapped B role must be granted");
        // The privilege-escalation guard: A's roles must NOT leak into B.
        resolvedRoles.Should().HaveCount(1, "only the mapped B subset is granted, never A's full role set");
    }

    /// <summary>
    ///     B-authorization gate: when A is NOT an ancestor of B, the exchange must be denied
    ///     (the validator maps this to <c>unauthorized_client</c>).
    /// </summary>
    [Fact]
    public async Task Exchange_BNotDescendantOfA_Denied()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var (parentUserId, _) = await CreateUserAsync(systemContext, parentTenantId, "bob");

        // A child tenant that is NOT linked to A (no RtOctoTenantIdentityProvider pointing at A).
        var unrelatedTenantId = await CreateChildTenantAsync(NewId("unrel"));

        var crossTenantAuth = CreateCrossTenantAuthService(systemContext);

        var authResult = await crossTenantAuth.ValidateCrossTenantAccessAsync(
            unrelatedTenantId, parentTenantId, parentUserId.ToString());

        authResult.Should().BeNull("A is not an ancestor of the unrelated tenant → exchange denied");
    }

    /// <summary>
    ///     Missing / unknown subject user: even with a valid ancestor relationship, if the claimed A
    ///     user does not exist the exchange must be denied (defends against a forged sub in an
    ///     otherwise well-formed request).
    /// </summary>
    [Fact]
    public async Task Exchange_UnknownSubjectUser_Denied()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);

        var crossTenantAuth = CreateCrossTenantAuthService(systemContext);

        var authResult = await crossTenantAuth.ValidateCrossTenantAccessAsync(
            childTenantId, parentTenantId, OctoObjectId.GenerateNewId().ToString());

        authResult.Should().BeNull("the claimed A user does not exist → exchange denied");
    }

    // ---------- helpers ----------

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..20];

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);
    }

    private CrossTenantAuthenticationService CreateCrossTenantAuthService(ISystemContext systemContext)
    {
        // ValidateCrossTenantAccessAsync only walks the hierarchy + looks up the user via ISystemContext;
        // the identity-provider store and password hasher are only used by the password-login path.
        var idpStore = new IdentityProviderStore(
            new FixedTenantResolver(systemContext.GetSystemTenantRepositoryAsAdmin()));
        return new CrossTenantAuthenticationService(
            systemContext,
            idpStore,
            new PasswordHasher<RtUser>(),
            NullLogger<CrossTenantAuthenticationService>.Instance);
    }

    private static CrossTenantUserProvisioningService CreateProvisioningService(ITenantRepository childRepo)
    {
        var resolver = new FixedTenantResolver(childRepo);
        var mappingStore = new ExternalTenantUserMappingStore(resolver);
        var userManager = BuildUserManager(resolver);
        return new CrossTenantUserProvisioningService(
            userManager, mappingStore, resolver, NullLogger<CrossTenantUserProvisioningService>.Instance);
    }

    private static async Task<IList<string>> ResolveRolesInTenantAsync(ITenantRepository repo, RtUser user)
    {
        var resolver = new FixedTenantResolver(repo);
        var groupStore = new GroupStore(resolver);
        var groupRoleResolver = new GroupRoleResolver(groupStore);
        var userStore = new OctoUserStore(resolver, groupRoleResolver, null);
        return await userStore.GetRolesAsync(user, TestContext.Current.CancellationToken);
    }

    private static async Task<string> NameOfRoleInTenantAsync(OctoObjectId roleRtId, ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var role = await repo.GetRtEntityByRtIdAsync<RtRole>(session, roleRtId);
        await session.CommitTransactionAsync();
        return role!.Name!;
    }

    /// <summary>
    ///     Builds a real <see cref="UserManager{RtUser}" /> over an <see cref="OctoUserStore" /> bound
    ///     to the given tenant repository, so <c>CreateAsync</c> / <c>AddToRoleAsync</c> hit the right
    ///     database — mirroring how the provisioning service runs in production for tenant B.
    /// </summary>
    private static UserManager<RtUser> BuildUserManager(FixedTenantResolver resolver)
    {
        var groupStore = new GroupStore(resolver);
        var groupRoleResolver = new GroupRoleResolver(groupStore);
        var store = new OctoUserStore(resolver, groupRoleResolver, null);

        var options = Microsoft.Extensions.Options.Options.Create(new IdentityOptions());
        return new UserManager<RtUser>(
            store,
            options,
            new PasswordHasher<RtUser>(),
            Array.Empty<IUserValidator<RtUser>>(),
            Array.Empty<IPasswordValidator<RtUser>>(),
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            services: null!,
            NullLogger<UserManager<RtUser>>.Instance);
    }

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

        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(tenantId);
        return tenantId;
    }

    /// <summary>
    ///     Creates a child tenant B and seeds an <see cref="RtOctoTenantIdentityProvider" /> whose
    ///     <c>ParentTenantId</c> is A, establishing the ancestor relationship the B-auth gate requires.
    /// </summary>
    private async Task<string> CreateChildWithParentProviderAsync(string parentTenantId)
    {
        var childTenantId = await CreateChildTenantAsync(NewId("child"));
        var systemContext = _fixture.GetSystemContext();
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;

        using var session = await childRepo.GetSessionAsync();
        session.StartTransaction();
        try
        {
            await childRepo.InsertOneRtEntityAsync(session, new RtOctoTenantIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = $"ParentTenant_{parentTenantId}",
                DisplayName = $"Login via {parentTenantId}",
                IsEnabled = true,
                ParentTenantId = parentTenantId
            });
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }

        return childTenantId;
    }

    private static async Task<(OctoObjectId userId, string userName)> CreateUserAsync(
        ISystemContext systemContext, string tenantId, string userNamePrefix)
    {
        var repo = tenantId == systemContext.TenantId
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;

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

    private static async Task<OctoObjectId> CreateRoleAsync(
        ISystemContext systemContext, string tenantId, string name)
    {
        var repo = tenantId == systemContext.TenantId
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;

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

    private static async Task AssignRoleToUserAsync(
        ISystemContext systemContext, string tenantId, OctoObjectId userRtId, OctoObjectId roleRtId)
    {
        var repo = tenantId == systemContext.TenantId
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;

        var resolver = new FixedTenantResolver(repo);
        var userStore = new OctoUserStore(
            resolver, new GroupRoleResolver(new GroupStore(resolver)), null);

        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var user = await repo.GetRtEntityByRtIdAsync<RtUser>(session, userRtId);
        var role = await repo.GetRtEntityByRtIdAsync<RtRole>(session, roleRtId);
        await session.CommitTransactionAsync();

        // AddToRoleAsync uses the normalized role name to look up the role, then writes the
        // AssignedRole association — the exact edge OctoUserStore.GetRolesAsync reads back.
        await userStore.AddToRoleAsync(user!, role!.NormalizedName!, TestContext.Current.CancellationToken);
    }

    private static async Task CreateMappingAsync(
        ISystemContext systemContext, string childTenantId, string sourceTenantId,
        OctoObjectId sourceUserId, string sourceUserName, IReadOnlyList<string> mappedRoleIds)
    {
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = sourceTenantId,
            SourceUserId = sourceUserId.ToString(),
            SourceUserName = sourceUserName,
            MappedRoleIds = new AttributeStringValueList()
        };
        foreach (var roleId in mappedRoleIds)
        {
            mapping.MappedRoleIds.Add(roleId);
        }

        using var session = await childRepo.GetSessionAsync();
        session.StartTransaction();
        await childRepo.InsertOneRtEntityAsync(session, mapping);
        await session.CommitTransactionAsync();
    }
}
