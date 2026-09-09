using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     Pins what <see cref="AllowedTenantsResolver" /> offers — the <c>allowed_tenants</c> claim, the
///     Studio switcher and the email-first tenant discovery all read it — against a real MongoDB
///     (Testcontainers) with the full Octo runtime engine (AB#5170).
/// </summary>
/// <remarks>
///     The rule under test: a user is offered the tenants they actually exist in — the login tenant,
///     the home tenants a shadow user's <c>xt_{home}_{name}</c> chain unwinds to, and the descendants
///     reachable through <see cref="RtExternalTenantUserMapping" /> — and nothing merely because an
///     <see cref="RtOctoTenantIdentityProvider" /> points there. The resolver used to add every
///     ancestor reachable through the provider graph, so a user created locally in an operating
///     tenant was offered the management tenant and the platform root, where no account of theirs
///     exists and the switch gate refuses them; picking one in tenant discovery ended in
///     "invalid credentials".
/// </remarks>
public class AllowedTenantsResolverIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public AllowedTenantsResolverIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    /// <summary>
    ///     A user who exists only in the operating tenant B is offered B — not the parent A its
    ///     <see cref="RtOctoTenantIdentityProvider" /> delegates to, and nothing above it.
    /// </summary>
    [Fact]
    public async Task LocalUser_IsOfferedOnlyItsOwnTenant_NeverTheParentItDelegatesTo()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        var localUser = await CreateUserAsync(systemContext, childTenantId, "local");

        var allowed = await CreateResolver(systemContext).ResolveAsync(childTenantId, localUser);

        allowed.Should().BeEquivalentTo([childTenantId],
            "the user exists in B alone; A only says where B delegates authentication to");
    }

    /// <summary>
    ///     A shadow user carries every home tenant its name unwinds to: the B shadow of an A user is
    ///     offered A, and the C shadow of that B shadow is offered B and A.
    /// </summary>
    [Fact]
    public async Task ShadowUser_IsOfferedEveryHomeTenantOfItsChain()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var parentUser = await CreateUserAsync(systemContext, parentTenantId, "carol");

        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        await CreateMappingAsync(systemContext, childTenantId, parentTenantId, parentUser.RtId, parentUser.UserName!);
        var childShadow = await ProvisionShadowAsync(systemContext, childTenantId, parentTenantId, parentUser);

        var grandchildTenantId = await CreateChildWithParentProviderAsync(childTenantId);
        await CreateMappingAsync(systemContext, grandchildTenantId, childTenantId, childShadow.RtId, childShadow.UserName!);
        var grandchildShadow = await ProvisionShadowAsync(systemContext, grandchildTenantId, childTenantId, childShadow);

        var resolver = CreateResolver(systemContext);

        var childAllowed = await resolver.ResolveAsync(childTenantId, childShadow);
        childAllowed.Should().Contain([childTenantId, parentTenantId]);

        grandchildShadow.UserName.Should().Be($"xt_{childTenantId}_xt_{parentTenantId}_{parentUser.UserName}");
        var grandchildAllowed = await resolver.ResolveAsync(grandchildTenantId, grandchildShadow);
        grandchildAllowed.Should().Contain([grandchildTenantId, childTenantId, parentTenantId],
            "each tier of the xt_ chain is a tenant the user really exists in");
    }

    /// <summary>
    ///     The descendant walk is unchanged: a parent user is offered every tenant below that maps
    ///     them, following the xt_ chain through intermediate tenants.
    /// </summary>
    [Fact]
    public async Task ParentUser_IsOfferedTheMappedDescendants()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var parentUser = await CreateUserAsync(systemContext, parentTenantId, "dave");

        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        await CreateMappingAsync(systemContext, childTenantId, parentTenantId, parentUser.RtId, parentUser.UserName!);
        var grandchildTenantId = await CreateChildWithParentProviderAsync(childTenantId);
        await CreateMappingAsync(systemContext, grandchildTenantId, childTenantId,
            OctoObjectId.GenerateNewId(), $"xt_{parentTenantId}_{parentUser.UserName}");
        // A child that maps somebody else must not appear.
        var unrelatedTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        await CreateMappingAsync(systemContext, unrelatedTenantId, parentTenantId, OctoObjectId.GenerateNewId(), "somebody-else");

        var allowed = await CreateResolver(systemContext).ResolveAsync(parentTenantId, parentUser);

        allowed.Should().Contain([parentTenantId, childTenantId, grandchildTenantId]);
        allowed.Should().NotContain(unrelatedTenantId);
    }

    /// <summary>
    ///     Tenant discovery reuses the resolver, so a local user asked for their e-mail is offered
    ///     the one tenant that knows them — the case the login page used to get wrong.
    /// </summary>
    [Fact]
    public async Task Discovery_OffersLocalUserOnlyTheTenantThatKnowsThem()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var childTenantId = await CreateChildWithParentProviderAsync(systemContext.TenantId);
        var localUser = await CreateUserAsync(systemContext, childTenantId, "erin");

        var discovery = new TenantDiscoveryService(
            systemContext, CreateResolver(systemContext), NullLogger<TenantDiscoveryService>.Instance);

        var tenants = await discovery.FindTenantsForUserAsync(localUser.Email!);

        tenants.Should().BeEquivalentTo([childTenantId]);
    }

    // ---------- helpers ----------

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..20];

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);
    }

    private static AllowedTenantsResolver CreateResolver(ISystemContext systemContext) =>
        new(systemContext, NullLogger<AllowedTenantsResolver>.Instance);

    /// <summary>
    ///     Creates the shadow user the way a cross-tenant login or switch does, so its name follows
    ///     the <c>xt_{source}_{name}</c> convention the resolver unwinds.
    /// </summary>
    private static async Task<RtUser> ProvisionShadowAsync(
        ISystemContext systemContext, string targetTenantId, string sourceTenantId, RtUser sourceUser)
    {
        var targetRepo = (await systemContext.TryFindTenantRepositoryAsync(targetTenantId))!;
        var resolver = new FixedTenantResolver(targetRepo);
        var provisioning = new CrossTenantUserProvisioningService(
            BuildUserManager(resolver),
            new ExternalTenantUserMappingStore(resolver),
            resolver,
            NullLogger<CrossTenantUserProvisioningService>.Instance);

        var shadow = await provisioning.FindOrCreateCrossTenantUserAsync(new CrossTenantAuthResult
        {
            SourceTenantId = sourceTenantId,
            SourceUserId = sourceUser.RtId.ToString(),
            SourceUserName = sourceUser.UserName!,
            Email = sourceUser.Email
        }, targetTenantId);
        shadow.Should().NotBeNull();
        return shadow!;
    }

    private static UserManager<RtUser> BuildUserManager(FixedTenantResolver resolver)
    {
        var groupStore = new GroupStore(resolver);
        var store = new OctoUserStore(resolver, new GroupRoleResolver(groupStore), null);
        return new UserManager<RtUser>(
            store,
            Microsoft.Extensions.Options.Options.Create(new IdentityOptions()),
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
    ///     A tenant that delegates authentication to <paramref name="parentTenantId" /> through an
    ///     <see cref="RtOctoTenantIdentityProvider" /> — the relation the resolver must NOT read as
    ///     "every user here also exists up there".
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

    private static async Task<RtUser> CreateUserAsync(ISystemContext systemContext, string tenantId, string userNamePrefix)
    {
        var repo = tenantId == systemContext.TenantId
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;

        var userName = NewId(userNamePrefix);
        var user = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = $"{userName}@example.com",
            NormalizedEmail = $"{userName}@example.com".ToUpperInvariant(),
            EmailConfirmed = true,
            SecurityStamp = Guid.NewGuid().ToString()
        };
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, user);
        await session.CommitTransactionAsync();
        return user;
    }

    private static async Task CreateMappingAsync(
        ISystemContext systemContext, string childTenantId, string sourceTenantId,
        OctoObjectId sourceUserId, string sourceUserName)
    {
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        using var session = await childRepo.GetSessionAsync();
        session.StartTransaction();
        await childRepo.InsertOneRtEntityAsync(session, new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = sourceTenantId,
            SourceUserId = sourceUserId.ToString(),
            SourceUserName = sourceUserName,
            MappedRoleIds = new AttributeStringValueList()
        });
        await session.CommitTransactionAsync();
    }
}
