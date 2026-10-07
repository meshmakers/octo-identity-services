using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Engine.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Services;

public class CrossTenantUserProvisioningServiceTests
{
    private readonly UserManager<RtUser> _userManager;
    private readonly IExternalTenantUserMappingStore _mappingStore;
    private readonly IMultiTenancyResolverService _multiTenancyResolver;
    private readonly CrossTenantUserProvisioningService _sut;

    public CrossTenantUserProvisioningServiceTests()
    {
        var userStore = Substitute.For<IUserStore<RtUser>>();
        _userManager = Substitute.For<UserManager<RtUser>>(
            userStore,
            Substitute.For<Microsoft.Extensions.Options.IOptions<IdentityOptions>>(),
            Substitute.For<IPasswordHasher<RtUser>>(),
            Array.Empty<IUserValidator<RtUser>>(),
            Array.Empty<IPasswordValidator<RtUser>>(),
            Substitute.For<ILookupNormalizer>(),
            Substitute.For<IdentityErrorDescriber>(),
            Substitute.For<IServiceProvider>(),
            Substitute.For<ILogger<UserManager<RtUser>>>());

        _mappingStore = Substitute.For<IExternalTenantUserMappingStore>();
        _multiTenancyResolver = Substitute.For<IMultiTenancyResolverService>();
        var logger = Substitute.For<ILogger<CrossTenantUserProvisioningService>>();

        _sut = new CrossTenantUserProvisioningService(
            _userManager,
            _mappingStore,
            _multiTenancyResolver,
            logger);
    }

    #region FindOrCreateCrossTenantUserAsync - Existing User

    [Fact]
    public async Task FindOrCreate_WithExistingUser_ReturnsExistingUser()
    {
        // Arrange
        var crossTenantResult = CreateCrossTenantResult();
        var existingUser = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = "xt_octosystem_admin@test.com",
            FirstName = "Admin",
            LastName = "User",
            Email = "admin@test.com"
        };

        _userManager.FindByNameAsync("xt_octosystem_admin@test.com")
            .Returns(existingUser);
        _mappingStore.FindBySourceUserAsync("octosystem", "source-user-id")
            .Returns((RtExternalTenantUserMapping?)null);

        // Act
        var result = await _sut.FindOrCreateCrossTenantUserAsync(crossTenantResult, "meshtest");

        // Assert
        result.Should().NotBeNull();
        result!.UserName.Should().Be("xt_octosystem_admin@test.com");
        await _userManager.DidNotReceive().CreateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task FindOrCreate_WithExistingUser_SyncsProfileFields()
    {
        // Arrange
        var crossTenantResult = CreateCrossTenantResult(
            firstName: "UpdatedFirst",
            lastName: "UpdatedLast",
            email: "updated@test.com");

        var existingUser = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = "xt_octosystem_admin@test.com",
            FirstName = "OldFirst",
            LastName = "OldLast",
            Email = "old@test.com"
        };

        _userManager.FindByNameAsync("xt_octosystem_admin@test.com")
            .Returns(existingUser);
        _userManager.UpdateAsync(Arg.Any<RtUser>())
            .Returns(IdentityResult.Success);
        _mappingStore.FindBySourceUserAsync("octosystem", "source-user-id")
            .Returns((RtExternalTenantUserMapping?)null);

        // Act
        var result = await _sut.FindOrCreateCrossTenantUserAsync(crossTenantResult, "meshtest");

        // Assert
        result.Should().NotBeNull();
        result!.FirstName.Should().Be("UpdatedFirst");
        result.LastName.Should().Be("UpdatedLast");
        result.Email.Should().Be("updated@test.com");
        await _userManager.Received(1).UpdateAsync(existingUser);
    }

    [Fact]
    public async Task FindOrCreate_WithExistingUserAndMapping_DoesNotMaterialiseMappedRoles()
    {
        // AB#5708: mapping roles are resolved at token time; copying them onto the user froze a
        // snapshot that a later removal from the mapping could never take away again.
        var crossTenantResult = CreateCrossTenantResult();
        var existingUser = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = "xt_octosystem_admin@test.com",
            FirstName = "Admin",
            LastName = "User",
            Email = "admin@test.com"
        };

        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = "octosystem",
            SourceUserId = "source-user-id",
            SourceUserName = "admin@test.com",
            MappedRoleIds = new Meshmakers.Octo.Runtime.Contracts.RepositoryEntities.AttributeStringValueList(
                [OctoObjectId.GenerateNewId().ToString()])
        };

        _userManager.FindByNameAsync("xt_octosystem_admin@test.com")
            .Returns(existingUser);
        _mappingStore.FindBySourceUserAsync("octosystem", "source-user-id")
            .Returns(mapping);

        var result = await _sut.FindOrCreateCrossTenantUserAsync(crossTenantResult, "meshtest");

        result.Should().BeSameAs(existingUser);
        await _userManager.DidNotReceive().AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>());
        await _userManager.DidNotReceive().RemoveFromRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>());
    }

    [Fact]
    public async Task FindOrCreate_TenantSwitchFromParent_ReusesShadowUserOfPasswordLogin()
    {
        // Password login unwound to the home tenant and created xt_meshmakers_gerald; the tenant switch
        // from karlplus arrives as karlplus' shadow user and must not mint xt_karlplus_xt_meshmakers_gerald.
        var crossTenantResult = CreateCrossTenantResult(
            sourceTenantId: "karlplus", sourceUserName: "xt_meshmakers_gerald");
        var homeShadow = CreateShadowUser("xt_meshmakers_gerald");

        _userManager.FindByNameAsync("xt_karlplus_xt_meshmakers_gerald").Returns((RtUser?)null);
        SetupTenantRepository(homeShadow);
        _userManager.UpdateAsync(Arg.Any<RtUser>()).Returns(IdentityResult.Success);

        var result = await _sut.FindOrCreateCrossTenantUserAsync(crossTenantResult, "handelsdemo");

        result.Should().BeSameAs(homeShadow);
        await _userManager.DidNotReceive().CreateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task FindOrCreate_PasswordLogin_ReusesShadowUserOfTenantSwitch()
    {
        var crossTenantResult = CreateCrossTenantResult(
            sourceTenantId: "meshmakers", sourceUserName: "gerald");
        var switchShadow = CreateShadowUser("xt_karlplus_xt_meshmakers_gerald");

        _userManager.FindByNameAsync("xt_meshmakers_gerald").Returns((RtUser?)null);
        SetupTenantRepository(switchShadow);
        _userManager.UpdateAsync(Arg.Any<RtUser>()).Returns(IdentityResult.Success);

        var result = await _sut.FindOrCreateCrossTenantUserAsync(crossTenantResult, "handelsdemo");

        result.Should().BeSameAs(switchShadow);
        await _userManager.DidNotReceive().CreateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task FindCrossTenantUser_ExactNameExists_WinsOverEquivalentShadowUsers()
    {
        // Legacy duplicates stay stable: each login path keeps the shadow user it created.
        var crossTenantResult = CreateCrossTenantResult(
            sourceTenantId: "karlplus", sourceUserName: "xt_meshmakers_gerald");
        var exact = CreateShadowUser("xt_karlplus_xt_meshmakers_gerald");
        _userManager.FindByNameAsync("xt_karlplus_xt_meshmakers_gerald").Returns(exact);
        SetupTenantRepository(CreateShadowUser("xt_meshmakers_gerald"));

        var result = await _sut.FindCrossTenantUserAsync(crossTenantResult);

        result.Should().BeSameAs(exact);
    }

    [Fact]
    public async Task FindCrossTenantUser_SeveralEquivalentShadowUsers_PicksShortestChain()
    {
        var crossTenantResult = CreateCrossTenantResult(
            sourceTenantId: "other", sourceUserName: "xt_meshmakers_gerald");
        var nested = CreateShadowUser("xt_karlplus_xt_meshmakers_gerald");
        var home = CreateShadowUser("xt_meshmakers_gerald");
        _userManager.FindByNameAsync(Arg.Any<string>()).Returns((RtUser?)null);
        SetupTenantRepository(nested, home);

        var result = await _sut.FindCrossTenantUserAsync(crossTenantResult);

        result.Should().BeSameAs(home);
    }

    [Fact]
    public async Task FindCrossTenantUser_CandidateWithPassword_IsNotTreatedAsShadowUser()
    {
        // A local account wearing an xt_ name (it has a password) must never be handed to the person.
        var crossTenantResult = CreateCrossTenantResult(
            sourceTenantId: "meshmakers", sourceUserName: "gerald");
        var impostor = CreateShadowUser("xt_karlplus_xt_meshmakers_gerald");
        impostor.PasswordHash = "hash";
        _userManager.FindByNameAsync(Arg.Any<string>()).Returns((RtUser?)null);
        SetupTenantRepository(impostor);

        var result = await _sut.FindCrossTenantUserAsync(crossTenantResult);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FindCrossTenantUser_SuffixMatchOfOtherIdentity_IsIgnored()
    {
        // xt_foo_bar_xt_meshmakers_gerald ends like the root shadow name but unwinds to (foo, bar_xt_…).
        var crossTenantResult = CreateCrossTenantResult(
            sourceTenantId: "meshmakers", sourceUserName: "gerald");
        _userManager.FindByNameAsync(Arg.Any<string>()).Returns((RtUser?)null);
        SetupTenantRepository(CreateShadowUser("xt_foo_bar_xt_meshmakers_gerald"));

        var result = await _sut.FindCrossTenantUserAsync(crossTenantResult);

        result.Should().BeNull();
    }

    [Fact]
    public async Task IsExplicitlyProvisioned_MappingForHomeIdentity_CountsForParentShadowSource()
    {
        var crossTenantResult = CreateCrossTenantResult(
            sourceTenantId: "karlplus", sourceUserName: "xt_meshmakers_gerald");
        _mappingStore.FindBySourceUserAsync("karlplus", "source-user-id")
            .Returns((RtExternalTenantUserMapping?)null);
        _mappingStore.FindBySourceUserNamesAsync(Arg.Is<IReadOnlyCollection<(string, string)>>(c =>
                HasIdentity(c, "karlplus", "xt_meshmakers_gerald") && HasIdentity(c, "meshmakers", "gerald")))
            .Returns([new RtExternalTenantUserMapping { SourceTenantId = "meshmakers", SourceUserName = "gerald" }]);

        var result = await _sut.IsExplicitlyProvisionedAsync(crossTenantResult);

        result.Should().BeTrue();
    }

    [Fact]
    public async Task IsExplicitlyProvisioned_NoMappingOnAnyTier_IsFalse()
    {
        var crossTenantResult = CreateCrossTenantResult(
            sourceTenantId: "karlplus", sourceUserName: "xt_meshmakers_gerald");
        _mappingStore.FindBySourceUserAsync(Arg.Any<string>(), Arg.Any<string>())
            .Returns((RtExternalTenantUserMapping?)null);
        _mappingStore.FindBySourceUserNamesAsync(Arg.Any<IReadOnlyCollection<(string, string)>>())
            .Returns(Array.Empty<RtExternalTenantUserMapping>());

        var result = await _sut.IsExplicitlyProvisionedAsync(crossTenantResult);

        result.Should().BeFalse();
    }

    #endregion

    #region FindOrCreateCrossTenantUserAsync - New User

    [Fact]
    public async Task FindOrCreate_WithNoExistingUser_CreatesNewUser()
    {
        // Arrange
        var crossTenantResult = CreateCrossTenantResult(
            firstName: "Gerald",
            lastName: "Lochner",
            email: "admin@test.com");

        _userManager.FindByNameAsync("xt_octosystem_admin@test.com")
            .Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>())
            .Returns(IdentityResult.Success);
        _mappingStore.FindBySourceUserAsync("octosystem", "source-user-id")
            .Returns((RtExternalTenantUserMapping?)null);

        SetupTenantRepository();

        // Act
        var result = await _sut.FindOrCreateCrossTenantUserAsync(crossTenantResult, "meshtest");

        // Assert
        result.Should().NotBeNull();
        result!.UserName.Should().Be("xt_octosystem_admin@test.com");
        result.FirstName.Should().Be("Gerald");
        result.LastName.Should().Be("Lochner");
        result.Email.Should().Be("admin@test.com");
        result.EmailConfirmed.Should().BeTrue();
        await _userManager.Received(1).CreateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task FindOrCreate_WithNoExistingUser_CreatesMapping()
    {
        // Arrange
        var crossTenantResult = CreateCrossTenantResult();

        _userManager.FindByNameAsync("xt_octosystem_admin@test.com")
            .Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>())
            .Returns(IdentityResult.Success);
        _mappingStore.FindBySourceUserAsync("octosystem", "source-user-id")
            .Returns((RtExternalTenantUserMapping?)null);

        SetupTenantRepository();

        // Act
        await _sut.FindOrCreateCrossTenantUserAsync(crossTenantResult, "meshtest");

        // Assert
        await _mappingStore.Received(1).StoreAsync(
            Arg.Is<RtExternalTenantUserMapping>(m =>
                m.SourceTenantId == "octosystem" &&
                m.SourceUserId == "source-user-id" &&
                m.SourceUserName == "admin@test.com"));
    }

    [Fact]
    public async Task FindOrCreate_WhenCreateFails_ReturnsNull()
    {
        // Arrange
        var crossTenantResult = CreateCrossTenantResult();

        _userManager.FindByNameAsync("xt_octosystem_admin@test.com")
            .Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>())
            .Returns(IdentityResult.Failed(new IdentityError { Description = "Create failed" }));
        _mappingStore.FindBySourceUserAsync("octosystem", "source-user-id")
            .Returns((RtExternalTenantUserMapping?)null);
        SetupTenantRepository();

        // Act
        var result = await _sut.FindOrCreateCrossTenantUserAsync(crossTenantResult, "meshtest");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task FindOrCreate_WithExistingMapping_DoesNotCreateNewMapping()
    {
        // Arrange
        var crossTenantResult = CreateCrossTenantResult();
        var existingMapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = "octosystem",
            SourceUserId = "source-user-id",
            SourceUserName = "admin@test.com"
        };

        _userManager.FindByNameAsync("xt_octosystem_admin@test.com")
            .Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>())
            .Returns(IdentityResult.Success);
        _mappingStore.FindBySourceUserAsync("octosystem", "source-user-id")
            .Returns(existingMapping);

        SetupTenantRepository();

        // Act
        await _sut.FindOrCreateCrossTenantUserAsync(crossTenantResult, "meshtest");

        // Assert
        await _mappingStore.DidNotReceive().StoreAsync(
            Arg.Is<RtExternalTenantUserMapping>(m => m.RtId != existingMapping.RtId));
    }

    #endregion

    #region Helpers

    private static CrossTenantAuthResult CreateCrossTenantResult(
        string sourceTenantId = "octosystem",
        string sourceUserId = "source-user-id",
        string sourceUserName = "admin@test.com",
        string? firstName = "Admin",
        string? lastName = "User",
        string? email = "admin@test.com")
    {
        return new CrossTenantAuthResult
        {
            SourceTenantId = sourceTenantId,
            SourceUserId = sourceUserId,
            SourceUserName = sourceUserName,
            FirstName = firstName,
            LastName = lastName,
            Email = email
        };
    }

    private static bool HasIdentity(IReadOnlyCollection<(string, string)> identities, string tenant, string user)
        => identities.Contains((tenant, user));

    private static RtUser CreateShadowUser(string userName) => new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        UserName = userName,
        NormalizedUserName = userName.ToUpperInvariant()
    };

    private void SetupTenantRepository(params RtUser[] users)
    {
        var tenantRepository = Substitute.For<ITenantRepository>();
        var session = Substitute.For<IOctoSession>();

        tenantRepository.GetSessionAsync().Returns(session);
        tenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<RtUser>>(new ResultSet<RtUser>(users, users.Length, null, null)));

        _multiTenancyResolver.GetTenantRepository().Returns(tenantRepository);
    }

    #endregion
}
