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
    public async Task FindOrCreate_WithExistingUserAndMapping_SyncsRoles()
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

        var roleRtId = OctoObjectId.GenerateNewId();
        var role = new RtRole
        {
            RtId = roleRtId,
            Name = "TenantAdmin"
        };

        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = "octosystem",
            SourceUserId = "source-user-id",
            SourceUserName = "admin@test.com",
            MappedRoleIds = new Meshmakers.Octo.Runtime.Contracts.RepositoryEntities.AttributeStringValueList(
                [roleRtId.ToString()])
        };

        _userManager.FindByNameAsync("xt_octosystem_admin@test.com")
            .Returns(existingUser);
        _mappingStore.FindBySourceUserAsync("octosystem", "source-user-id")
            .Returns(mapping);

        SetupTenantRepository(role);

        _userManager.GetRolesAsync(existingUser).Returns(new List<string>());
        _userManager.AddToRoleAsync(existingUser, "TenantAdmin")
            .Returns(IdentityResult.Success);

        // Act
        var result = await _sut.FindOrCreateCrossTenantUserAsync(crossTenantResult, "meshtest");

        // Assert
        result.Should().NotBeNull();
        await _userManager.Received(1).AddToRoleAsync(existingUser, "TenantAdmin");
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

        _userManager.GetRolesAsync(Arg.Any<RtUser>()).Returns(new List<string>());

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

        _userManager.GetRolesAsync(Arg.Any<RtUser>()).Returns(new List<string>());

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

        _userManager.GetRolesAsync(Arg.Any<RtUser>()).Returns(new List<string>());

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

    private void SetupTenantRepository(params RtRole[] roles)
    {
        var tenantRepository = Substitute.For<ITenantRepository>();
        var session = Substitute.For<IOctoSession>();

        tenantRepository.GetSessionAsync().Returns(session);
        tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<RtRole>>(new ResultSet<RtRole>(roles, roles.Length, null, null)));

        _multiTenancyResolver.GetTenantRepository().Returns(tenantRepository);
    }

    #endregion
}
