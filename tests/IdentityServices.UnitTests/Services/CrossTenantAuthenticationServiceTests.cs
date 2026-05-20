using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Services;

public class CrossTenantAuthenticationServiceTests
{
    private readonly ISystemContext _systemContext;
    private readonly IOctoIdentityProviderStore _identityProviderStore;
    private readonly IPasswordHasher<RtUser> _passwordHasher;
    private readonly ILogger<CrossTenantAuthenticationService> _logger;
    private readonly CrossTenantAuthenticationService _sut;

    public CrossTenantAuthenticationServiceTests()
    {
        _systemContext = Substitute.For<ISystemContext>();
        _identityProviderStore = Substitute.For<IOctoIdentityProviderStore>();
        _passwordHasher = Substitute.For<IPasswordHasher<RtUser>>();
        _logger = Substitute.For<ILogger<CrossTenantAuthenticationService>>();

        _sut = new CrossTenantAuthenticationService(
            _systemContext,
            _identityProviderStore,
            _passwordHasher,
            _logger);
    }

    [Fact]
    public async Task Authenticate_WithNoProviderConfigured_ReturnsNull()
    {
        // Arrange
        _identityProviderStore.GetAllAsync()
            .Returns(Array.Empty<RtIdentityProvider>());

        // Act
        var result = await _sut.AuthenticateAsync("child-tenant", "user", "pass");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task Authenticate_WithDisabledProvider_ReturnsNull()
    {
        // Arrange
        var provider = CreateTenantProvider("parent-tenant", isEnabled: false);
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { provider });

        // Act
        var result = await _sut.AuthenticateAsync("child-tenant", "user", "pass");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task Authenticate_WithValidCredentialsInParent_Succeeds()
    {
        // Arrange
        var provider = CreateTenantProvider("parent-tenant", isEnabled: true);
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { provider });

        var user = CreateUser("testuser");
        SetupTenantWithUser("parent-tenant", user);
        SetupTenantWithNoProviders("parent-tenant");

        _passwordHasher.VerifyHashedPassword(user, Arg.Any<string>(), "correctpass")
            .Returns(PasswordVerificationResult.Success);

        // Act
        var result = await _sut.AuthenticateAsync("child-tenant", "testuser", "correctpass");

        // Assert
        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be("parent-tenant");
        result.SourceUserId.Should().Be(user.RtId.ToString());
        result.SourceUserName.Should().Be("testuser");
    }

    [Fact]
    public async Task Authenticate_WithInvalidCredentials_ReturnsNull()
    {
        // Arrange
        var provider = CreateTenantProvider("parent-tenant", isEnabled: true);
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { provider });

        var user = CreateUser("testuser");
        SetupTenantWithUser("parent-tenant", user);
        SetupTenantWithNoProviders("parent-tenant");

        _passwordHasher.VerifyHashedPassword(user, Arg.Any<string>(), "wrongpass")
            .Returns(PasswordVerificationResult.Failed);

        // Act
        var result = await _sut.AuthenticateAsync("child-tenant", "testuser", "wrongpass");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task Authenticate_WithLockedOutUser_ReturnsNull()
    {
        // Arrange
        var provider = CreateTenantProvider("parent-tenant", isEnabled: true);
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { provider });

        var user = CreateUser("testuser");
        user.LockoutEnabled = true;
        user.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1);

        SetupTenantWithUser("parent-tenant", user);
        SetupTenantWithNoProviders("parent-tenant");

        _passwordHasher.VerifyHashedPassword(user, Arg.Any<string>(), "pass")
            .Returns(PasswordVerificationResult.Success);

        // Act
        var result = await _sut.AuthenticateAsync("child-tenant", "testuser", "pass");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task Authenticate_WalksHierarchyUpToGrandparent()
    {
        // Arrange: child -> parent -> grandparent (user is in grandparent)
        var childProvider = CreateTenantProvider("parent-tenant", isEnabled: true);
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { childProvider });

        // Parent tenant has no user but has a provider pointing to grandparent
        SetupTenantWithNoUser("parent-tenant");
        var parentProvider = CreateTenantProvider("grandparent-tenant", isEnabled: true);
        SetupTenantWithProviders("parent-tenant", [parentProvider]);

        // Grandparent has the user
        var user = CreateUser("granduser");
        user.FirstName = "Grand";
        user.LastName = "User";
        SetupTenantWithUser("grandparent-tenant", user);
        SetupTenantWithNoProviders("grandparent-tenant");

        _passwordHasher.VerifyHashedPassword(user, Arg.Any<string>(), "pass")
            .Returns(PasswordVerificationResult.Success);

        // Act
        var result = await _sut.AuthenticateAsync("child-tenant", "granduser", "pass");

        // Assert
        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be("grandparent-tenant");
        result.SourceUserId.Should().Be(user.RtId.ToString());
        result.FirstName.Should().Be("Grand");
        result.LastName.Should().Be("User");
    }

    [Fact]
    public async Task Authenticate_StopsAtFirstMatch()
    {
        // Arrange: child -> parent (user exists in parent, also in grandparent)
        var childProvider = CreateTenantProvider("parent-tenant", isEnabled: true);
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { childProvider });

        var parentUser = CreateUser("shareduser");
        SetupTenantWithUser("parent-tenant", parentUser);

        // Even though parent has a provider to grandparent, we should stop at parent
        var parentProvider = CreateTenantProvider("grandparent-tenant", isEnabled: true);
        SetupTenantWithProviders("parent-tenant", [parentProvider]);

        _passwordHasher.VerifyHashedPassword(parentUser, Arg.Any<string>(), "pass")
            .Returns(PasswordVerificationResult.Success);

        // Act
        var result = await _sut.AuthenticateAsync("child-tenant", "shareduser", "pass");

        // Assert
        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be("parent-tenant");
        result.SourceUserId.Should().Be(parentUser.RtId.ToString());
    }

    [Fact]
    public async Task Authenticate_WithCircularHierarchy_DoesNotInfiniteLoop()
    {
        // Arrange: child -> A -> B -> A (circular)
        var childProvider = CreateTenantProvider("tenant-a", isEnabled: true);
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { childProvider });

        SetupTenantWithNoUser("tenant-a");
        var providerToB = CreateTenantProvider("tenant-b", isEnabled: true);
        SetupTenantWithProviders("tenant-a", [providerToB]);

        SetupTenantWithNoUser("tenant-b");
        var providerToA = CreateTenantProvider("tenant-a", isEnabled: true);
        SetupTenantWithProviders("tenant-b", [providerToA]);

        // Act
        var result = await _sut.AuthenticateAsync("child-tenant", "user", "pass");

        // Assert - should return null without hanging
        result.Should().BeNull();
    }

    [Fact]
    public async Task ValidateCrossTenantAccess_WithAncestorTenant_Succeeds()
    {
        // Arrange: target -> parent (parent = source)
        SetupTenantWithProviders("target-tenant",
            [CreateTenantProvider("source-tenant", isEnabled: true)]);

        var user = CreateUser("testuser");
        SetupTenantWithUser("source-tenant", user);

        // Act
        var result = await _sut.ValidateCrossTenantAccessAsync(
            "target-tenant", "source-tenant", user.RtId.ToString());

        // Assert
        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be("source-tenant");
        result.SourceUserId.Should().Be(user.RtId.ToString());
    }

    [Fact]
    public async Task ValidateCrossTenantAccess_WithSiblingTenant_Fails()
    {
        // Arrange: target -> parent, source is a sibling (not an ancestor)
        SetupTenantWithProviders("target-tenant",
            [CreateTenantProvider("parent-tenant", isEnabled: true)]);
        SetupTenantWithNoProviders("parent-tenant");

        // Act
        var result = await _sut.ValidateCrossTenantAccessAsync(
            "target-tenant", "sibling-tenant", Guid.NewGuid().ToString("N"));

        // Assert
        result.Should().BeNull();
    }

    #region Helper Methods

    private static RtOctoTenantIdentityProvider CreateTenantProvider(
        string parentTenantId, bool isEnabled)
    {
        return new RtOctoTenantIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = $"Provider_{parentTenantId}",
            IsEnabled = isEnabled,
            ParentTenantId = parentTenantId
        };
    }

    private static RtUser CreateUser(string userName)
    {
        return new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            PasswordHash = "hashed-password",
            SecurityStamp = Guid.NewGuid().ToString()
        };
    }

    private void SetupTenantWithUser(string tenantId, RtUser user)
    {
        var tenantRepo = Substitute.For<ITenantRepository>();
        var session = Substitute.For<IOctoSession>();
        tenantRepo.GetSessionAsync().Returns(session);

        var queryResult = Substitute.For<IResultSet<RtUser>>();
        queryResult.Items.Returns(new[] { user });

        tenantRepo.GetRtEntitiesByTypeAsync<RtUser>(session, Arg.Any<RtEntityQueryOptions>())
            .Returns(queryResult);

        // For FindUserByIdInTenantAsync
        tenantRepo.GetRtEntityByRtIdAsync<RtUser>(session, user.RtId)
            .Returns(user);

        _systemContext.FindTenantRepositoryAsync(tenantId).Returns(tenantRepo);
    }

    private void SetupTenantWithNoUser(string tenantId)
    {
        var tenantRepo = Substitute.For<ITenantRepository>();
        var session = Substitute.For<IOctoSession>();
        tenantRepo.GetSessionAsync().Returns(session);

        var queryResult = Substitute.For<IResultSet<RtUser>>();
        queryResult.Items.Returns(Array.Empty<RtUser>());

        tenantRepo.GetRtEntitiesByTypeAsync<RtUser>(session, Arg.Any<RtEntityQueryOptions>())
            .Returns(queryResult);

        _systemContext.FindTenantRepositoryAsync(tenantId).Returns(tenantRepo);
    }

    private void SetupTenantWithProviders(string tenantId,
        RtOctoTenantIdentityProvider[] providers)
    {
        var tenantRepo = Substitute.For<ITenantRepository>();
        var session = Substitute.For<IOctoSession>();
        tenantRepo.GetSessionAsync().Returns(session);

        var providerResult = Substitute.For<IResultSet<RtOctoTenantIdentityProvider>>();
        providerResult.Items.Returns(providers);

        tenantRepo.GetRtEntitiesByTypeAsync<RtOctoTenantIdentityProvider>(
                session, Arg.Any<RtEntityQueryOptions>())
            .Returns(providerResult);

        // If user setup hasn't been done for this tenant, set up empty user results too
        var existingRepo = _systemContext.FindTenantRepositoryAsync(tenantId)
            .GetAwaiter().GetResult();
        if (existingRepo != null)
        {
            // Tenant repo already set up (e.g., by SetupTenantWithUser) — add provider query to it
            existingRepo.GetRtEntitiesByTypeAsync<RtOctoTenantIdentityProvider>(
                    Arg.Any<IOctoSession>(), Arg.Any<RtEntityQueryOptions>())
                .Returns(providerResult);
        }
        else
        {
            var userResult = Substitute.For<IResultSet<RtUser>>();
            userResult.Items.Returns(Array.Empty<RtUser>());
            tenantRepo.GetRtEntitiesByTypeAsync<RtUser>(session, Arg.Any<RtEntityQueryOptions>())
                .Returns(userResult);

            _systemContext.FindTenantRepositoryAsync(tenantId).Returns(tenantRepo);
        }
    }

    private void SetupTenantWithNoProviders(string tenantId)
    {
        SetupTenantWithProviders(tenantId, []);
    }

    #endregion
}
