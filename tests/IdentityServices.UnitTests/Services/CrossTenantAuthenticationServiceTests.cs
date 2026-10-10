using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Memory;
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
    private readonly List<OctoTenant> _registeredTenants = [];
    private readonly Dictionary<string, ITenantRepository> _repositories = new();

    public CrossTenantAuthenticationServiceTests()
    {
        _systemContext = Substitute.For<ISystemContext>();
        _systemContext.TenantId.Returns("octosystem");
        _systemContext.DatabaseName.Returns("db-octosystem");
        // The tenant registry the service resolves repositories from (AB#6393): tenants are registered by
        // the Setup* helpers; everything else is unknown to the registry and must fail closed.
        var registry = Substitute.For<IResultSet<OctoTenant>>();
        registry.Items.Returns(_ => _registeredTenants.ToArray());
        _systemContext.GetAdminSessionAsync().Returns(Substitute.For<IOctoAdminSession>());
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>())
            .Returns(registry);
        _identityProviderStore = Substitute.For<IOctoIdentityProviderStore>();
        _passwordHasher = Substitute.For<IPasswordHasher<RtUser>>();
        _logger = Substitute.For<ILogger<CrossTenantAuthenticationService>>();

        _sut = new CrossTenantAuthenticationService(
            new TenantRegistry(_systemContext, new MemoryCache(new MemoryCacheOptions())),
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

    [Fact]
    public async Task ValidateCrossTenantAccess_WithAncestorBehindAnotherProvider_Succeeds()
    {
        // Arrange: the target has TWO enabled providers and the one naming the source is enumerated
        // SECOND. The walk used to descend into the first branch and abandon its siblings, so the
        // real parent was never seen and access was denied by enumeration order alone (AB#4960).
        SetupTenantWithProviders("target-tenant",
        [
            CreateTenantProvider("unrelated-tenant", isEnabled: true),
            CreateTenantProvider("source-tenant", isEnabled: true)
        ]);
        SetupTenantWithNoProviders("unrelated-tenant");

        var user = CreateUser("testuser");
        SetupTenantWithUser("source-tenant", user);

        // Act
        var result = await _sut.ValidateCrossTenantAccessAsync(
            "target-tenant", "source-tenant", user.RtId.ToString());

        // Assert
        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be("source-tenant");
    }

    [Fact]
    public async Task ValidateCrossTenantAccess_WithAncestorTransitivelyBehindAnotherProvider_Succeeds()
    {
        // Arrange: target -> [dead-end, mid] and mid -> source, so the ancestor sits two levels up on
        // the branch that is NOT enumerated first.
        SetupTenantWithProviders("target-tenant",
        [
            CreateTenantProvider("dead-end-tenant", isEnabled: true),
            CreateTenantProvider("mid-tenant", isEnabled: true)
        ]);
        SetupTenantWithNoProviders("dead-end-tenant");
        SetupTenantWithProviders("mid-tenant",
            [CreateTenantProvider("source-tenant", isEnabled: true)]);

        var user = CreateUser("testuser");
        SetupTenantWithUser("source-tenant", user);

        // Act
        var result = await _sut.ValidateCrossTenantAccessAsync(
            "target-tenant", "source-tenant", user.RtId.ToString());

        // Assert
        result.Should().NotBeNull();
    }

    [Fact]
    public async Task ValidateCrossTenantAccess_WithConvergingProviders_StillResolvesAncestor()
    {
        // Arrange: target -> [mid-a, mid-b] and both -> shared-root -> source. Two branches converging
        // on one tenant is normal in a graph; the duplicate must be skipped without aborting the walk.
        SetupTenantWithProviders("target-tenant",
        [
            CreateTenantProvider("mid-a", isEnabled: true),
            CreateTenantProvider("mid-b", isEnabled: true)
        ]);
        SetupTenantWithProviders("mid-a", [CreateTenantProvider("shared-root", isEnabled: true)]);
        SetupTenantWithProviders("mid-b", [CreateTenantProvider("shared-root", isEnabled: true)]);
        SetupTenantWithProviders("shared-root",
            [CreateTenantProvider("source-tenant", isEnabled: true)]);

        var user = CreateUser("testuser");
        SetupTenantWithUser("source-tenant", user);

        // Act
        var result = await _sut.ValidateCrossTenantAccessAsync(
            "target-tenant", "source-tenant", user.RtId.ToString());

        // Assert
        result.Should().NotBeNull();
    }

    [Fact]
    public async Task ValidateCrossTenantAccess_WithDisabledProviderToSource_Fails()
    {
        // Arrange: the only provider naming the source is disabled. Considering every provider on a
        // level must not soften the IsEnabled gate.
        SetupTenantWithProviders("target-tenant",
        [
            CreateTenantProvider("unrelated-tenant", isEnabled: true),
            CreateTenantProvider("source-tenant", isEnabled: false)
        ]);
        SetupTenantWithNoProviders("unrelated-tenant");

        // Act
        var result = await _sut.ValidateCrossTenantAccessAsync(
            "target-tenant", "source-tenant", Guid.NewGuid().ToString("N"));

        // Assert
        result.Should().BeNull();
    }

    // ---------- AB#6393: lightweight repository access, fail closed ----------

    [Fact]
    public async Task ValidateCrossTenantAccess_NeverUsesTheHeavyTenantResolution()
    {
        SetupTenantWithProviders("target-tenant",
            [CreateTenantProvider("source-tenant", isEnabled: true)]);
        var user = CreateUser("testuser");
        SetupTenantWithUser("source-tenant", user);

        var result = await _sut.ValidateCrossTenantAccessAsync(
            "target-tenant", "source-tenant", user.RtId.ToString());

        result.Should().NotBeNull();
        // No existence probe, admin session or CK auto-import per lookup: only the cached registry entry.
        await _systemContext.DidNotReceiveWithAnyArgs().FindTenantRepositoryAsync(default!);
        await _systemContext.DidNotReceiveWithAnyArgs().TryFindTenantRepositoryAsync(default!);
        await _systemContext.DidNotReceiveWithAnyArgs().TryFindTenantContextAsync(default!);
        await _systemContext.DidNotReceive().IsSystemTenantExistingAsync();
    }

    [Fact]
    public async Task ValidateCrossTenantAccess_ReadsTheRegistryOnceForTheWholeWalk()
    {
        SetupTenantWithProviders("target-tenant", [CreateTenantProvider("mid-tenant", isEnabled: true)]);
        SetupTenantWithProviders("mid-tenant", [CreateTenantProvider("source-tenant", isEnabled: true)]);
        var user = CreateUser("testuser");
        SetupTenantWithUser("source-tenant", user);

        await _sut.ValidateCrossTenantAccessAsync("target-tenant", "source-tenant", user.RtId.ToString());

        await _systemContext.Received(1).GetAllTenantsAsync(
            Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>());
    }

    [Fact]
    public async Task ValidateCrossTenantAccess_WithAncestorMissingFromTheRegistry_Fails()
    {
        // The identity provider names "ghost-tenant" as parent, but the registry does not know it: there is
        // no repository to open, so the ancestor proof and the user lookup both fail closed.
        SetupTenantWithProviders("target-tenant",
            [CreateTenantProvider("ghost-tenant", isEnabled: true)]);

        var result = await _sut.ValidateCrossTenantAccessAsync(
            "target-tenant", "ghost-tenant", Guid.NewGuid().ToString("N"));

        result.Should().BeNull();
        _systemContext.DidNotReceive().GetRegisteredTenantRepository(
            Arg.Is<OctoTenant>(t => t.TenantId == "ghost-tenant"));
    }

    [Fact]
    public async Task ValidateCrossTenantAccess_WithTargetMissingFromTheRegistry_Fails()
    {
        var user = CreateUser("testuser");
        SetupTenantWithUser("source-tenant", user);

        var result = await _sut.ValidateCrossTenantAccessAsync(
            "ghost-tenant", "source-tenant", user.RtId.ToString());

        result.Should().BeNull();
    }

    [Fact]
    public async Task Authenticate_WithParentMissingFromTheRegistry_ReturnsNull()
    {
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { CreateTenantProvider("ghost-tenant", isEnabled: true) });

        var result = await _sut.AuthenticateAsync("child-tenant", "user", "pass");

        result.Should().BeNull();
        _passwordHasher.DidNotReceiveWithAnyArgs().VerifyHashedPassword(default!, default!, default!);
    }

    [Fact]
    public async Task UserLookups_InTenantMissingFromTheRegistry_ReturnNull()
    {
        (await _sut.FindUserIdByNameInTenantAsync("ghost-tenant", "user")).Should().BeNull();
        (await _sut.FindUserNameByIdInTenantAsync("ghost-tenant", Guid.NewGuid().ToString("N"))).Should().BeNull();
    }

    [Fact]
    public async Task UserLookups_InRegisteredTenant_ResolveTheUser()
    {
        var user = CreateUser("testuser");
        SetupTenantWithUser("source-tenant", user);

        (await _sut.FindUserIdByNameInTenantAsync("source-tenant", "testuser")).Should().Be(user.RtId.ToString());
        (await _sut.FindUserNameByIdInTenantAsync("source-tenant", user.RtId.ToString())).Should().Be("testuser");
    }

    [Fact]
    public async Task ValidateCrossTenantAccess_WithSystemTenantAsAncestor_Succeeds()
    {
        // The system tenant is not a registry entry; its database name comes from the system context.
        SetupTenantWithProviders("target-tenant",
            [CreateTenantProvider("octosystem", isEnabled: true)]);
        var user = CreateUser("admin");
        SetupTenantWithUser("octosystem", user);

        var result = await _sut.ValidateCrossTenantAccessAsync(
            "target-tenant", "octosystem", user.RtId.ToString());

        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be("octosystem");
    }

    [Fact]
    public async Task ValidateCrossTenantAccess_WhenTheRegistryCannotBeRead_FailsClosed()
    {
        SetupTenantWithProviders("target-tenant",
            [CreateTenantProvider("source-tenant", isEnabled: true)]);
        var user = CreateUser("testuser");
        SetupTenantWithUser("source-tenant", user);
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>())
            .Returns<IResultSet<OctoTenant>>(_ => throw new InvalidOperationException("db down"));

        var result = await _sut.ValidateCrossTenantAccessAsync(
            "target-tenant", "source-tenant", user.RtId.ToString());

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

        RegisterTenant(tenantId, tenantRepo);
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

        RegisterTenant(tenantId, tenantRepo);
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
        if (_repositories.TryGetValue(tenantId, out var existingRepo))
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

            RegisterTenant(tenantId, tenantRepo);
        }
    }

    /// <summary>Registers the tenant in the registry and makes its repository available without I/O.</summary>
    private void RegisterTenant(string tenantId, ITenantRepository repository)
    {
        _repositories[tenantId] = repository;
        var tenant = tenantId == "octosystem"
            ? new OctoTenant("octosystem", "db-octosystem")
            : new OctoTenant(tenantId, "db-" + tenantId);
        if (tenantId != "octosystem" && _registeredTenants.All(t => t.TenantId != tenantId))
        {
            _registeredTenants.Add(tenant);
        }

        _systemContext.GetRegisteredTenantRepository(
                Arg.Is<OctoTenant>(t => t.TenantId == tenantId && t.DatabaseName == "db-" + tenantId))
            .Returns(repository);
    }

    private void SetupTenantWithNoProviders(string tenantId)
    {
        SetupTenantWithProviders(tenantId, []);
    }

    #endregion
}
