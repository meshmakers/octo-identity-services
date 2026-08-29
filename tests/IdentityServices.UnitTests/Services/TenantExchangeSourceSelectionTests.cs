using Duende.IdentityServer.Stores;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#4966 — which source identity a token exchange runs from.
/// </summary>
/// <remarks>
///     The hierarchy under test mirrors the one that exposed the bug in production:
///     <c>octosystem → bernkopf → {bierok, tecob}</c>, where the bernkopf user is itself a shadow of an
///     octosystem user (<c>xt_octosystem_admin</c>). bernkopf IS an ancestor of bierok, so its own
///     mapping is the one describing this user there — rewriting to the home tenant skipped it and
///     produced a role-less token.
/// </remarks>
public class TenantExchangeSourceSelectionTests
{
    private const string Target = "bierok";
    private const string Source = "bernkopf";
    private const string Home = "octosystem";
    private const string SourceUserId = "source-user-1";
    private const string HomeUserId = "home-user-1";
    private const string ShadowUserName = "xt_octosystem_admin";

    private readonly ICrossTenantAuthenticationService _crossTenantAuth =
        Substitute.For<ICrossTenantAuthenticationService>();

    private readonly IExternalTenantUserMappingStore _mappingStore =
        Substitute.For<IExternalTenantUserMappingStore>();

    private readonly TenantExchangeGrantValidator _sut;

    public TenantExchangeSourceSelectionTests()
    {
        var options = Options.Create(new OctoIdentityServicesOptions
        {
            AuthorityUrl = "https://identity.example.com/",
            IdentityServerLicenseKey = string.Empty,
            AutoMapperLicenseKey = string.Empty
        });

        _sut = new TenantExchangeGrantValidator(
            Substitute.For<IValidationKeysStore>(),
            options,
            _crossTenantAuth,
            Substitute.For<ICrossTenantUserProvisioningService>(),
            _mappingStore,
            Substitute.For<IHttpContextAccessor>(),
            Substitute.For<Duende.IdentityServer.Services.IEventService>(),
            Substitute.For<ILogger<TenantExchangeGrantValidator>>());
    }

    private static CrossTenantAuthResult ResultFor(string tenantId, string userId) => new()
    {
        SourceTenantId = tenantId,
        SourceUserId = userId,
        SourceUserName = "whoever"
    };

    private static RtExternalTenantUserMapping Mapping() => new()
    {
        RtId = OctoObjectId.GenerateNewId()
    };

    private void GateAllows(string tenantId, string userId) =>
        _crossTenantAuth.ValidateCrossTenantAccessAsync(Target, tenantId, userId)
            .Returns(ResultFor(tenantId, userId));

    private void GateDenies(string tenantId, string userId) =>
        _crossTenantAuth.ValidateCrossTenantAccessAsync(Target, tenantId, userId)
            .Returns((CrossTenantAuthResult?)null);

    private void SourceIsShadowUser()
    {
        _crossTenantAuth.FindUserNameByIdInTenantAsync(Source, SourceUserId).Returns(ShadowUserName);
        _crossTenantAuth.FindUserIdByNameInTenantAsync(Home, "admin").Returns(HomeUserId);
    }

    [Fact]
    public async Task NestedShadowUser_WithMappingOnTheImmediateSource_ExchangesFromThatSource()
    {
        // Arrange: the source is a shadow user AND an ancestor of the target, and the target holds a
        // mapping for it. Before AB#4966 the home rewrite skipped that mapping and issued no roles.
        SourceIsShadowUser();
        GateAllows(Source, SourceUserId);
        GateAllows(Home, HomeUserId);
        _mappingStore.FindBySourceUserAsync(Source, SourceUserId).Returns(Mapping());
        _mappingStore.FindBySourceUserAsync(Home, HomeUserId).Returns((RtExternalTenantUserMapping?)null);

        // Act
        var result = await _sut.ResolveExchangeSourceAsync(Target, Source, SourceUserId);

        // Assert
        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be(Source);
        result.SourceUserId.Should().Be(SourceUserId);
    }

    [Fact]
    public async Task SiblingSource_FallsBackToTheHomeIdentity()
    {
        // Arrange: a sibling is not an ancestor, so only the home identity can reach the target.
        SourceIsShadowUser();
        GateDenies(Source, SourceUserId);
        GateAllows(Home, HomeUserId);
        _mappingStore.FindBySourceUserAsync(Home, HomeUserId).Returns(Mapping());

        // Act
        var result = await _sut.ResolveExchangeSourceAsync(Target, Source, SourceUserId);

        // Assert
        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be(Home);
        result.SourceUserId.Should().Be(HomeUserId);
    }

    [Fact]
    public async Task MappingOnlyOnTheHomeIdentity_PrefersTheHomeIdentity()
    {
        // Arrange: both candidates may reach the target, but only the home one is mapped there.
        // Preferring the immediate source blindly would regress this configuration to no roles.
        SourceIsShadowUser();
        GateAllows(Source, SourceUserId);
        GateAllows(Home, HomeUserId);
        _mappingStore.FindBySourceUserAsync(Source, SourceUserId).Returns((RtExternalTenantUserMapping?)null);
        _mappingStore.FindBySourceUserAsync(Home, HomeUserId).Returns(Mapping());

        // Act
        var result = await _sut.ResolveExchangeSourceAsync(Target, Source, SourceUserId);

        // Assert
        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be(Home);
    }

    [Fact]
    public async Task NoMappingAnywhere_StillExchangesFromAnAuthorizedCandidate()
    {
        // Arrange: nothing is mapped. The exchange should behave as before rather than be denied.
        SourceIsShadowUser();
        GateAllows(Source, SourceUserId);
        GateAllows(Home, HomeUserId);
        _mappingStore.FindBySourceUserAsync(Arg.Any<string>(), Arg.Any<string>())
            .Returns((RtExternalTenantUserMapping?)null);

        // Act
        var result = await _sut.ResolveExchangeSourceAsync(Target, Source, SourceUserId);

        // Assert
        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be(Source);
    }

    [Fact]
    public async Task DirectUser_IsNeverRewrittenToAHomeTenant()
    {
        // Arrange: a plain local user carries no xt_ prefix, so there is no home identity to consider.
        _crossTenantAuth.FindUserNameByIdInTenantAsync(Source, SourceUserId).Returns("kbernkopf");
        GateAllows(Source, SourceUserId);
        _mappingStore.FindBySourceUserAsync(Source, SourceUserId).Returns(Mapping());

        // Act
        var result = await _sut.ResolveExchangeSourceAsync(Target, Source, SourceUserId);

        // Assert
        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be(Source);
        await _crossTenantAuth.DidNotReceive().FindUserIdByNameInTenantAsync(Home, Arg.Any<string>());
    }

    [Fact]
    public async Task NoCandidateMayReachTheTarget_ReturnsNull()
    {
        // Arrange
        SourceIsShadowUser();
        GateDenies(Source, SourceUserId);
        GateDenies(Home, HomeUserId);

        // Act
        var result = await _sut.ResolveExchangeSourceAsync(Target, Source, SourceUserId);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task UnresolvableHomeIdentity_DoesNotBlockAnAuthorizedImmediateSource()
    {
        // Arrange: the shadow name points at a home user that no longer exists. That used to deny the
        // exchange outright, even when the immediate source was a perfectly good ancestor.
        _crossTenantAuth.FindUserNameByIdInTenantAsync(Source, SourceUserId).Returns(ShadowUserName);
        _crossTenantAuth.FindUserIdByNameInTenantAsync(Home, "admin").Returns((string?)null);
        GateAllows(Source, SourceUserId);
        _mappingStore.FindBySourceUserAsync(Source, SourceUserId).Returns(Mapping());

        // Act
        var result = await _sut.ResolveExchangeSourceAsync(Target, Source, SourceUserId);

        // Assert
        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be(Source);
    }
}
