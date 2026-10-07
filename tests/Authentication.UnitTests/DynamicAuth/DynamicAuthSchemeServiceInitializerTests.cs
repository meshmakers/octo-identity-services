using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace Authentication.UnitTests.DynamicAuth;

/// <summary>
///     AB#5540 — on test-2 one tenant whose System.Identity CK import had failed threw
///     <see cref="CkCacheException" /> from <see cref="IDynamicAuthSchemeService.ConfigureAsync" /> during
///     startup and the unguarded initializer loop took the whole host down. One tenant must not stop
///     the others, and its schemes must be registered once its setup completes.
/// </summary>
public class DynamicAuthSchemeServiceInitializerTests
{
    private const string SystemTenantId = "octosystem";

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly IDynamicAuthSchemeService _schemeService = Substitute.For<IDynamicAuthSchemeService>();

    public DynamicAuthSchemeServiceInitializerTests()
    {
        _systemContext.TenantId.Returns(SystemTenantId);
        _systemContext.IsSystemTenantExistingAsync().Returns(true);
        _systemContext.GetAdminSessionAsync().Returns(Substitute.For<IOctoAdminSession>());

        var tenants = Substitute.For<IResultSet<OctoTenant>>();
        tenants.Items.Returns(new[]
        {
            new OctoTenant("alpha", "alpha"),
            new OctoTenant("meshtest", "meshtest"),
            new OctoTenant("omega", "omega")
        });
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>()).Returns(tenants);
    }

    [Fact]
    public async Task InitializeAsync_OneTenantFails_RemainingTenantsAreStillConfigured()
    {
        _schemeService.ConfigureAsync("meshtest").ThrowsAsync(
            new CkCacheException("RtCkTypeId 'System.Identity/IdentityProvider' not found"));
        var sut = CreateSut();

        var act = () => sut.InitializeAsync();

        await act.Should().NotThrowAsync();
        await _schemeService.Received(1).ConfigureAsync(SystemTenantId);
        await _schemeService.Received(1).ConfigureAsync("alpha");
        await _schemeService.Received(1).ConfigureAsync("meshtest");
        await _schemeService.Received(1).ConfigureAsync("omega");
    }

    [Fact]
    public async Task InitializeAsync_SystemTenantFails_StillFailsTheHostStart()
    {
        // Deliberate: without the system tenant nothing works, so its failure stays fatal (same
        // contract as DefaultConfigurationInitializationService).
        _schemeService.ConfigureAsync(SystemTenantId).ThrowsAsync(new CkCacheException("broken"));
        var sut = CreateSut();

        var act = () => sut.InitializeAsync();

        await act.Should().ThrowAsync<CkCacheException>();
        await _schemeService.DidNotReceive().ConfigureAsync("alpha");
    }

    [Fact]
    public async Task TenantSetupHandler_AfterSetupRetry_ConfiguresTheTenantsSchemes()
    {
        var handler = new DynamicAuthSchemeTenantSetupHandler(_schemeService,
            NullLogger<DynamicAuthSchemeTenantSetupHandler>.Instance);

        await handler.OnTenantSetupCompletedAsync("meshtest");

        await _schemeService.Received(1).ConfigureAsync("meshtest");
    }

    [Fact]
    public void DynamicAuthBuilder_RegistersTenantSetupHandler()
    {
        var services = new ServiceCollection();

        _ = new DynamicAuthBuilder(services);
        _ = new DynamicAuthBuilder(services); // TryAddEnumerable: registering twice must not duplicate

        services.Where(d => d.ServiceType == typeof(ITenantSetupCompletedHandler))
            .Should().ContainSingle()
            .Which.ImplementationType.Should().Be<DynamicAuthSchemeTenantSetupHandler>();
    }

    [Fact]
    public async Task ConfigureAsync_ProviderLoadFails_KeepsTheTenantsExistingSchemes()
    {
        // The providers are loaded before the old schemes are removed, so a tenant whose CK model is
        // temporarily unusable keeps the schemes it had instead of losing all of them.
        var schemeProvider = Substitute.For<IAuthenticationSchemeProvider>();
        var existing = new AuthenticationScheme("meshtest:google", "google", typeof(GoogleHandler));
        schemeProvider.GetAllSchemesAsync()
            .Returns(Task.FromResult<IEnumerable<AuthenticationScheme>>(new[] { existing }));

        var tenantRepo = Substitute.For<ITenantRepository>();
        var session = Substitute.For<IOctoSession>();
        tenantRepo.GetSessionAsync().Returns(session);
        tenantRepo.GetRtEntitiesByTypeAsync<RtIdentityProvider>(session, Arg.Any<RtEntityQueryOptions>())
            .ThrowsAsync(new CkCacheException("RtCkTypeId 'System.Identity/IdentityProvider' not found"));
        _systemContext.FindTenantRepositoryAsync("meshtest").Returns(tenantRepo);

        var sut = new DynamicAuthSchemeService(_systemContext, schemeProvider,
            Substitute.For<IAuthSchemeCreatorFactory>(), NullLogger<DynamicAuthSchemeService>.Instance);

        var act = () => sut.ConfigureAsync("meshtest");

        await act.Should().ThrowAsync<CkCacheException>();
        schemeProvider.DidNotReceive().RemoveScheme(Arg.Any<string>());
    }

    private DynamicAuthSchemeServiceInitializer CreateSut() =>
        new(_systemContext, _schemeService, NullLogger<DynamicAuthSchemeServiceInitializer>.Instance);
}
