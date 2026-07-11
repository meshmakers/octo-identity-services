using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.DynamicClientRegistration;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// End-to-end checks of RFC 7591 Dynamic Client Registration (AB#4338) against a real MongoDB
/// (Testcontainers) with the full Octo runtime engine. Pins the security gate, the system-tenant +
/// mirror placement, dedupe, and the per-tenant cap that Claude-Code-class interactive clients depend on.
/// </summary>
[Collection("Sequential")]
public class DynamicClientRegistrationIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public DynamicClientRegistrationIntegrationTests(
        IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task ValidLoopbackRequest_CreatesSystemTenantClient_AndMirrorsIntoChild()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"dcr-child-{Guid.NewGuid():N}"[..24]);
        var redirect = UniqueLoopback();

        var result = await service.RegisterAsync(new DynamicClientRegistrationRequest
        {
            RedirectUris = [redirect],
            ClientName = "Test MCP client"
        }, TestContext.Current.CancellationToken);

        result.Outcome.Should().Be(DynamicClientRegistrationOutcome.Created);
        result.Response.Should().NotBeNull();
        result.Response!.ClientId.Should().StartWith("octo-dcr-");
        result.Response.TokenEndpointAuthMethod.Should().Be("none");
        result.Response.Scope.Should().Contain("octo_api");
        result.Response.RedirectUris.Should().Contain(redirect);

        // Persisted in the system tenant with the dynamic markers.
        var stored = await FindSystemClientAsync(systemContext, result.Response.ClientId);
        stored.Should().NotBeNull();
        stored!.DynamicRegistration.Should().BeTrue();
        stored.DynamicRegistrationExpiresAt.Should().NotBeNull();
        stored.AutoProvisionInChildTenants.Should().BeTrue();
        stored.RequirePkce.Should().BeTrue();
        stored.RequireClientSecret.Should().BeFalse();
        stored.AllowOfflineAccess.Should().BeTrue();

        // Mirrored into the existing child tenant so it resolves wherever the user authenticates.
        (await ChildHasClientAsync(systemContext, childTenantId, result.Response.ClientId)).Should().BeTrue();
    }

    [Fact]
    public async Task NonLoopbackRedirect_IsRejected()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var result = await service.RegisterAsync(new DynamicClientRegistrationRequest
        {
            RedirectUris = ["https://evil.example.com/callback"]
        }, TestContext.Current.CancellationToken);

        result.Outcome.Should().Be(DynamicClientRegistrationOutcome.Invalid);
        result.Error!.Error.Should().Be("invalid_redirect_uri");
    }

    [Fact]
    public async Task NoRedirectUris_IsRejected()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var result = await service.RegisterAsync(
            new DynamicClientRegistrationRequest(), TestContext.Current.CancellationToken);

        result.Outcome.Should().Be(DynamicClientRegistrationOutcome.Invalid);
        result.Error!.Error.Should().Be("invalid_redirect_uri");
    }

    [Fact]
    public async Task ConfidentialAuthMethod_IsRejected()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var result = await service.RegisterAsync(new DynamicClientRegistrationRequest
        {
            RedirectUris = [UniqueLoopback()],
            TokenEndpointAuthMethod = "client_secret_basic"
        }, TestContext.Current.CancellationToken);

        result.Outcome.Should().Be(DynamicClientRegistrationOutcome.Invalid);
        result.Error!.Error.Should().Be("invalid_client_metadata");
    }

    [Fact]
    public async Task UnsupportedGrantType_IsRejected()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var result = await service.RegisterAsync(new DynamicClientRegistrationRequest
        {
            RedirectUris = [UniqueLoopback()],
            GrantTypes = ["client_credentials"]
        }, TestContext.Current.CancellationToken);

        result.Outcome.Should().Be(DynamicClientRegistrationOutcome.Invalid);
        result.Error!.Error.Should().Be("invalid_client_metadata");
    }

    [Fact]
    public async Task Disabled_ReturnsDisabled()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext, enabled: false);

        var result = await service.RegisterAsync(new DynamicClientRegistrationRequest
        {
            RedirectUris = [UniqueLoopback()]
        }, TestContext.Current.CancellationToken);

        result.Outcome.Should().Be(DynamicClientRegistrationOutcome.Disabled);
    }

    [Fact]
    public async Task IdenticalRedirectSet_IsDeduped_ReturnsExistingClient()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var redirect = UniqueLoopback();

        var first = await service.RegisterAsync(new DynamicClientRegistrationRequest { RedirectUris = [redirect] },
            TestContext.Current.CancellationToken);
        var second = await service.RegisterAsync(new DynamicClientRegistrationRequest { RedirectUris = [redirect] },
            TestContext.Current.CancellationToken);

        first.Outcome.Should().Be(DynamicClientRegistrationOutcome.Created);
        second.Outcome.Should().Be(DynamicClientRegistrationOutcome.ReturnedExisting);
        second.Response!.ClientId.Should().Be(first.Response!.ClientId);
    }

    [Fact]
    public async Task PerTenantCap_Reached_RefusesRegistration()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        // Robust to accumulation from other tests: pin the cap at the current live count so any fresh
        // (non-deduped) registration is over the limit.
        var currentCount = await CountSystemDynamicClientsAsync(systemContext);
        var service = CreateService(systemContext, maxClientsPerTenant: currentCount);

        var result = await service.RegisterAsync(new DynamicClientRegistrationRequest
        {
            RedirectUris = [UniqueLoopback()]
        }, TestContext.Current.CancellationToken);

        result.Outcome.Should().Be(DynamicClientRegistrationOutcome.CapExceeded);
    }

    // ---- helpers -----------------------------------------------------------------------------

    private static IDynamicClientRegistrationService CreateService(
        ISystemContext systemContext, bool enabled = true, int maxClientsPerTenant = 100, int ttlDays = 90)
    {
        var mirror = new ClientMirrorProvisioningService(
            NullLogger<ClientMirrorProvisioningService>.Instance, systemContext);
        var options = Options.Create(new OctoIdentityServicesOptions
        {
            IdentityServerLicenseKey = "test",
            AutoMapperLicenseKey = "test",
            DynamicClientRegistration = new DynamicClientRegistrationOptions
            {
                Enabled = enabled,
                MaxClientsPerTenant = maxClientsPerTenant,
                ClientTtlDays = ttlDays
            }
        });
        return new DynamicClientRegistrationService(
            systemContext, mirror, options, NullLogger<DynamicClientRegistrationService>.Instance);
    }

    private static string UniqueLoopback() => $"http://127.0.0.1:8976/callback-{Guid.NewGuid():N}";

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);
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

    private static async Task<RtClient?> FindSystemClientAsync(ISystemContext systemContext, string clientId)
    {
        var repo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        var result = await repo.GetRtEntitiesByTypeAsync<RtClient>(session,
            RtEntityQueryOptions.Create().FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.FirstOrDefault();
    }

    private static async Task<int> CountSystemDynamicClientsAsync(ISystemContext systemContext)
    {
        var repo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        var result = await repo.GetRtEntitiesByTypeAsync<RtClient>(session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.DynamicRegistration), FieldFilterOperator.Equals, true));
        var now = DateTime.UtcNow;
        return result.Items.Count(c =>
            !c.DynamicRegistrationExpiresAt.HasValue || c.DynamicRegistrationExpiresAt.Value > now);
    }

    private static async Task<bool> ChildHasClientAsync(
        ISystemContext systemContext, string childTenantId, string clientId)
    {
        var childRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        if (childRepo == null)
        {
            return false;
        }

        using var session = await childRepo.GetSessionAsync();
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(session,
            RtEntityQueryOptions.Create().FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.Any();
    }
}
