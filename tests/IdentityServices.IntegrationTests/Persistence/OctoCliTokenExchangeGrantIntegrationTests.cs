using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.ClientGrants;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#6839: existing tenants get the token-exchange grant on the <c>octo-cli</c> client although the blueprint
///     import cannot change the tenant-owned <c>AllowedGrantTypes</c> — against a real MongoDB (Testcontainers).
///     Each test uses its own child tenant. The fixture registers no blueprint catalog, so the clients are inserted
///     in-test in the shape a tenant provisioned before blueprint 1.8.0 holds them.
/// </summary>
[Collection("Sequential")]
public class OctoCliTokenExchangeGrantIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private const string DeviceCode = "urn:ietf:params:oauth:grant-type:device_code";
    private const string TokenExchange = OctoCliTokenExchangeGrant.TokenExchangeGrantType;

    private readonly IdentityServicesFixture _fixture;

    public OctoCliTokenExchangeGrantIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task ExistingClientWithOnlyDeviceCode_GetsTheGrant_AndNothingElseChanges()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        var octoCli = await InsertClientAsync(repo, "octo-cli", DeviceCode);

        var result = await OctoCliTokenExchangeGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        result.Status.Should().Be(OctoCliTokenExchangeGrantStatus.Added);
        result.ClientsUpdated.Should().Be(1);
        var after = await GetClientAsync(repo, octoCli);
        after.AllowedGrantTypes.Should().Equal(DeviceCode, TokenExchange);
        after.AllowedScopes.Should().Equal("openid", "octo_api");
        after.ClientName.Should().Be("octo-cli client");
        after.RequireClientSecret.Should().BeFalse();
        after.Enabled.Should().BeTrue();
        after.AutoProvisionInChildTenants.Should().BeTrue();
    }

    [Fact]
    public async Task OtherClients_AreNeverTouched()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertClientAsync(repo, "octo-cli", DeviceCode);
        var other = await InsertClientAsync(repo, "octo-studio", "authorization_code");
        var lookalike = await InsertClientAsync(repo, "octo-cli-2", DeviceCode);

        await OctoCliTokenExchangeGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        (await GetClientAsync(repo, other)).AllowedGrantTypes.Should().Equal("authorization_code");
        (await GetClientAsync(repo, lookalike)).AllowedGrantTypes.Should().Equal(DeviceCode);
    }

    [Fact]
    public async Task SecondRun_IsANoOp_ViaTheMarker()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        var octoCli = await InsertClientAsync(repo, "octo-cli", DeviceCode);

        await OctoCliTokenExchangeGrant.EnsureAsync(tenantContext, NullLogger.Instance);
        var second = await OctoCliTokenExchangeGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        second.Status.Should().Be(OctoCliTokenExchangeGrantStatus.AlreadyDone);
        (await GetClientAsync(repo, octoCli)).AllowedGrantTypes.Should().Equal(DeviceCode, TokenExchange);

        // An administrator removes the grant on purpose — the next setup must not bring it back.
        await SetGrantsAsync(repo, octoCli, DeviceCode);
        var third = await OctoCliTokenExchangeGrant.EnsureAsync(tenantContext, NullLogger.Instance);
        third.Status.Should().Be(OctoCliTokenExchangeGrantStatus.AlreadyDone);
        (await GetClientAsync(repo, octoCli)).AllowedGrantTypes.Should().Equal(DeviceCode);
    }

    [Fact]
    public async Task ClientAlreadyHasTheGrant_NothingIsWritten_ButTheRunIsRecorded()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        var octoCli = await InsertClientAsync(repo, "octo-cli", DeviceCode, TokenExchange);

        var result = await OctoCliTokenExchangeGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        result.Status.Should().Be(OctoCliTokenExchangeGrantStatus.AlreadyPresent);
        result.ClientsUpdated.Should().Be(0);
        (await GetClientAsync(repo, octoCli)).AllowedGrantTypes.Should().Equal(DeviceCode, TokenExchange);
        using var session = await tenantContext.GetAdminSessionAsync();
        var marker = await tenantContext.GetConfigurationAsync<OctoCliTokenExchangeGrantMarker>(
            session, IdentityServiceConstants.OctoCliTokenExchangeGrantKey, defaultValue: null);
        marker.Should().NotBeNull();
        marker!.GrantAdded.Should().BeFalse();
    }

    [Fact]
    public async Task ClientMissing_IsNoError_RecordsNoMarker_AndAddsTheGrantOnceTheClientExists()
    {
        var (tenantContext, repo) = await CreateTenantAsync();

        var first = await OctoCliTokenExchangeGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        first.Status.Should().Be(OctoCliTokenExchangeGrantStatus.ClientMissing);
        var octoCli = await InsertClientAsync(repo, "octo-cli", DeviceCode);
        var second = await OctoCliTokenExchangeGrant.EnsureAsync(tenantContext, NullLogger.Instance);
        second.Status.Should().Be(OctoCliTokenExchangeGrantStatus.Added);
        (await GetClientAsync(repo, octoCli)).AllowedGrantTypes.Should().Equal(DeviceCode, TokenExchange);
    }

    [Fact]
    public async Task TenantSetup_OnAnExistingTenant_AddsTheGrant()
    {
        var (_, repo) = await CreateTenantAsync();
        var tenantId = repo.TenantId;
        var octoCli = await InsertClientAsync(repo, "octo-cli", DeviceCode);

        // The same entry point identity runs for every tenant at startup (after the blueprint apply).
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantId);

        (await GetClientAsync(repo, octoCli)).AllowedGrantTypes.Should().Equal(DeviceCode, TokenExchange);
    }

    private async Task<(ITenantContext TenantContext, ITenantRepository Repo)> CreateTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"ocgrant-{Guid.NewGuid():N}"[..24];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        await setup.SetupAsync(tenantId);
        var tenantContext = await systemContext.GetChildTenantContextAsync(tenantId);
        return (tenantContext, tenantContext.GetTenantRepositoryAsAdmin());
    }

    private static async Task<OctoObjectId> InsertClientAsync(
        ITenantRepository repo, string clientId, params string[] grants)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = rtId,
            Enabled = true,
            ClientId = clientId,
            ClientName = $"{clientId} client",
            ProtocolType = "oidc",
            RequireClientSecret = false,
            AllowedGrantTypes = new AttributeStringValueList(grants.ToList()),
            AllowedScopes = new AttributeStringValueList { "openid", "octo_api" },
            AutoProvisionInChildTenants = clientId == "octo-cli"
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task SetGrantsAsync(ITenantRepository repo, OctoObjectId rtId, params string[] grants)
    {
        var client = await GetClientAsync(repo, rtId);
        client.AllowedGrantTypes = new AttributeStringValueList(grants.ToList());
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.ReplaceOneRtEntityByIdAsync(session, rtId, client);
        await session.CommitTransactionAsync();
    }

    private static async Task<RtClient> GetClientAsync(ITenantRepository repo, OctoObjectId rtId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var client = await repo.GetRtEntityByRtIdAsync<RtClient>(session, rtId);
        await session.CommitTransactionAsync();
        return client!;
    }
}
