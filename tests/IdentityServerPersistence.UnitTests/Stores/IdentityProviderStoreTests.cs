using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Stores;

// Pins the secret-preservation contract that backs the Refinery Studio edit flow (ADO #4199):
// the Studio form omits ClientSecret when the user does not re-enter it ("Secret is stored
// encrypted on the server. SET NEW SECRET") — without preservation StoreAsync would overwrite
// the stored secret with null on every edit.
public class IdentityProviderStoreTests
{
    private readonly ITenantRepository _tenantRepository;
    private readonly IdentityProviderStore _sut;
    private readonly FakeOctoSession _session;

    public IdentityProviderStoreTests()
    {
        var multiTenancyResolver = Substitute.For<IMultiTenancyResolverService>();
        _session = new FakeOctoSession();

        _tenantRepository = Substitute.For<ITenantRepository>();
        _tenantRepository.TenantId.Returns("test-tenant");
        _tenantRepository.GetSessionAsync()
            .Returns(Task.FromResult<IOctoSession>(_session));

        multiTenancyResolver.GetTenantRepository().Returns(_tenantRepository);

        _sut = new IdentityProviderStore(multiTenancyResolver);
    }

    [Fact]
    public async Task StoreAsync_NewGoogleProvider_InsertsAsIs()
    {
        var rtId = OctoObjectId.GenerateNewId();
        var incoming = new RtGoogleIdentityProvider
        {
            RtId = rtId, Name = "Google", ClientId = "cid", ClientSecret = "fresh-secret"
        };
        _tenantRepository.GetRtEntityByRtIdAsync<RtIdentityProvider>(_session, rtId)
            .Returns(Task.FromResult<RtIdentityProvider?>(null));

        await _sut.StoreAsync(incoming);

        await _tenantRepository.Received(1).InsertOneRtEntityAsync(_session, incoming);
        await _tenantRepository.DidNotReceive()
            .ReplaceOneRtEntityByIdAsync(Arg.Any<IOctoSession>(), Arg.Any<OctoObjectId>(),
                Arg.Any<RtIdentityProvider>());
        incoming.ClientSecret.Should().Be("fresh-secret");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task StoreAsync_UpdateGoogleProvider_OmittedSecret_PreservesExisting(string? omitted)
    {
        var rtId = OctoObjectId.GenerateNewId();
        var existing = new RtGoogleIdentityProvider
        {
            RtId = rtId, Name = "Google", ClientId = "cid", ClientSecret = "kept-secret"
        };
        var incoming = new RtGoogleIdentityProvider
        {
            RtId = rtId, Name = "Google (renamed)", ClientId = "cid", ClientSecret = omitted!
        };
        _tenantRepository.GetRtEntityByRtIdAsync<RtIdentityProvider>(_session, rtId)
            .Returns(Task.FromResult<RtIdentityProvider?>(existing));

        await _sut.StoreAsync(incoming);

        incoming.ClientSecret.Should().Be("kept-secret",
            "an omitted secret on PUT must inherit the value stored on the server");
        await _tenantRepository.Received(1)
            .ReplaceOneRtEntityByIdAsync(_session, rtId, incoming);
    }

    [Fact]
    public async Task StoreAsync_UpdateGoogleProvider_NewSecret_OverwritesExisting()
    {
        var rtId = OctoObjectId.GenerateNewId();
        var existing = new RtGoogleIdentityProvider
        {
            RtId = rtId, Name = "Google", ClientSecret = "old-secret"
        };
        var incoming = new RtGoogleIdentityProvider
        {
            RtId = rtId, Name = "Google", ClientSecret = "new-secret"
        };
        _tenantRepository.GetRtEntityByRtIdAsync<RtIdentityProvider>(_session, rtId)
            .Returns(Task.FromResult<RtIdentityProvider?>(existing));

        await _sut.StoreAsync(incoming);

        incoming.ClientSecret.Should().Be("new-secret",
            "an explicit new secret on PUT must overwrite the stored value");
    }

    [Fact]
    public async Task StoreAsync_UpdateMicrosoftProvider_OmittedSecret_PreservesExisting()
    {
        var rtId = OctoObjectId.GenerateNewId();
        var existing = new RtMicrosoftIdentityProvider { RtId = rtId, ClientSecret = "ms-kept" };
        var incoming = new RtMicrosoftIdentityProvider { RtId = rtId, ClientSecret = null! };
        _tenantRepository.GetRtEntityByRtIdAsync<RtIdentityProvider>(_session, rtId)
            .Returns(Task.FromResult<RtIdentityProvider?>(existing));

        await _sut.StoreAsync(incoming);

        incoming.ClientSecret.Should().Be("ms-kept");
    }

    [Fact]
    public async Task StoreAsync_UpdateFacebookProvider_OmittedSecret_PreservesExisting()
    {
        var rtId = OctoObjectId.GenerateNewId();
        var existing = new RtFacebookIdentityProvider { RtId = rtId, ClientSecret = "fb-kept" };
        var incoming = new RtFacebookIdentityProvider { RtId = rtId, ClientSecret = null! };
        _tenantRepository.GetRtEntityByRtIdAsync<RtIdentityProvider>(_session, rtId)
            .Returns(Task.FromResult<RtIdentityProvider?>(existing));

        await _sut.StoreAsync(incoming);

        incoming.ClientSecret.Should().Be("fb-kept");
    }

    [Fact]
    public async Task StoreAsync_UpdateAzureEntraIdProvider_OmittedSecret_PreservesExisting()
    {
        var rtId = OctoObjectId.GenerateNewId();
        var existing = new RtAzureEntraIdIdentityProvider { RtId = rtId, ClientSecret = "azure-kept" };
        var incoming = new RtAzureEntraIdIdentityProvider { RtId = rtId, ClientSecret = null! };
        _tenantRepository.GetRtEntityByRtIdAsync<RtIdentityProvider>(_session, rtId)
            .Returns(Task.FromResult<RtIdentityProvider?>(existing));

        await _sut.StoreAsync(incoming);

        incoming.ClientSecret.Should().Be("azure-kept");
    }
}
