using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using AutoMapper;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     AB#5540: the identity-provider ClientSecret is a Secret attribute and write-only on the REST
///     API. No response of <see cref="IdentityProvidersController" /> may contain the secret — neither
///     the plaintext nor the stored envelope — and create/replace accept it as a string where null or
///     "" means "keep the stored secret".
/// </summary>
public class IdentityProvidersControllerSecretTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    private readonly IOctoIdentityProviderStore _store = Substitute.For<IOctoIdentityProviderStore>();
    private readonly IdentityProvidersController _sut;

    public IdentityProvidersControllerSecretTests()
    {
        var mapper = new MapperConfiguration(cfg => cfg.AddProfile<MapperProfile>(), NullLoggerFactory.Instance)
            .CreateMapper();
        _store.TenantId.Returns("test-tenant");
        _sut = new IdentityProvidersController(_store, mapper, Substitute.For<IDistributionEventHubService>());
    }

    private static RtSecretValue NewStoredEnvelope()
        => RtSecretValue.Protected("enc:v2:k1:" + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(48)));

    private static string Serialize(object? value) => JsonSerializer.Serialize(value, WebJson);

    public static TheoryData<RtIdentityProvider> StoredProvidersWithSecret()
    {
        var envelope = NewStoredEnvelope();
        var legacy = new RtAzureEntraIdIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(), Name = "Entra", TenantId = "tid", ClientId = "entra-client"
        };
        legacy.SetAttributeRawValue("ClientSecret", "legacy-clear-text-secret");
        return new TheoryData<RtIdentityProvider>
        {
            new RtGoogleIdentityProvider
                { RtId = OctoObjectId.GenerateNewId(), Name = "Google", ClientId = "g", ClientSecret = envelope },
            new RtMicrosoftIdentityProvider
                { RtId = OctoObjectId.GenerateNewId(), Name = "Microsoft", ClientId = "m", ClientSecret = envelope },
            new RtFacebookIdentityProvider
                { RtId = OctoObjectId.GenerateNewId(), Name = "Facebook", ClientId = "f", ClientSecret = envelope },
            legacy
        };
    }

    [Theory]
    [MemberData(nameof(StoredProvidersWithSecret))]
    public async Task GetAll_NeverReturnsTheSecret(RtIdentityProvider stored)
    {
        _store.GetAllAsync().Returns(new[] { stored });

        var result = await _sut.GetIdentityProvidersAsync();

        var dto = result.Value!.IdentityProviders.Should().ContainSingle().Subject;
        MapperProfile.GetClientSecretInput(dto).Should().BeNull();
        var json = Serialize(result.Value);
        json.Should().NotContain("enc:v2").And.NotContain("legacy-clear-text-secret");
    }

    [Theory]
    [MemberData(nameof(StoredProvidersWithSecret))]
    public async Task GetById_NeverReturnsTheSecret(RtIdentityProvider stored)
    {
        _store.GetByIdAsync(stored.RtId).Returns(stored);

        var result = await _sut.Get(stored.RtId);

        var dto = result.Value!.IdentityProviders.Should().ContainSingle().Subject;
        MapperProfile.GetClientSecretInput(dto).Should().BeNull();
        Serialize(result.Value).Should().NotContain("enc:v2").And.NotContain("legacy-clear-text-secret");
    }

    [Fact]
    public async Task Create_StoresPendingSecret_AndDoesNotEchoIt()
    {
        RtIdentityProvider? stored = null;
        await _store.StoreAsync(Arg.Do<RtIdentityProvider>(p => stored = p));
        var input = new GoogleIdentityProviderDto
        {
            Name = "Google", IsEnabled = true, ClientId = "google-client", ClientSecret = "write-only-secret"
        };

        var result = await _sut.AddNewIdentityProviderAsync(input);

        stored.Should().BeOfType<RtGoogleIdentityProvider>()
            .Which.ClientSecret.Should().Be(RtSecretValue.Pending("write-only-secret"));
        var response = result.Value.Should().BeOfType<GoogleIdentityProviderDto>().Subject;
        response.ClientSecret.Should().BeNull();
        response.ClientId.Should().Be("google-client");
        Serialize(result.Value).Should().NotContain("write-only-secret");
    }

    [Fact]
    public async Task Replace_WithNewSecret_DoesNotEchoTheRequest()
    {
        var rtId = OctoObjectId.GenerateNewId();
        RtIdentityProvider? stored = null;
        await _store.StoreAsync(Arg.Do<RtIdentityProvider>(p => stored = p));
        var input = new AzureEntraIdProviderDto
        {
            Name = "Entra", IsEnabled = true, TenantId = "tid", ClientId = "entra-client",
            ClientSecret = "rotated-secret"
        };

        var result = await _sut.ReplaceProviderAsync(rtId, input);

        stored!.RtId.Should().Be(rtId);
        ((RtAzureEntraIdIdentityProvider)stored).ClientSecret.Should().Be(RtSecretValue.Pending("rotated-secret"));
        var ok = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var response = ok.Value.Should().BeOfType<AzureEntraIdProviderDto>().Subject;
        response.ClientSecret.Should().BeNull();
        response.RtId.Should().Be(rtId);
        Serialize(ok.Value).Should().NotContain("rotated-secret");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Replace_WithoutSecret_LeavesTheAttributeUntouched(string? omitted)
    {
        // The attribute must be ABSENT (not an explicit null — that would clear the stored secret),
        // so the store/engine carries the stored secret over.
        RtIdentityProvider? stored = null;
        await _store.StoreAsync(Arg.Do<RtIdentityProvider>(p => stored = p));
        var input = new MicrosoftIdentityProviderDto
        {
            Name = "Microsoft", IsEnabled = true, ClientId = "ms-client", ClientSecret = omitted
        };

        await _sut.ReplaceProviderAsync(OctoObjectId.GenerateNewId(), input);

        stored.Should().NotBeNull();
        stored!.Attributes.ContainsKey("ClientSecret").Should().BeFalse();
    }

    [Theory]
    [InlineData("<google-client-secret>")]
    [InlineData("TODO_SET_GOOGLE_CLIENT_SECRET")]
    public async Task CreateAndReplace_RejectPlaceholderSecret(string placeholder)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMvcCore();
        _sut.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() }
        };
        GoogleIdentityProviderDto Input() => new()
            { Name = "Google", IsEnabled = true, ClientId = "google-client", ClientSecret = placeholder };

        var created = await _sut.AddNewIdentityProviderAsync(Input());
        _sut.ModelState.Clear();
        var replaced = await _sut.ReplaceProviderAsync(OctoObjectId.GenerateNewId(), Input());

        created.Result.Should().BeAssignableTo<ObjectResult>()
            .Which.Value.Should().BeOfType<ValidationProblemDetails>();
        replaced.Result.Should().BeAssignableTo<ObjectResult>()
            .Which.Value.Should().BeOfType<ValidationProblemDetails>();
        await _store.DidNotReceive().StoreAsync(Arg.Any<RtIdentityProvider>());
    }
}
