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
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
public sealed class IdentityProvidersControllerSecretTests : IDisposable
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    private readonly IOctoIdentityProviderStore _store = Substitute.For<IOctoIdentityProviderStore>();
    private readonly ISecretAttributeProtector _protector = Substitute.For<ISecretAttributeProtector>();
    private readonly ServiceProvider _services;
    private readonly IdentityProvidersController _sut;

    public IdentityProvidersControllerSecretTests()
    {
        // The key ring of this host knows only "k1"; the protector is never asked to decrypt.
        _protector.IsKnownKeyId(Arg.Any<string?>())
            .Returns(ci => IsKnownKeyId(ci.Arg<string?>()));
        // DescribeSecret is a default interface member: forward it to the same classification the
        // real protector uses (stored form + key id only, no decrypt).
        _protector.DescribeSecret(Arg.Any<RtSecretValue?>(), Arg.Any<SecretAccessContext?>())
            .Returns(ci => SecretValueStates.Describe(ci.Arg<RtSecretValue?>(), IsKnownKeyId));
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(_protector);
        services.AddDynamicAuthentication();
        services.AddTransient<ClientSecretIsSetResolver>();
        services.AddTransient<ClientSecretKeyMissingResolver>();
        services.AddTransient<ClientSecretSetAtResolver>();
        _services = services.BuildServiceProvider();

        var mapper = new MapperConfiguration(cfg => cfg.AddProfile<MapperProfile>(), NullLoggerFactory.Instance)
            .CreateMapper(_services.GetService);
        _store.TenantId.Returns("test-tenant");
        _sut = new IdentityProvidersController(_store, mapper, Substitute.For<IDistributionEventHubService>());
    }

    public void Dispose() => _services.Dispose();

    private static bool IsKnownKeyId(string? keyId) => string.Equals(keyId, "k1", StringComparison.OrdinalIgnoreCase);

    private static bool? ClientSecretKeyMissing(IdentityProviderDto dto) => dto switch
    {
        GoogleIdentityProviderDto g => g.ClientSecretKeyMissing,
        MicrosoftIdentityProviderDto m => m.ClientSecretKeyMissing,
        FacebookIdentityProviderDto f => f.ClientSecretKeyMissing,
        AzureEntraIdProviderDto a => a.ClientSecretKeyMissing,
        _ => null
    };

    private static DateTime? ClientSecretSetAt(IdentityProviderDto dto) => dto switch
    {
        GoogleIdentityProviderDto g => g.ClientSecretSetAt,
        MicrosoftIdentityProviderDto m => m.ClientSecretSetAt,
        FacebookIdentityProviderDto f => f.ClientSecretSetAt,
        AzureEntraIdProviderDto a => a.ClientSecretSetAt,
        _ => null
    };

    private static RtSecretValue NewStoredEnvelope(string keyId = "k1")
        => RtSecretValue.Protected($"enc:v2:{keyId}:" + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(48)));

    private static string Serialize(object? value) => JsonSerializer.Serialize(value, WebJson);

    private static bool? ClientSecretIsSet(IdentityProviderDto dto) => dto switch
    {
        GoogleIdentityProviderDto g => g.ClientSecretIsSet,
        MicrosoftIdentityProviderDto m => m.ClientSecretIsSet,
        FacebookIdentityProviderDto f => f.ClientSecretIsSet,
        AzureEntraIdProviderDto a => a.ClientSecretIsSet,
        _ => null
    };

    // The write-only field may be serialized as null, but never with a value.
    private static void AssertNoClientSecretValue(string json)
        => json.Should().NotMatchRegex("\"clientSecret\"\\s*:\\s*\"");

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
        ClientSecretIsSet(dto).Should().BeTrue();
        var json = Serialize(result.Value);
        json.Should().NotContain("enc:v2").And.NotContain("legacy-clear-text-secret");
        json.Should().Contain("\"clientSecretIsSet\":true");
        AssertNoClientSecretValue(json);
    }

    [Theory]
    [MemberData(nameof(StoredProvidersWithSecret))]
    public async Task GetById_NeverReturnsTheSecret(RtIdentityProvider stored)
    {
        _store.GetByIdAsync(stored.RtId).Returns(stored);

        var result = await _sut.Get(stored.RtId);

        var dto = result.Value!.IdentityProviders.Should().ContainSingle().Subject;
        MapperProfile.GetClientSecretInput(dto).Should().BeNull();
        ClientSecretIsSet(dto).Should().BeTrue();
        var json = Serialize(result.Value);
        json.Should().NotContain("enc:v2").And.NotContain("legacy-clear-text-secret");
        json.Should().Contain("\"clientSecretIsSet\":true");
        AssertNoClientSecretValue(json);
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
        response.ClientSecretIsSet.Should().BeTrue();
        response.ClientId.Should().Be("google-client");
        var json = Serialize(result.Value);
        json.Should().NotContain("write-only-secret").And.Contain("\"clientSecretIsSet\":true");
        AssertNoClientSecretValue(json);
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
        response.ClientSecretIsSet.Should().BeTrue();
        response.RtId.Should().Be(rtId);
        var json = Serialize(ok.Value);
        json.Should().NotContain("rotated-secret").And.Contain("\"clientSecretIsSet\":true");
        AssertNoClientSecretValue(json);
    }

    public static TheoryData<RtIdentityProvider> StoredProvidersWithoutSecret()
    {
        var emptyLegacy = new RtFacebookIdentityProvider
            { RtId = OctoObjectId.GenerateNewId(), Name = "Facebook", ClientId = "f" };
        emptyLegacy.SetAttributeRawValue("ClientSecret", "");
        return new TheoryData<RtIdentityProvider>
        {
            new RtGoogleIdentityProvider { RtId = OctoObjectId.GenerateNewId(), Name = "Google", ClientId = "g" },
            new RtMicrosoftIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(), Name = "Microsoft", ClientId = "m",
                ClientSecret = RtSecretValue.Pending(string.Empty)
            },
            new RtAzureEntraIdIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(), Name = "Entra", TenantId = "tid", ClientId = "e",
                ClientSecret = RtSecretValue.LegacyPlaintext(string.Empty)
            },
            emptyLegacy
        };
    }

    [Theory]
    [MemberData(nameof(StoredProvidersWithoutSecret))]
    public async Task GetById_ReportsAMissingSecretAsNotSet(RtIdentityProvider stored)
    {
        _store.GetByIdAsync(stored.RtId).Returns(stored);

        var result = await _sut.Get(stored.RtId);

        var dto = result.Value!.IdentityProviders.Should().ContainSingle().Subject;
        ClientSecretIsSet(dto).Should().BeFalse();
        Serialize(result.Value).Should().Contain("\"clientSecretIsSet\":false");
    }

    [Fact]
    public async Task GetAll_ProviderTypesWithoutClientSecret_HaveNoIsSetFlag()
    {
        _store.GetAllAsync().Returns(new RtIdentityProvider[]
        {
            new RtOctoTenantIdentityProvider
                { RtId = OctoObjectId.GenerateNewId(), Name = "Parent", ParentTenantId = "parent" }
        });

        var result = await _sut.GetIdentityProvidersAsync();

        var json = Serialize(result.Value);
        json.Should().NotContain("clientSecretIsSet").And.NotContain("clientSecretKeyMissing")
            .And.NotContain("clientSecretSetAt");
    }

    [Fact]
    public async Task GetById_ProtectedSecret_ReportsSetAtAndNoKeyMissing()
    {
        var setAt = new DateTime(2026, 10, 6, 7, 30, 0, DateTimeKind.Utc);
        var stored = new RtMicrosoftIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(), Name = "Microsoft", ClientId = "m",
            ClientSecret = NewStoredEnvelope().WithSetAt(setAt)
        };
        _store.GetByIdAsync(stored.RtId).Returns(stored);

        var result = await _sut.Get(stored.RtId);

        var dto = result.Value!.IdentityProviders.Should().ContainSingle().Subject;
        ClientSecretIsSet(dto).Should().BeTrue();
        ClientSecretKeyMissing(dto).Should().BeFalse();
        ClientSecretSetAt(dto).Should().Be(setAt);
        Serialize(result.Value).Should().Contain("\"clientSecretSetAt\":\"2026-10-06T07:30:00Z\"");
        _protector.DidNotReceiveWithAnyArgs().Unprotect(default(RtSecretValue)!, default);
    }

    [Fact]
    public async Task GetAll_LegacySecret_HasNoSetAt()
    {
        var legacy = new RtFacebookIdentityProvider
            { RtId = OctoObjectId.GenerateNewId(), Name = "Facebook", ClientId = "f" };
        legacy.SetAttributeRawValue("ClientSecret", "legacy-clear-text-secret");
        _store.GetAllAsync().Returns(new RtIdentityProvider[] { legacy });

        var result = await _sut.GetIdentityProvidersAsync();

        var dto = result.Value!.IdentityProviders.Should().ContainSingle().Subject;
        ClientSecretIsSet(dto).Should().BeTrue();
        ClientSecretKeyMissing(dto).Should().BeFalse();
        ClientSecretSetAt(dto).Should().BeNull();
    }

    [Fact]
    public async Task Replace_ResponseFromStoredEntity_CarriesKeyMissingAndSetAt()
    {
        var input = new GoogleIdentityProviderDto
            { Name = "Google", IsEnabled = true, ClientId = "google-client" };

        var result = await _sut.ReplaceProviderAsync(OctoObjectId.GenerateNewId(), input);

        // Nothing sent and nothing stored in this unit test: not set, no key missing, no SetAt.
        var response = result.Result.Should().BeOfType<OkObjectResult>().Subject.Value
            .Should().BeOfType<GoogleIdentityProviderDto>().Subject;
        response.ClientSecretIsSet.Should().BeFalse();
        response.ClientSecretKeyMissing.Should().BeFalse();
        response.ClientSecretSetAt.Should().BeNull();
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

    [Fact]
    public async Task GetById_SecretWithUnknownKeyId_IsReportedAsNotSet()
    {
        // Decision r2-2: an envelope encrypted with a key that is not in the ring (e.g. restored from
        // another environment) stays stored but reads as not set — decided from the key id alone.
        var stored = new RtGoogleIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(), Name = "Google", ClientId = "g",
            ClientSecret = NewStoredEnvelope("k9")
        };
        _store.GetByIdAsync(stored.RtId).Returns(stored);

        var result = await _sut.Get(stored.RtId);

        var dto = result.Value!.IdentityProviders.Should().ContainSingle().Subject;
        ClientSecretIsSet(dto).Should().BeFalse();
        ClientSecretKeyMissing(dto).Should().BeTrue();
        var json = Serialize(result.Value);
        json.Should().Contain("\"clientSecretIsSet\":false").And.Contain("\"clientSecretKeyMissing\":true")
            .And.NotContain("enc:v2");
        AssertNoClientSecretValue(json);
        _protector.DidNotReceiveWithAnyArgs().Unprotect(default(RtSecretValue)!, default);
    }

    [Theory]
    [InlineData("<google-client-secret>")]
    [InlineData("TODO_SET_GOOGLE_CLIENT_SECRET")]
    public async Task CreateAndReplace_PlaceholderLikeSecret_IsAnOrdinaryValue(string value)
    {
        // Decision r2-1: there are no placeholder semantics on the API; such a string is stored as
        // a pending secret (encrypted by the engine) like any other value.
        var storedProviders = new List<RtIdentityProvider>();
        await _store.StoreAsync(Arg.Do<RtIdentityProvider>(p => storedProviders.Add(p)));
        GoogleIdentityProviderDto Input() => new()
            { Name = "Google", IsEnabled = true, ClientId = "google-client", ClientSecret = value };

        var created = await _sut.AddNewIdentityProviderAsync(Input());
        var replaced = await _sut.ReplaceProviderAsync(OctoObjectId.GenerateNewId(), Input());

        created.Value.Should().BeOfType<GoogleIdentityProviderDto>().Which.ClientSecretIsSet.Should().BeTrue();
        replaced.Result.Should().BeOfType<OkObjectResult>();
        storedProviders.Should().HaveCount(2).And.AllSatisfy(p =>
            p.Should().BeOfType<RtGoogleIdentityProvider>().Which.ClientSecret.Should().Be(RtSecretValue.Pending(value)));
        AssertNoClientSecretValue(Serialize(created.Value));
        Serialize(created.Value).Should().NotContain(value);
    }
}
