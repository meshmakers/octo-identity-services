using System.Text.Json;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Mapping;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Mapping;

public sealed class IdentityProviderMappingTests : IDisposable
{
    private static readonly string[] MembersNeverCarriedByAnyDto =
    [
        nameof(RtIdentityProvider.DisplayName),
        nameof(RtGoogleIdentityProvider.ClientSecret)
    ];

    private static readonly string[] LdapMembersMissingOnMicrosoftAdDto =
    [
        nameof(RtMicrosoftAdIdentityProvider.UserBaseDn),
        nameof(RtMicrosoftAdIdentityProvider.UserNameAttribute)
    ];

    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    private readonly ServiceProvider _services = TestSecretReader.CreateServices();
    private readonly IdentityProviderDtoMapper _sut;

    public IdentityProviderMappingTests()
    {
        _sut = new IdentityProviderDtoMapper(TestSecretReader.From(_services));
    }

    public void Dispose() => _services.Dispose();

    public static TheoryData<string> ProviderTypeNames()
    {
        var providerTypeNames = MappingSampleFactory.AllIdentityProviderEntities()
            .Select(entity => entity.GetType().Name);
        return new TheoryData<string>(providerTypeNames);
    }

    [Theory]
    [MemberData(nameof(ProviderTypeNames))]
    public void RoundTrip_PreservesEveryFieldTheDtoCarries(string providerTypeName)
    {
        var original = SampleOf(providerTypeName);
        var membersNotCarried = MembersNotCarriedByDto(original);
        var expectedAttributes = original.Attributes
            .Where(attribute => !membersNotCarried.Contains(attribute.Key))
            .ToDictionary(attribute => attribute.Key, attribute => attribute.Value);

        var roundTripped = _sut.ToDto(original).ToEntity();

        roundTripped.Should().BeOfType(original.GetType());
        roundTripped.RtId.Should().Be(original.RtId);
        roundTripped.Attributes.Should().BeEquivalentTo(expectedAttributes);
    }

    public static TheoryData<string> ProviderTypesWithClientSecret() =>
        new(nameof(RtGoogleIdentityProvider), nameof(RtMicrosoftIdentityProvider),
            nameof(RtFacebookIdentityProvider), nameof(RtAzureEntraIdIdentityProvider));

    [Theory]
    [MemberData(nameof(ProviderTypesWithClientSecret))]
    public void ToDto_ProjectsSecretStateButNeverTheSecret(string providerTypeName)
    {
        const string storedPlaintext = "do-not-leak";
        var entity = SampleWithStoredSecret(providerTypeName, storedPlaintext);

        var dto = _sut.ToDto(entity);
        var responseJson = JsonSerializer.Serialize(dto, dto.GetType(), WebJson);

        responseJson.Should().NotContain(storedPlaintext);
        responseJson.Should().Contain("\"clientSecret\":null");
        responseJson.Should().Contain("\"clientSecretIsSet\":true");
        responseJson.Should().Contain("\"clientSecretKeyMissing\":false");
    }

    [Fact]
    public void ToDto_WithoutStoredSecret_ReportsNotSet()
    {
        var dto = (MicrosoftIdentityProviderDto)_sut.ToDto(new RtMicrosoftIdentityProvider { Name = "ms", ClientId = "client" });

        dto.ClientSecretIsSet.Should().BeFalse();
        dto.ClientSecretSetAt.Should().BeNull();
    }

    [Fact]
    public void ToDto_PortOutsideUshortRange_Throws()
    {
        var entity = new RtOpenLdapIdentityProvider { Host = "ldap", Port = 70000 };

        var act = () => _sut.ToDto(entity);

        act.Should().Throw<OverflowException>();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ToEntity_MissingSecret_LeavesSecretUntouched(string? clientSecret)
    {
        var dto = new AzureEntraIdProviderDto { Name = "entra", TenantId = "t", ClientId = "c", ClientSecret = clientSecret };

        var entity = (RtAzureEntraIdIdentityProvider)dto.ToEntity();

        entity.ClientSecret.Should().BeNull();
    }

    [Fact]
    public void ToEntity_GivenSecret_BecomesPendingSecret()
    {
        var dto = new FacebookIdentityProviderDto { Name = "facebook", ClientId = "c", ClientSecret = "plain" };

        var entity = (RtFacebookIdentityProvider)dto.ToEntity();

        entity.ClientSecret.Should().BeEquivalentTo(RtSecretValue.Pending("plain"));
    }

    private static RtIdentityProvider SampleWithStoredSecret(string providerTypeName, string storedPlaintext)
    {
        var storedSecret = RtSecretValue.Pending(storedPlaintext);
        var entity = SampleOf(providerTypeName);
        switch (entity)
        {
            case RtGoogleIdentityProvider google:
                google.ClientSecret = storedSecret;
                break;
            case RtMicrosoftIdentityProvider microsoft:
                microsoft.ClientSecret = storedSecret;
                break;
            case RtFacebookIdentityProvider facebook:
                facebook.ClientSecret = storedSecret;
                break;
            case RtAzureEntraIdIdentityProvider azureEntraId:
                azureEntraId.ClientSecret = storedSecret;
                break;
        }

        return entity;
    }

    private static RtIdentityProvider SampleOf(string providerTypeName) =>
        MappingSampleFactory.AllIdentityProviderEntities().Single(entity => entity.GetType().Name == providerTypeName);

    private static HashSet<string> MembersNotCarriedByDto(RtIdentityProvider original)
    {
        var membersNotCarried = new HashSet<string>(MembersNeverCarriedByAnyDto);
        if (original is RtMicrosoftAdIdentityProvider)
        {
            membersNotCarried.UnionWith(LdapMembersMissingOnMicrosoftAdDto);
        }

        return membersNotCarried;
    }
}
