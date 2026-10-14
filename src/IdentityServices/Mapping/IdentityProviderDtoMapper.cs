using Meshmakers.Octo.Backend.Authentication.Secrets;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Mapping;

public sealed class IdentityProviderDtoMapper(IIdentityProviderSecretReader secretReader)
{
    public IdentityProviderDto ToDto(RtIdentityProvider identityProvider)
    {
        var dto = CreateTypedDto(identityProvider);
        CopyCommonFields(identityProvider, dto);
        return dto;
    }

    private IdentityProviderDto CreateTypedDto(RtIdentityProvider identityProvider) => identityProvider switch
    {
        RtGoogleIdentityProvider google => ToGoogleDto(google),
        RtMicrosoftIdentityProvider microsoft => ToMicrosoftDto(microsoft),
        RtFacebookIdentityProvider facebook => ToFacebookDto(facebook),
        RtAzureEntraIdIdentityProvider azureEntraId => ToAzureEntraIdDto(azureEntraId),
        RtMicrosoftAdIdentityProvider microsoftAd => ToMicrosoftAdDto(microsoftAd),
        RtOpenLdapIdentityProvider openLdap => ToOpenLdapDto(openLdap),
        RtOctoTenantIdentityProvider octoTenant => new OctoTenantIdentityProviderDto
        {
            ParentTenantId = octoTenant.ParentTenantId
        },
        _ => new IdentityProviderDto()
    };

    private GoogleIdentityProviderDto ToGoogleDto(RtGoogleIdentityProvider google)
    {
        var secretState = ReadSecretState(google);
        return new GoogleIdentityProviderDto
        {
            ClientId = google.ClientId,
            ClientSecretIsSet = secretState.IsSet,
            ClientSecretKeyMissing = secretState.KeyMissing,
            ClientSecretSetAt = secretState.SetAt
        };
    }

    private MicrosoftIdentityProviderDto ToMicrosoftDto(RtMicrosoftIdentityProvider microsoft)
    {
        var secretState = ReadSecretState(microsoft);
        return new MicrosoftIdentityProviderDto
        {
            ClientId = microsoft.ClientId,
            ClientSecretIsSet = secretState.IsSet,
            ClientSecretKeyMissing = secretState.KeyMissing,
            ClientSecretSetAt = secretState.SetAt
        };
    }

    private FacebookIdentityProviderDto ToFacebookDto(RtFacebookIdentityProvider facebook)
    {
        var secretState = ReadSecretState(facebook);
        return new FacebookIdentityProviderDto
        {
            ClientId = facebook.ClientId,
            ClientSecretIsSet = secretState.IsSet,
            ClientSecretKeyMissing = secretState.KeyMissing,
            ClientSecretSetAt = secretState.SetAt
        };
    }

    private AzureEntraIdProviderDto ToAzureEntraIdDto(RtAzureEntraIdIdentityProvider azureEntraId)
    {
        var secretState = ReadSecretState(azureEntraId);
        return new AzureEntraIdProviderDto
        {
            TenantId = azureEntraId.TenantId,
            Authority = azureEntraId.Authority,
            ClientId = azureEntraId.ClientId,
            ClientSecretIsSet = secretState.IsSet,
            ClientSecretKeyMissing = secretState.KeyMissing,
            ClientSecretSetAt = secretState.SetAt
        };
    }

    private static MicrosoftAdProviderDto ToMicrosoftAdDto(RtMicrosoftAdIdentityProvider microsoftAd) => new()
    {
        Host = microsoftAd.Host,
        Port = Convert.ToUInt16(microsoftAd.Port),
        UseTls = microsoftAd.UseTls
    };

    private static OpenLdapProviderDto ToOpenLdapDto(RtOpenLdapIdentityProvider openLdap) => new()
    {
        Host = openLdap.Host,
        Port = Convert.ToUInt16(openLdap.Port),
        UserBaseDn = openLdap.UserBaseDn,
        UserNameAttribute = openLdap.UserNameAttribute,
        UseTls = openLdap.UseTls
    };

    private ClientSecretState ReadSecretState(RtIdentityProvider identityProvider)
    {
        var storedSecret = secretReader.DescribeClientSecret(identityProvider);
        var isSet = storedSecret.State == SecretValueState.Set;
        return new ClientSecretState(isSet, storedSecret.KeyMissing, storedSecret.SetAt);
    }

    private static void CopyCommonFields(RtIdentityProvider identityProvider, IdentityProviderDto dto)
    {
        dto.RtId = identityProvider.RtId;
        dto.Name = identityProvider.Name;
        dto.Description = identityProvider.Description;
        dto.IsEnabled = identityProvider.IsEnabled;
        dto.AllowSelfRegistration = identityProvider.AllowSelfRegistration;
        dto.DefaultGroupRtId = identityProvider.DefaultGroupRtId;
    }

    private sealed record ClientSecretState(bool IsSet, bool KeyMissing, DateTime? SetAt);
}
