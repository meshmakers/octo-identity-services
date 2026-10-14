using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Mapping;

public static class IdentityProviderEntityMapping
{
    public static RtIdentityProvider ToEntity(this IdentityProviderDto dto)
    {
        var entity = CreateTypedEntity(dto);
        CopyCommonFields(dto, entity);
        ApplyClientSecretIfSent(dto, entity);
        return entity;
    }

    internal static string? GetClientSecretInput(IdentityProviderDto dto) => dto switch
    {
        GoogleIdentityProviderDto google => google.ClientSecret,
        MicrosoftIdentityProviderDto microsoft => microsoft.ClientSecret,
        FacebookIdentityProviderDto facebook => facebook.ClientSecret,
        AzureEntraIdProviderDto azureEntraId => azureEntraId.ClientSecret,
        _ => null
    };

    private static RtIdentityProvider CreateTypedEntity(IdentityProviderDto dto) => dto switch
    {
        GoogleIdentityProviderDto google => new RtGoogleIdentityProvider
        {
            ClientId = google.ClientId!
        },
        MicrosoftIdentityProviderDto microsoft => new RtMicrosoftIdentityProvider
        {
            ClientId = microsoft.ClientId!
        },
        FacebookIdentityProviderDto facebook => new RtFacebookIdentityProvider
        {
            ClientId = facebook.ClientId!
        },
        AzureEntraIdProviderDto azureEntraId => new RtAzureEntraIdIdentityProvider
        {
            TenantId = azureEntraId.TenantId,
            Authority = azureEntraId.Authority,
            ClientId = azureEntraId.ClientId
        },
        MicrosoftAdProviderDto microsoftAd => new RtMicrosoftAdIdentityProvider
        {
            Host = microsoftAd.Host,
            Port = microsoftAd.Port,
            UseTls = microsoftAd.UseTls
        },
        OpenLdapProviderDto openLdap => new RtOpenLdapIdentityProvider
        {
            Host = openLdap.Host,
            Port = openLdap.Port,
            UserBaseDn = openLdap.UserBaseDn,
            UserNameAttribute = openLdap.UserNameAttribute,
            UseTls = openLdap.UseTls
        },
        OctoTenantIdentityProviderDto octoTenant => new RtOctoTenantIdentityProvider
        {
            ParentTenantId = octoTenant.ParentTenantId!
        },
        _ => new RtIdentityProvider()
    };

    private static void ApplyClientSecretIfSent(IdentityProviderDto dto, RtIdentityProvider entity)
    {
        var clientSecretInput = GetClientSecretInput(dto);
        if (string.IsNullOrEmpty(clientSecretInput))
        {
            return;
        }

        var pendingSecret = RtSecretValue.Pending(clientSecretInput);
        switch (entity)
        {
            case RtGoogleIdentityProvider google:
                google.ClientSecret = pendingSecret;
                break;
            case RtMicrosoftIdentityProvider microsoft:
                microsoft.ClientSecret = pendingSecret;
                break;
            case RtFacebookIdentityProvider facebook:
                facebook.ClientSecret = pendingSecret;
                break;
            case RtAzureEntraIdIdentityProvider azureEntraId:
                azureEntraId.ClientSecret = pendingSecret;
                break;
        }
    }

    private static void CopyCommonFields(IdentityProviderDto dto, RtIdentityProvider entity)
    {
        if (dto.RtId.HasValue)
        {
            entity.RtId = dto.RtId.Value;
        }

        entity.Name = dto.Name!;
        entity.Description = dto.Description;
        entity.IsEnabled = dto.IsEnabled;
        entity.AllowSelfRegistration = dto.AllowSelfRegistration;
        entity.DefaultGroupRtId = dto.DefaultGroupRtId;
    }
}
