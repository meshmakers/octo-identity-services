using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServices.UnitTests.Mapping;

internal static class MappingSampleFactory
{
    public static IEnumerable<RtIdentityProvider> AllIdentityProviderEntities()
    {
        yield return FillEntityBase(new RtIdentityProvider());
        yield return FillEntityBase(new RtGoogleIdentityProvider { ClientId = "google-client" });
        yield return FillEntityBase(new RtMicrosoftIdentityProvider { ClientId = "microsoft-client" });
        yield return FillEntityBase(new RtFacebookIdentityProvider { ClientId = "facebook-client" });
        yield return FillEntityBase(new RtAzureEntraIdIdentityProvider
        {
            TenantId = "entra-tenant",
            Authority = "https://login.example.com",
            ClientId = "entra-client"
        });
        yield return FillEntityBase(new RtMicrosoftAdIdentityProvider
        {
            Host = "ad.example.com",
            Port = 389,
            UseTls = true,
            UserBaseDn = "dc=ad,dc=example",
            UserNameAttribute = "sAMAccountName"
        });
        yield return FillEntityBase(new RtOpenLdapIdentityProvider
        {
            Host = "ldap.example.com",
            Port = 636,
            UseTls = false,
            UserBaseDn = "ou=people,dc=example",
            UserNameAttribute = "uid"
        });
        yield return FillEntityBase(new RtOctoTenantIdentityProvider { ParentTenantId = "parent-tenant" });
    }

    public static IEnumerable<IdentityProviderDto> AllIdentityProviderDtos(string? clientSecret)
    {
        yield return FillDtoBase(new IdentityProviderDto());
        yield return FillDtoBase(new GoogleIdentityProviderDto { ClientId = "google-client", ClientSecret = clientSecret });
        yield return FillDtoBase(new MicrosoftIdentityProviderDto { ClientId = "microsoft-client", ClientSecret = clientSecret });
        yield return FillDtoBase(new FacebookIdentityProviderDto { ClientId = "facebook-client", ClientSecret = clientSecret });
        yield return FillDtoBase(new AzureEntraIdProviderDto
        {
            TenantId = "entra-tenant",
            Authority = "https://login.example.com",
            ClientId = "entra-client",
            ClientSecret = clientSecret
        });
        yield return FillDtoBase(new MicrosoftAdProviderDto { Host = "ad.example.com", Port = 389, UseTls = true });
        yield return FillDtoBase(new OpenLdapProviderDto
        {
            Host = "ldap.example.com",
            Port = 636,
            UseTls = false,
            UserBaseDn = "ou=people,dc=example",
            UserNameAttribute = "uid"
        });
        yield return FillDtoBase(new OctoTenantIdentityProviderDto { ParentTenantId = "parent-tenant" });
    }

    public static RtUser UserWithLogins() => UserWithLogins(OctoObjectId.GenerateNewId());

    public static RtUser UserWithLogins(OctoObjectId rtId)
    {
        var user = new RtUser
        {
            RtId = rtId,
            UserName = "jane.doe",
            NormalizedUserName = "JANE.DOE",
            FirstName = "Jane",
            LastName = "Doe",
            Email = "jane@example.com",
            ResetPasswordOnLogin = true,
            UserLogins = new AttributeRecordValueList<RtUserLoginRecord>()
        };
        user.UserLogins.Add(new RtUserLoginRecord
        {
            LoginProvider = "tenant:google",
            ProviderKey = "google-key",
            ProviderDisplayName = "Google",
            UserId = user.RtId.ToString()
        });
        user.UserLogins.Add(new RtUserLoginRecord
        {
            LoginProvider = "tenant:ldap",
            ProviderKey = "ldap-key",
            ProviderDisplayName = null,
            UserId = user.RtId.ToString()
        });
        return user;
    }

    public static RtRole Role() => new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        Name = "UserManagement",
        NormalizedName = "USERMANAGEMENT"
    };

    public static RtEmailDomainGroupRule EmailDomainGroupRule() => new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        EmailDomainPattern = "example.com",
        TargetGroupRtId = OctoObjectId.GenerateNewId().ToString(),
        Description = "Everybody from example.com"
    };

    private static T FillEntityBase<T>(T identityProvider) where T : RtIdentityProvider
    {
        identityProvider.RtId = OctoObjectId.GenerateNewId();
        identityProvider.Name = $"{typeof(T).Name}-name";
        identityProvider.DisplayName = $"{typeof(T).Name} display";
        identityProvider.Description = $"{typeof(T).Name} description";
        identityProvider.IsEnabled = true;
        identityProvider.AllowSelfRegistration = false;
        identityProvider.DefaultGroupRtId = "default-group";
        return identityProvider;
    }

    private static T FillDtoBase<T>(T dto) where T : IdentityProviderDto
    {
        dto.RtId = OctoObjectId.GenerateNewId();
        dto.Name = $"{typeof(T).Name}-name";
        dto.Description = $"{typeof(T).Name} description";
        dto.IsEnabled = true;
        dto.AllowSelfRegistration = false;
        dto.DefaultGroupRtId = "default-group";
        return dto;
    }
}
