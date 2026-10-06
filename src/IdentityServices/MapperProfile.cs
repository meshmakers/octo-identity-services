using AutoMapper;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices;

public class MapperProfile : Profile
{
    public MapperProfile()
    {
        // AB#5540: ClientSecret of the external providers is a Secret attribute. It is never mapped
        // to a response (write-only), and an incoming value becomes a pending secret that the
        // engine encrypts on write. null / "" = not sent = keep the stored secret (concept §4.3).
        CreateMap<RtIdentityProvider, IdentityProviderDto>()
            .Include<RtGoogleIdentityProvider, GoogleIdentityProviderDto>()
            .Include<RtMicrosoftIdentityProvider, MicrosoftIdentityProviderDto>()
            .Include<RtMicrosoftAdIdentityProvider, MicrosoftAdProviderDto>()
            .Include<RtOpenLdapIdentityProvider, OpenLdapProviderDto>()
            .Include<RtAzureEntraIdIdentityProvider, AzureEntraIdProviderDto>()
            .Include<RtFacebookIdentityProvider, FacebookIdentityProviderDto>()
            .Include<RtOctoTenantIdentityProvider, OctoTenantIdentityProviderDto>();

        CreateMap<RtGoogleIdentityProvider, GoogleIdentityProviderDto>()
            .ForMember(d => d.ClientSecret, o => o.Ignore());
        CreateMap<RtMicrosoftIdentityProvider, MicrosoftIdentityProviderDto>()
            .ForMember(d => d.ClientSecret, o => o.Ignore());
        CreateMap<RtMicrosoftAdIdentityProvider, MicrosoftAdProviderDto>();
        CreateMap<RtOpenLdapIdentityProvider, OpenLdapProviderDto>();
        CreateMap<RtAzureEntraIdIdentityProvider, AzureEntraIdProviderDto>()
            .ForMember(d => d.ClientSecret, o => o.Ignore());
        CreateMap<RtFacebookIdentityProvider, FacebookIdentityProviderDto>()
            .ForMember(d => d.ClientSecret, o => o.Ignore());
        CreateMap<RtOctoTenantIdentityProvider, OctoTenantIdentityProviderDto>();


        CreateMap<IdentityProviderDto, RtIdentityProvider>()
            .Include<GoogleIdentityProviderDto, RtGoogleIdentityProvider>()
            .Include<MicrosoftIdentityProviderDto, RtMicrosoftIdentityProvider>()
            .Include<MicrosoftAdProviderDto, RtMicrosoftAdIdentityProvider>()
            .Include<OpenLdapProviderDto, RtOpenLdapIdentityProvider>()
            .Include<AzureEntraIdProviderDto, RtAzureEntraIdIdentityProvider>()
            .Include<FacebookIdentityProviderDto, RtFacebookIdentityProvider>()
            .Include<OctoTenantIdentityProviderDto, RtOctoTenantIdentityProvider>();

        CreateMap<GoogleIdentityProviderDto, RtGoogleIdentityProvider>()
            .ForMember(d => d.ClientSecret, MapWriteOnlySecret);
        CreateMap<MicrosoftIdentityProviderDto, RtMicrosoftIdentityProvider>()
            .ForMember(d => d.ClientSecret, MapWriteOnlySecret);
        CreateMap<MicrosoftAdProviderDto, RtMicrosoftAdIdentityProvider>();
        CreateMap<OpenLdapProviderDto, RtOpenLdapIdentityProvider>();
        CreateMap<AzureEntraIdProviderDto, RtAzureEntraIdIdentityProvider>()
            .ForMember(d => d.ClientSecret, MapWriteOnlySecret);
        CreateMap<FacebookIdentityProviderDto, RtFacebookIdentityProvider>()
            .ForMember(d => d.ClientSecret, MapWriteOnlySecret);
        CreateMap<OctoTenantIdentityProviderDto, RtOctoTenantIdentityProvider>();

        CreateMap<RtEmailDomainGroupRule, EmailDomainGroupRuleDto>()
            .ReverseMap()
            .ForMember(dest => dest.RtId, x => x.Ignore())
            .ForMember(dest => dest.CkTypeId, x => x.Ignore());
    }

    /// <summary>
    ///     Maps a write-only secret input onto a Secret attribute: a non-empty string becomes a pending
    ///     secret that the engine encrypts on write; <c>null</c> or <c>""</c> leaves the attribute
    ///     untouched (an explicit <c>null</c> would CLEAR the stored secret, concept §3.6), so a
    ///     replace keeps the stored secret.
    /// </summary>
    private static void MapWriteOnlySecret<TSource, TDestination>(
        IMemberConfigurationExpression<TSource, TDestination, RtSecretValue?> member)
        where TSource : IdentityProviderDto
    {
        member.PreCondition(src => !string.IsNullOrEmpty(GetClientSecretInput(src)));
        member.MapFrom(src => RtSecretValue.Pending(GetClientSecretInput(src)!));
    }

    internal static string? GetClientSecretInput(IdentityProviderDto dto) => dto switch
    {
        GoogleIdentityProviderDto g => g.ClientSecret,
        MicrosoftIdentityProviderDto m => m.ClientSecret,
        FacebookIdentityProviderDto f => f.ClientSecret,
        AzureEntraIdProviderDto a => a.ClientSecret,
        _ => null
    };
}
