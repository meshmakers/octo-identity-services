using AutoMapper;
using Duende.IdentityServer.Models;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices;

public class MapperProfile : Profile
{
    public MapperProfile()
    {
        // Explicit RtClient → Duende.IdentityServer.Models.Client map.
        //
        // Until System.Identity-2.9.0 the URI lists on RtClient were IList<string>, so
        // AutoMapper's name-convention auto-map handled the Duende projection silently. The
        // 2.9.0 bump (AB#4209) changed each list to IList<ClientUriEntry> — convention can no
        // longer map IList<ClientUriEntry> to ICollection<string> on the Duende side. The three
        // ForMember rules below project entry.Uri; every other RtClient property still
        // auto-maps by name into Client.
        CreateMap<RtClient, Client>()
            .ForMember(dest => dest.RedirectUris,
                opt => opt.MapFrom(src => src.RedirectUris.Select(e => e.Uri).ToList()))
            .ForMember(dest => dest.PostLogoutRedirectUris,
                opt => opt.MapFrom(src => src.PostLogoutRedirectUris.Select(e => e.Uri).ToList()))
            .ForMember(dest => dest.AllowedCorsOrigins,
                opt => opt.MapFrom(src => src.AllowedCorsOrigins.Select(e => e.Uri).ToList()));

        CreateMap<RtIdentityProvider, IdentityProviderDto>()
            .Include<RtGoogleIdentityProvider, GoogleIdentityProviderDto>()
            .Include<RtMicrosoftIdentityProvider, MicrosoftIdentityProviderDto>()
            .Include<RtMicrosoftAdIdentityProvider, MicrosoftAdProviderDto>()
            .Include<RtOpenLdapIdentityProvider, OpenLdapProviderDto>()
            .Include<RtAzureEntraIdIdentityProvider, AzureEntraIdProviderDto>()
            .Include<RtFacebookIdentityProvider, FacebookIdentityProviderDto>()
            .Include<RtOctoTenantIdentityProvider, OctoTenantIdentityProviderDto>();

        CreateMap<RtGoogleIdentityProvider, GoogleIdentityProviderDto>();
        CreateMap<RtMicrosoftIdentityProvider, MicrosoftIdentityProviderDto>();
        CreateMap<RtMicrosoftAdIdentityProvider, MicrosoftAdProviderDto>();
        CreateMap<RtOpenLdapIdentityProvider, OpenLdapProviderDto>();
        CreateMap<RtAzureEntraIdIdentityProvider, AzureEntraIdProviderDto>();
        CreateMap<RtFacebookIdentityProvider, FacebookIdentityProviderDto>();
        CreateMap<RtOctoTenantIdentityProvider, OctoTenantIdentityProviderDto>();


        CreateMap<IdentityProviderDto, RtIdentityProvider>()
            .Include<GoogleIdentityProviderDto, RtGoogleIdentityProvider>()
            .Include<MicrosoftIdentityProviderDto, RtMicrosoftIdentityProvider>()
            .Include<MicrosoftAdProviderDto, RtMicrosoftAdIdentityProvider>()
            .Include<OpenLdapProviderDto, RtOpenLdapIdentityProvider>()
            .Include<AzureEntraIdProviderDto, RtAzureEntraIdIdentityProvider>()
            .Include<FacebookIdentityProviderDto, RtFacebookIdentityProvider>()
            .Include<OctoTenantIdentityProviderDto, RtOctoTenantIdentityProvider>();

        CreateMap<GoogleIdentityProviderDto, RtGoogleIdentityProvider>();
        CreateMap<MicrosoftIdentityProviderDto, RtMicrosoftIdentityProvider>();
        CreateMap<MicrosoftAdProviderDto, RtMicrosoftAdIdentityProvider>();
        CreateMap<OpenLdapProviderDto, RtOpenLdapIdentityProvider>();
        CreateMap<AzureEntraIdProviderDto, RtAzureEntraIdIdentityProvider>();
        CreateMap<FacebookIdentityProviderDto, RtFacebookIdentityProvider>();
        CreateMap<OctoTenantIdentityProviderDto, RtOctoTenantIdentityProvider>();

        CreateMap<RtEmailDomainGroupRule, EmailDomainGroupRuleDto>()
            .ReverseMap()
            .ForMember(dest => dest.RtId, x => x.Ignore())
            .ForMember(dest => dest.CkTypeId, x => x.Ignore());
    }
}