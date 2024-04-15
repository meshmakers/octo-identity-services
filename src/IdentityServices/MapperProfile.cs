using AutoMapper;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices;

public class MapperProfile : Profile
{
    public MapperProfile()
    {
        CreateMap<RtIdentityProvider, IdentityProviderDto>()
            .Include<RtGoogleIdentityProvider, GoogleIdentityProviderDto>()
            .Include<RtMicrosoftIdentityProvider, MicrosoftIdentityProviderDto>()
            .Include<RtMicrosoftAdIdentityProvider, MicrosoftAdProviderDto>()
            .Include<RtOpenLdapIdentityProvider, OpenLdapProviderDto>()
            .Include<RtAzureEntraIdIdentityProvider, AzureEntraIdProviderDto>()
            .Include<RtFacebookIdentityProvider, FacebookIdentityProviderDto>();

        CreateMap<RtGoogleIdentityProvider, GoogleIdentityProviderDto>();
        CreateMap<RtMicrosoftIdentityProvider, MicrosoftIdentityProviderDto>();
        CreateMap<RtMicrosoftAdIdentityProvider, MicrosoftAdProviderDto>();
        CreateMap<RtOpenLdapIdentityProvider, OpenLdapProviderDto>();
        CreateMap<RtAzureEntraIdIdentityProvider, AzureEntraIdProviderDto>();
        CreateMap<RtFacebookIdentityProvider, FacebookIdentityProviderDto>();

        
        CreateMap<IdentityProviderDto, RtIdentityProvider>()
            .Include<GoogleIdentityProviderDto, RtGoogleIdentityProvider>()
            .Include<MicrosoftIdentityProviderDto, RtMicrosoftIdentityProvider>()
            .Include<MicrosoftAdProviderDto, RtMicrosoftAdIdentityProvider>()
            .Include<OpenLdapProviderDto, RtOpenLdapIdentityProvider>()
            .Include<AzureEntraIdProviderDto, RtAzureEntraIdIdentityProvider>()
            .Include<FacebookIdentityProviderDto, RtFacebookIdentityProvider>();

        CreateMap<GoogleIdentityProviderDto, RtGoogleIdentityProvider>();
        CreateMap<MicrosoftIdentityProviderDto, RtMicrosoftIdentityProvider>();
        CreateMap<MicrosoftAdProviderDto, RtMicrosoftAdIdentityProvider>();
        CreateMap<OpenLdapProviderDto, RtOpenLdapIdentityProvider>();
        CreateMap<AzureEntraIdProviderDto, RtAzureEntraIdIdentityProvider>();
        CreateMap<FacebookIdentityProviderDto, RtFacebookIdentityProvider>();
    }
}