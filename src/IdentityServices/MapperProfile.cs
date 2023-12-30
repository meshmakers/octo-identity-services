using AutoMapper;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

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
            .Include<RtAzureEntraIdentityProvider, AzureEntraProviderDto>();

        CreateMap<RtGoogleIdentityProvider, GoogleIdentityProviderDto>();
        CreateMap<RtMicrosoftIdentityProvider, MicrosoftIdentityProviderDto>();
        CreateMap<RtMicrosoftAdIdentityProvider, MicrosoftAdProviderDto>();
        CreateMap<RtOpenLdapIdentityProvider, OpenLdapProviderDto>();
        CreateMap<RtAzureEntraIdentityProvider, AzureEntraProviderDto>();

        CreateMap<IdentityProviderDto, RtIdentityProvider>()
            .Include<GoogleIdentityProviderDto, RtGoogleIdentityProvider>()
            .Include<MicrosoftIdentityProviderDto, RtMicrosoftIdentityProvider>()
            .Include<MicrosoftAdProviderDto, RtMicrosoftAdIdentityProvider>()
            .Include<OpenLdapProviderDto, RtOpenLdapIdentityProvider>()
            .Include<AzureEntraProviderDto, RtAzureEntraIdentityProvider>();

        CreateMap<GoogleIdentityProviderDto, RtGoogleIdentityProvider>();
        CreateMap<MicrosoftIdentityProviderDto, RtMicrosoftIdentityProvider>();
        CreateMap<MicrosoftAdProviderDto, RtMicrosoftAdIdentityProvider>();
        CreateMap<OpenLdapProviderDto, RtOpenLdapIdentityProvider>();
        CreateMap<AzureEntraProviderDto, RtAzureEntraIdentityProvider>();
    }
}