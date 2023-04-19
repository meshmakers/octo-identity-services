using AutoMapper;
using Meshmakers.Octo.Common.Shared.DataTransferObjects;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;

namespace Meshmakers.Octo.Backend.IdentityServices;

public class MapperProfile : Profile
{
    public MapperProfile()
    {
        CreateMap<OctoIdentityProvider, IdentityProviderDto>()
            .Include<GoogleIdentityProvider, GoogleIdentityProviderDto>()
            .Include<MicrosoftIdentityProvider, MicrosoftIdentityProviderDto>()
            .Include<MicrosoftAdIdentityProvider, MicrosoftAdProviderDto>()
            .Include<OpenLdapIdentityProvider, OpenLdapProviderDto>()
            .Include<AzureAdIdentityProvider, AzureAdProviderDto>();

        CreateMap<GoogleIdentityProvider, GoogleIdentityProviderDto>();
        CreateMap<MicrosoftIdentityProvider, MicrosoftIdentityProviderDto>();
        CreateMap<MicrosoftAdIdentityProvider, MicrosoftAdProviderDto>();
        CreateMap<OpenLdapIdentityProvider, OpenLdapProviderDto>();
        CreateMap<AzureAdIdentityProvider, AzureAdProviderDto>();

        CreateMap<IdentityProviderDto, OctoIdentityProvider>()
            .Include<GoogleIdentityProviderDto, GoogleIdentityProvider>()
            .Include<MicrosoftIdentityProviderDto, MicrosoftIdentityProvider>()
            .Include<MicrosoftAdProviderDto, MicrosoftAdIdentityProvider>()
            .Include<OpenLdapProviderDto, OpenLdapIdentityProvider>()
            .Include<AzureAdProviderDto, AzureAdIdentityProvider>();

        CreateMap<GoogleIdentityProviderDto, GoogleIdentityProvider>();
        CreateMap<MicrosoftIdentityProviderDto, MicrosoftIdentityProvider>();
        CreateMap<MicrosoftAdProviderDto, MicrosoftAdIdentityProvider>();
        CreateMap<OpenLdapProviderDto, OpenLdapIdentityProvider>();
        CreateMap<AzureAdProviderDto, AzureAdIdentityProvider>();
    }
}
