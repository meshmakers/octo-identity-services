using Meshmakers.Octo.Backend.Authentication.Azure;
using Meshmakers.Octo.Backend.Authentication.Connection;
using Meshmakers.Octo.Backend.Authentication.Google;
using Meshmakers.Octo.Backend.Authentication.Microsoft;
using Meshmakers.Octo.Backend.Authentication.MicrosoftAd;
using Meshmakers.Octo.Backend.Authentication.OpenLdap;
using Meshmakers.Octo.Backend.Authentication.Options;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

public static class DynamicAuthBuilderExtensions
{
    public static IDynamicAuthBuilder AddOpenIdConnect(this IDynamicAuthBuilder builder)
    {
        builder.Services.AddTransient<IDynamicAuthOptionsBuilder<OpenIdConnectOptions>,
            OpenIdDynamicAuthOptionsBuilder>();
        builder.Services.AddTransient<IAuthSchemeCreator<AzureAdIdentityProvider>, AzureAuthSchemeCreator>();

        return builder;
    }

    public static IDynamicAuthBuilder AddGoogle(this IDynamicAuthBuilder builder)
    {
        builder.Services.AddTransient<IDynamicAuthOptionsBuilder<GoogleOptions>,
            OAuthDynamicAuthOptionsBuilder<GoogleHandler, GoogleOptions>>();
        builder.Services.AddTransient<IAuthSchemeCreator<GoogleIdentityProvider>, GoogleAuthSchemeCreator>();

        return builder;
    }

    public static IDynamicAuthBuilder AddMicrosoft(this IDynamicAuthBuilder builder)
    {
        builder.Services.AddTransient<IDynamicAuthOptionsBuilder<MicrosoftAccountOptions>,
            OAuthDynamicAuthOptionsBuilder<MicrosoftAccountHandler, MicrosoftAccountOptions>>();
        builder.Services.AddTransient<IAuthSchemeCreator<MicrosoftIdentityProvider>, MicrosoftAuthSchemeCreator>();
        return builder;
    }
    
    public static IDynamicAuthBuilder AddMicrosoftAdAuthentication(this IDynamicAuthBuilder builder)
    {
        builder.AddGeneralDependencies();
        builder.Services.TryAddTransient<IAuthSchemeCreator<MicrosoftAdIdentityProvider>, MicrosoftAdSchemeCreator>();
        return builder;
    }
    
    public static IDynamicAuthBuilder AddOpenLdapAuthentication(this IDynamicAuthBuilder builder)
    {
        builder.AddGeneralDependencies();
        builder.Services.TryAddTransient<IAuthSchemeCreator<OpenLdapIdentityProvider>, OpenLdapSchemeCreator>();
        return builder;
    }
    
    private static void AddGeneralDependencies(this IDynamicAuthBuilder builder)
    {
        builder.Services.TryAddTransient<ILdapConnectionFactory, LdapConnectionFactory>();
        builder.Services.TryAddTransient<IDynamicAuthOptionsBuilder<LdapOptions>, DynamicAuthOptionsBuilder<LdapOptions>>();
    }
}
