using Meshmakers.Octo.Backend.Authentication.AzureEntraId;
using Meshmakers.Octo.Backend.Authentication.Connection;
using Meshmakers.Octo.Backend.Authentication.Google;
using Meshmakers.Octo.Backend.Authentication.Microsoft;
using Meshmakers.Octo.Backend.Authentication.MicrosoftAd;
using Meshmakers.Octo.Backend.Authentication.OpenLdap;
using Meshmakers.Octo.Backend.Authentication.Options;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

public static class DynamicAuthBuilderExtensions
{
    public static IDynamicAuthBuilder AddAzureEntraId(this IDynamicAuthBuilder builder)
    {
        builder.Services.AddTransient<IDynamicAuthOptionsBuilder<OpenIdConnectOptions>,
            OpenIdDynamicAuthOptionsBuilder>();
        builder.Services.AddTransient<IAuthSchemeCreator<RtAzureEntraIdIdentityProvider>, AzureEntraIdAuthSchemeCreator>();

        return builder;
    }

    public static IDynamicAuthBuilder AddGoogle(this IDynamicAuthBuilder builder)
    {
        builder.Services.AddTransient<IDynamicAuthOptionsBuilder<GoogleOptions>,
            OAuthDynamicAuthOptionsBuilder<GoogleHandler, GoogleOptions>>();
        builder.Services.AddTransient<IAuthSchemeCreator<RtGoogleIdentityProvider>, GoogleAuthSchemeCreator>();

        return builder;
    }

    public static IDynamicAuthBuilder AddMicrosoft(this IDynamicAuthBuilder builder)
    {
        builder.Services.AddTransient<IDynamicAuthOptionsBuilder<MicrosoftAccountOptions>,
            OAuthDynamicAuthOptionsBuilder<MicrosoftAccountHandler, MicrosoftAccountOptions>>();
        builder.Services.AddTransient<IAuthSchemeCreator<RtMicrosoftIdentityProvider>, MicrosoftAuthSchemeCreator>();
        return builder;
    }

    public static IDynamicAuthBuilder AddMicrosoftAdAuthentication(this IDynamicAuthBuilder builder)
    {
        builder.AddGeneralDependencies();
        builder.Services.TryAddTransient<IAuthSchemeCreator<RtMicrosoftAdIdentityProvider>, MicrosoftAdSchemeCreator>();
        return builder;
    }

    public static IDynamicAuthBuilder AddOpenLdapAuthentication(this IDynamicAuthBuilder builder)
    {
        builder.AddGeneralDependencies();
        builder.Services.TryAddTransient<IAuthSchemeCreator<RtOpenLdapIdentityProvider>, OpenLdapSchemeCreator>();
        return builder;
    }

    private static void AddGeneralDependencies(this IDynamicAuthBuilder builder)
    {
        builder.Services.TryAddTransient<ILdapConnectionFactory, LdapConnectionFactory>();
        builder.Services.TryAddTransient<IDynamicAuthOptionsBuilder<LdapOptions>, DynamicAuthOptionsBuilder<LdapOptions>>();
    }
}