using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

internal class OpenIdDynamicAuthOptionsBuilder : DynamicAuthOptionsBuilder<OpenIdConnectOptions>
{
    private readonly IDataProtectionProvider _dataProtectionProvider;

    public OpenIdDynamicAuthOptionsBuilder(IDataProtectionProvider dataProtectionProvider,
        IOptions<AuthenticationOptions> authOptions, IOptionsFactory<OpenIdConnectOptions> optionsFactory,
        IOptionsMonitorCache<OpenIdConnectOptions> optionsMonitorCache)
        : base(authOptions, optionsFactory, optionsMonitorCache)
    {
        _dataProtectionProvider = dataProtectionProvider;
    }

    protected override void PostConfigure(string schemeName, OpenIdConnectOptions options)
    {
        options.SignInScheme ??= AuthOptions.DefaultSignInScheme ?? AuthOptions.DefaultScheme;

        var go = new OpenIdConnectPostConfigureOptions(_dataProtectionProvider);
        go.PostConfigure(schemeName, options);
    }
}