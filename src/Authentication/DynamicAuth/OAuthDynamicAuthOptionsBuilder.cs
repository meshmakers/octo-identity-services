using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

internal class OAuthDynamicAuthOptionsBuilder<THandler, TOptions> : DynamicAuthOptionsBuilder<TOptions>
    where TOptions : OAuthOptions, new()
    where THandler : OAuthHandler<TOptions>
{
    private readonly IDataProtectionProvider _dataProtectionProvider;

    public OAuthDynamicAuthOptionsBuilder(IDataProtectionProvider dataProtectionProvider,
        IOptions<AuthenticationOptions> authOptions, IOptionsFactory<TOptions> optionsFactory,
        IOptionsMonitorCache<TOptions> optionsMonitorCache)
        : base(authOptions, optionsFactory, optionsMonitorCache)
    {
        _dataProtectionProvider = dataProtectionProvider;
    }

    protected override void PostConfigure(string schemeName, TOptions options)
    {
        options.SignInScheme ??= AuthOptions.DefaultSignInScheme ?? AuthOptions.DefaultScheme;

        var go = new OAuthPostConfigureOptions<TOptions, THandler>(_dataProtectionProvider);
        go.PostConfigure(schemeName, options);
    }
}
