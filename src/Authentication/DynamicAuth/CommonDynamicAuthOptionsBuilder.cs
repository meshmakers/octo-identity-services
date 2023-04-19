using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

public class CommonDynamicAuthOptionsBuilder<THandler, TOptions> : DynamicAuthOptionsBuilder<TOptions>
    where TOptions : AuthenticationSchemeOptions, new()
    where THandler : AuthenticationHandler<TOptions>
{
    public CommonDynamicAuthOptionsBuilder(IOptions<AuthenticationOptions> authOptions,
        IOptionsFactory<TOptions> optionsFactory, IOptionsMonitorCache<TOptions> optionsMonitorCache)
        : base(authOptions, optionsFactory, optionsMonitorCache)
    {
        
    }
}
