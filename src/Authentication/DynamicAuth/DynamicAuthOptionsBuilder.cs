using Meshmakers.Common.Shared;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

/// <summary>
///     Implements the dynamic auth options builder, that allows to add options during run-time of identity services
/// </summary>
/// <typeparam name="TOptions"></typeparam>
public class DynamicAuthOptionsBuilder<TOptions> : IDynamicAuthOptionsBuilder<TOptions>
    where TOptions : AuthenticationSchemeOptions, new()
{
    private readonly IOptionsFactory<TOptions> _optionsFactory;
    private readonly IOptionsMonitorCache<TOptions> _optionsMonitorCache;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="authOptions"></param>
    /// <param name="optionsFactory"></param>
    /// <param name="optionsMonitorCache"></param>
    public DynamicAuthOptionsBuilder(
        IOptions<AuthenticationOptions> authOptions,
        IOptionsFactory<TOptions> optionsFactory,
        IOptionsMonitorCache<TOptions> optionsMonitorCache)
    {
        _optionsFactory = optionsFactory;
        _optionsMonitorCache = optionsMonitorCache;
        AuthOptions = authOptions.Value;
    }

    protected AuthenticationOptions AuthOptions { get; }

    public TOptions CreateOptions(string schemeName)
    {
        ArgumentValidation.ValidateString(nameof(schemeName), schemeName);

        var options = _optionsFactory.Create(schemeName);

        _optionsMonitorCache.TryRemove(schemeName);
        _optionsMonitorCache.TryAdd(schemeName, options);

        PostConfigure(schemeName, options);

        return options;
    }

    protected virtual void PostConfigure(string schemeName, TOptions options)
    {
    }
}