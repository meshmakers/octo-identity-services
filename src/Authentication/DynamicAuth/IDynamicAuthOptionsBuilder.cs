using Microsoft.AspNetCore.Authentication;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

/// <summary>
///     Interface of the dynamic auth options builder, that allows to add options during run-time of identity services
/// </summary>
/// <typeparam name="TOptions">Options of </typeparam>
public interface IDynamicAuthOptionsBuilder<out TOptions>
    where TOptions : AuthenticationSchemeOptions, new()
{
    /// <summary>
    ///     Create options with the given scheme name
    /// </summary>
    /// <param name="schemeName">Scheme name</param>
    /// <returns>Created options</returns>
    TOptions CreateOptions(string schemeName);
}
