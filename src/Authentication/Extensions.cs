using Duende.IdentityServer.Models;

namespace Meshmakers.Octo.Backend.Authentication;

/// <summary>
///     Identity Service specific extensions
/// </summary>
public static class Extensions
{
    /// <summary>
    ///     Checks if the redirect URI is for a native client.
    /// </summary>
    /// <returns></returns>
    public static bool IsNativeClient(this AuthorizationRequest context)
    {
        return !context.RedirectUri.StartsWith("https", StringComparison.Ordinal)
               && !context.RedirectUri.StartsWith("http", StringComparison.Ordinal);
    }
}