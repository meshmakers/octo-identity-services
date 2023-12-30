using Duende.IdentityServer.Stores;
using Meshmakers.Octo.Backend.IdentityServices.Services;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

/// <summary>
///     Extensions for Identity Server
/// </summary>
public static class IdentityServerBuilderExtensions
{
    /// <summary>
    ///     Uses Octo singing credential file from file system using the configuration of Octo.
    /// </summary>
    /// <param name="builder"></param>
    public static void AddOctoSigningCredential(
        this IIdentityServerBuilder builder)
    {
        builder.Services.AddSingleton<ISigningCredentialStore, SigningCredentialService>();
        builder.Services.AddSingleton<IValidationKeysStore, SigningCredentialService>();
    }
}