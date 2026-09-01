using System.Security.Cryptography.X509Certificates;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Common.Shared;
using NLog;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Loads the static PKCS#12 token-signing certificate configured via
///     <see cref="OctoIdentityServicesOptions.KeyFilePath" /> /
///     <see cref="OctoIdentityServicesOptions.KeyFilePassword" />. Shared by the Duende
///     <see cref="SigningCredentialService" /> and the OpenIddict server configuration
///     (AB#4989/AB#4990) so both stacks sign with the identical certificate — the JWKS stays
///     unchanged across the migration and outstanding access tokens remain valid.
/// </summary>
internal static class SigningCertificateLoader
{
    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    public static X509Certificate2? TryLoad(OctoIdentityServicesOptions options)
    {
        ArgumentValidation.ValidateString(nameof(options.KeyFilePath), options.KeyFilePath);
        ArgumentValidation.ValidateString(nameof(options.KeyFilePassword), options.KeyFilePassword);

        if (!File.Exists(options.KeyFilePath))
        {
            Logger.Error($"Signing credential key file not found: {options.KeyFilePath}");
            return null;
        }

        Logger.Debug($"Loading signing credential from file {options.KeyFilePath}");
        return X509CertificateLoader.LoadPkcs12FromFile(options.KeyFilePath, options.KeyFilePassword);
    }
}
