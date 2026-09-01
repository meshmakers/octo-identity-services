using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Common.Shared;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NLog;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

internal class SigningCredentialService : IValidationKeysStore, ISigningCredentialStore
{
    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
    private readonly SigningCredentials? _credential;

    private readonly IReadOnlyCollection<SecurityKeyInfo> _keys = Array.Empty<SecurityKeyInfo>();

    /// <summary>
    ///     Initializes a new instance
    /// </summary>
    /// <param name="octoIdentityOptions">The Octo identity options.</param>
    /// <exception cref="System.ArgumentNullException">keys</exception>
    public SigningCredentialService(IOptions<OctoIdentityServicesOptions> octoIdentityOptions)
    {
        ArgumentValidation.ValidateString(nameof(octoIdentityOptions.Value.KeyFilePath),
            octoIdentityOptions.Value.KeyFilePath);
        ArgumentValidation.ValidateString(nameof(octoIdentityOptions.Value.KeyFilePassword),
            octoIdentityOptions.Value.KeyFilePassword);

        var certificate = SigningCertificateLoader.TryLoad(octoIdentityOptions.Value);
        if (certificate != null)
        {
            _credential = new SigningCredentials(new X509SecurityKey(certificate), SecurityAlgorithms.RsaSha256);

            var keyInfo = new SecurityKeyInfo
            {
                Key = _credential.Key,
                SigningAlgorithm = _credential.Algorithm
            };
            _keys = new[] { keyInfo };
        }
    }

    /// <summary>
    ///     Gets the signing credentials.
    /// </summary>
    /// <returns></returns>
    public Task<SigningCredentials?> GetSigningCredentialsAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_credential);
    }

    /// <summary>
    ///     Gets all validation keys.
    /// </summary>
    /// <returns></returns>
    public Task<IReadOnlyCollection<SecurityKeyInfo>> GetValidationKeysAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_keys);
    }
}