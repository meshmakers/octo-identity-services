using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Application manager keeping the existing client secrets working across the OpenIddict
///     migration (AB#4991): stored secrets are legacy-format hashes written by the pre-migration
///     IdentityServer — Base64 of the SHA-256 (or SHA-512) of the plain secret (see
///     <c>OctoSecretHasher</c>) — while OpenIddict's default manager expects its own
///     ASP.NET-Identity-style hash. This override compares the incoming plain secret against the
///     stored value in the legacy format, so no client has to rotate its secret at the cutover.
/// </summary>
public class OctoApplicationManager(
    IOpenIddictApplicationCache<RtClient> cache,
    ILogger<OpenIddictApplicationManager<RtClient>> logger,
    IOptionsMonitor<OpenIddictCoreOptions> options,
    IOpenIddictApplicationStore<RtClient> store)
    : OpenIddictApplicationManager<RtClient>(cache, logger, options, store)
{
    protected override ValueTask<bool> ValidateClientSecretAsync(
        string secret, string comparand, CancellationToken cancellationToken = default)
    {
        // comparand = stored value (legacy Base64 SHA-256/512 hash), secret = plain secret from
        // the request.
        return new ValueTask<bool>(OctoSecretHasher.Matches(secret, comparand));
    }
}

/// <summary>
///     The secret hash format used by the stored <c>RtSecretRecord.Value</c> entries: Base64 of
///     the SHA-256/SHA-512 of the UTF-8 plain secret — the legacy format the pre-migration
///     IdentityServer wrote for all existing records, so stored secrets must keep validating
///     without rotation.
/// </summary>
public static class OctoSecretHasher
{
    /// <summary>Hashes a plain secret for storage (SHA-256, legacy-format compatible).</summary>
    public static string HashSecret(string plainSecret)
        => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(plainSecret)));

    /// <summary>Compares a plain secret against a stored SHA-256/SHA-512 Base64 hash.</summary>
    public static bool Matches(string plainSecret, string storedHash)
    {
        if (string.IsNullOrEmpty(plainSecret) || string.IsNullOrEmpty(storedHash))
        {
            return false;
        }

        var bytes = Encoding.UTF8.GetBytes(plainSecret);
        var sha256 = Convert.ToBase64String(SHA256.HashData(bytes));
        if (CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(sha256), Encoding.UTF8.GetBytes(storedHash)))
        {
            return true;
        }

        var sha512 = Convert.ToBase64String(SHA512.HashData(bytes));
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(sha512), Encoding.UTF8.GetBytes(storedHash));
    }
}
