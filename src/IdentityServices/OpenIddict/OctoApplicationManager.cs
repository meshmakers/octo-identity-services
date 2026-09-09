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
/// <remarks>
///     🔴 <b>It also restores multi-secret clients (AB#5061).</b> OpenIddict's application model
///     carries exactly <b>one</b> client secret, and
///     <c>OpenIddictApplicationStore.GetClientSecretAsync</c> can therefore only project the first
///     stored <c>RtSecretRecord</c>. The pre-migration server validated a presented credential
///     against the client's <b>whole</b> secret list, and the platform relies on that in two places:
///     a client mid-rotation holds the old and the new secret at once, and — since AB#5061 — every
///     mirror of a confidential client holds the secret inherited from its parent <i>and</i> its own
///     tenant-scoped one. With only the first record consulted, which of the two works would depend
///     on list order. <see cref="ValidateClientSecretAsync(RtClient,string,CancellationToken)" />
///     therefore iterates the stored records itself instead of going through the single-valued store
///     projection, and reports the matched record to <see cref="IMirrorSecretUsageTelemetry" />
///     (AB#5065) — this is the only place where the presented credential and the client's stored
///     secrets are both in hand.
/// </remarks>
public class OctoApplicationManager(
    IOpenIddictApplicationCache<RtClient> cache,
    ILogger<OpenIddictApplicationManager<RtClient>> logger,
    IOptionsMonitor<OpenIddictCoreOptions> options,
    IOpenIddictApplicationStore<RtClient> store,
    IMirrorSecretUsageTelemetry mirrorSecretUsageTelemetry)
    : OpenIddictApplicationManager<RtClient>(cache, logger, options, store)
{
    /// <summary>
    ///     Validates a presented client secret against <b>every</b> stored, unexpired secret record
    ///     of the client — see the class remarks for why the single-valued store projection is not
    ///     enough — and records which one matched (AB#5065).
    /// </summary>
    public override ValueTask<bool> ValidateClientSecretAsync(
        RtClient application, string secret, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(application);

        // Same candidate set as OpenIddictApplicationStore.GetClientSecretAsync, only unabridged:
        // deliberately NOT filtered by RtSecretRecord.Type, because that projection does not filter
        // either and a legacy record with an unset Type must keep authenticating.
        var candidates = application.ClientSecrets?
            .Where(s => !string.IsNullOrEmpty(s.Value) &&
                        (s.ExpirationDateTime == null || s.ExpirationDateTime > DateTime.UtcNow))
            .ToList();

        if (candidates is not { Count: > 0 })
        {
            // No usable secret on record: let the base implementation own the outcome and its
            // logging (a confidential client without a secret is a configuration error).
            return base.ValidateClientSecretAsync(application, secret, cancellationToken);
        }

        if (string.IsNullOrEmpty(secret))
        {
            return new ValueTask<bool>(false);
        }

        var matched = candidates.FirstOrDefault(s => OctoSecretHasher.Matches(secret, s.Value!));
        if (matched == null)
        {
            return new ValueTask<bool>(false);
        }

        mirrorSecretUsageTelemetry.RecordSecretMatch(application, candidates, matched);
        return new ValueTask<bool>(true);
    }

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
