using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.Authentication.Secrets;

/// <summary>
///     Stored state of an identity provider's <c>ClientSecret</c>, determined without decrypting it.
/// </summary>
public enum IdentityProviderSecretState
{
    /// <summary>
    ///     No client secret is stored (or the provider type has none).
    /// </summary>
    NotSet,

    /// <summary>
    ///     A client secret is stored and its key (if encrypted) is known to this host.
    /// </summary>
    Set,

    /// <summary>
    ///     A client secret is stored encrypted with a key id that is not in this host's key ring
    ///     (e.g. restored from another environment). The ciphertext is kept; it reads as "not set"
    ///     until the key is added to the ring or the secret is re-entered (AB#5528 decision r2-2).
    /// </summary>
    KeyMissing
}

/// <summary>
///     Reads the plaintext <c>ClientSecret</c> of an external identity provider (Google, Microsoft,
///     Facebook, Azure Entra ID) for the authentication handler options (AB#5540, concept AB#5528).
/// </summary>
/// <remarks>
///     The attribute is of the CK value type <c>Secret</c>: stored as an <c>enc:v2</c> envelope, or —
///     until the encrypt sweep has run — as legacy clear text or an <c>enc:v1</c> value. All three
///     forms go through <see cref="ISecretAttributeProtector.Unprotect(RtSecretValue, SecretAccessContext?)" />,
///     which counts every decrypt (<c>octo.secrets.decrypt</c>). The value is never logged.
/// </remarks>
public interface IIdentityProviderSecretReader
{
    /// <summary>
    ///     Returns the plaintext client secret of <paramref name="identityProvider" />, or <c>null</c>
    ///     when the provider has none (not set, a provider type without a client secret, or a value
    ///     encrypted with a key id that is not in the key ring — logged as an error without the value).
    /// </summary>
    /// <param name="identityProvider">The identity provider entity</param>
    /// <param name="tenantId">Tenant the provider belongs to (decrypt counter tag)</param>
    /// <returns>The plaintext or <c>null</c></returns>
    /// <exception cref="SecretEncryptionNotConfiguredException">An encrypted value but no key ring</exception>
    string? GetClientSecret(RtIdentityProvider identityProvider, string? tenantId);

    /// <summary>
    ///     Classifies the stored client secret of <paramref name="identityProvider" /> from its stored
    ///     form only — the value is never decrypted for it.
    /// </summary>
    /// <param name="identityProvider">The identity provider entity</param>
    /// <returns>The stored state</returns>
    IdentityProviderSecretState GetClientSecretState(RtIdentityProvider identityProvider);

    /// <summary>
    ///     Describes the stored client secret of <paramref name="identityProvider" /> (state, storage
    ///     form, key id, <c>SetAt</c>) through <see cref="ISecretAttributeProtector.DescribeSecret" /> —
    ///     the value is never decrypted for it. A provider type without a client secret reads as not set.
    /// </summary>
    /// <param name="identityProvider">The identity provider entity</param>
    /// <param name="tenantId">Tenant the provider belongs to (log context only)</param>
    /// <returns>The read info of the stored client secret</returns>
    SecretReadInfo DescribeClientSecret(RtIdentityProvider identityProvider, string? tenantId = null);
}

/// <inheritdoc />
internal sealed class IdentityProviderSecretReader(
    ISecretAttributeProtector protector,
    ILogger<IdentityProviderSecretReader> logger) : IIdentityProviderSecretReader
{
    /// <summary>
    ///     CK attribute name of the client secret on the external provider types.
    /// </summary>
    internal const string ClientSecretAttributeName = "ClientSecret";

    /// <summary>
    ///     Service tag of the decrypt counter.
    /// </summary>
    internal const string ServiceName = "identity";

    /// <inheritdoc />
    public string? GetClientSecret(RtIdentityProvider identityProvider, string? tenantId)
    {
        ArgumentNullException.ThrowIfNull(identityProvider);

        var value = GetStoredValue(identityProvider);
        if (value == null)
        {
            return null;
        }

        if (IsKeyMissing(value))
        {
            // Decision r2-2: an unknown key id reads as "not set". Log the key id (not secret) and
            // the provider, never the value.
            logger.LogError(
                "Client secret of identity provider '{ProviderName}' in tenant '{TenantId}' is encrypted with unknown key id '{KeyId}'; treated as not set until the key is added to the key ring or the secret is re-entered",
                identityProvider.Name, tenantId, value.KeyId);
            return null;
        }

        var plaintext = protector.Unprotect(value, new SecretAccessContext(tenantId,
            identityProvider.CkTypeId?.ToString(), ClientSecretAttributeName, ServiceName));
        return string.IsNullOrEmpty(plaintext) ? null : plaintext;
    }

    /// <inheritdoc />
    public IdentityProviderSecretState GetClientSecretState(RtIdentityProvider identityProvider)
        => DescribeClientSecret(identityProvider).State switch
        {
            SecretValueState.Set => IdentityProviderSecretState.Set,
            SecretValueState.KeyMissing => IdentityProviderSecretState.KeyMissing,
            _ => IdentityProviderSecretState.NotSet
        };

    /// <inheritdoc />
    public SecretReadInfo DescribeClientSecret(RtIdentityProvider identityProvider, string? tenantId = null)
    {
        ArgumentNullException.ThrowIfNull(identityProvider);

        var value = GetStoredValue(identityProvider);
        if (value == null)
        {
            return new SecretReadInfo(SecretValueState.NotSet, SecretStorageForm.NotSet, null, null);
        }

        return protector.DescribeSecret(value, new SecretAccessContext(tenantId,
            identityProvider.CkTypeId?.ToString(), ClientSecretAttributeName, ServiceName));
    }

    private static RtSecretValue? GetStoredValue(RtIdentityProvider identityProvider)
    {
        if (identityProvider is not (RtGoogleIdentityProvider or RtMicrosoftIdentityProvider
            or RtFacebookIdentityProvider or RtAzureEntraIdIdentityProvider))
        {
            return null;
        }

        return identityProvider.GetAttributeSecretValueOrDefault(ClientSecretAttributeName);
    }

    // Only a parseable enc:v2 envelope has a key id; a damaged envelope (KeyId null) is left to
    // Unprotect, which rejects it.
    private bool IsKeyMissing(RtSecretValue value)
        => value.IsProtected && value.KeyId != null && !protector.IsKnownKeyId(value.KeyId);
}
