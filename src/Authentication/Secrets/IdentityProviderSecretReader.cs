using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.Authentication.Secrets;

/// <summary>
///     Reads the plaintext <c>ClientSecret</c> of an external identity provider (Google, Microsoft,
///     Facebook, Azure Entra ID) for the authentication handler options (AB#5540, concept AB#5528).
/// </summary>
/// <remarks>
///     The attribute is of the CK value type <c>Secret</c>: stored as an <c>enc:v2</c> envelope, or —
///     until the encrypt sweep has run — as legacy clear text or an <c>enc:v1</c> value. All three
///     forms go through <see cref="ISecretAttributeProtector.Unprotect(Meshmakers.Octo.Runtime.Contracts.RepositoryEntities.RtSecretValue, SecretAccessContext?)" />,
///     which counts every decrypt (<c>octo.secrets.decrypt</c>). The value is never logged.
/// </remarks>
public interface IIdentityProviderSecretReader
{
    /// <summary>
    ///     Returns the plaintext client secret of <paramref name="identityProvider" />, or <c>null</c>
    ///     when the provider has none (not set, or a provider type without a client secret).
    /// </summary>
    /// <param name="identityProvider">The identity provider entity</param>
    /// <param name="tenantId">Tenant the provider belongs to (decrypt counter tag)</param>
    /// <returns>The plaintext or <c>null</c></returns>
    /// <exception cref="SecretEncryptionNotConfiguredException">An encrypted value but no key ring</exception>
    /// <exception cref="UnknownSecretKeyIdException">The value was encrypted with a key this host does not know</exception>
    string? GetClientSecret(RtIdentityProvider identityProvider, string? tenantId);
}

/// <inheritdoc />
internal sealed class IdentityProviderSecretReader(ISecretAttributeProtector protector) : IIdentityProviderSecretReader
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

        if (identityProvider is not (RtGoogleIdentityProvider or RtMicrosoftIdentityProvider
            or RtFacebookIdentityProvider or RtAzureEntraIdIdentityProvider))
        {
            return null;
        }

        var value = identityProvider.GetAttributeSecretValueOrDefault(ClientSecretAttributeName);
        if (value == null)
        {
            return null;
        }

        var plaintext = protector.Unprotect(value, new SecretAccessContext(tenantId,
            identityProvider.CkTypeId?.ToString(), ClientSecretAttributeName, ServiceName));
        return string.IsNullOrEmpty(plaintext) ? null : plaintext;
    }
}
