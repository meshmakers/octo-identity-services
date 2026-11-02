using System.Xml.Linq;
using Meshmakers.Octo.Runtime.Contracts.Secrets;

namespace IdentityServerPersistence.SystemStores.DataProtection;

/// <summary>
///     Reads and rewrites the stored XML of ASP.NET Data Protection keys (AB#5530) in the format ASP.NET itself
///     writes when a key encryptor is configured: every element marked <c>requiresEncryption="true"</c> (the
///     <c>masterKey</c>) is replaced by
///     <c>&lt;encryptedSecret decryptorType="..."&gt;&lt;platformKeyRingEncryptedKey&gt;...&lt;/encryptedSecret&gt;</c>.
///     Key id, creation, activation and expiration date and the key material stay the same, so payloads protected
///     before the rewrite unprotect after it.
/// </summary>
/// <remarks>
///     The key store writes the encrypted form itself (instead of <c>KeyManagementOptions.XmlEncryptor</c>) so it can
///     decide per write whether a key may be encrypted yet (rollout flag, fresh store) and so that the
///     <c>decryptorType</c> carries no assembly version - a key written by a newer image stays readable after a
///     rollback to an older image that already ships the decryptor.
/// </remarks>
public static class DataProtectionKeyXml
{
    /// <summary>Root namespace of the ASP.NET Data Protection key XML.</summary>
    public const string DataProtectionNamespace = "http://schemas.asp.net/2015/03/dataProtection";

    /// <summary>
    ///     Version-free type name of <see cref="PlatformKeyRingXmlDecryptor" /> as written into
    ///     <c>decryptorType</c>. Never rename or move the decryptor: stored keys reference this name.
    /// </summary>
    public const string DecryptorTypeName =
        "IdentityServerPersistence.SystemStores.DataProtection.PlatformKeyRingXmlDecryptor, IdentityServerPersistence";

    /// <summary><c>{dataProtection}encryptedSecret</c></summary>
    public static readonly XName EncryptedSecretElementName = XName.Get("encryptedSecret", DataProtectionNamespace);

    /// <summary><c>{dataProtection}requiresEncryption</c></summary>
    public static readonly XName RequiresEncryptionAttributeName =
        XName.Get("requiresEncryption", DataProtectionNamespace);

    /// <summary><c>decryptorType</c> (no namespace)</summary>
    public static readonly XName DecryptorTypeAttributeName = "decryptorType";

    /// <summary>Key id reported for a platform envelope that cannot be parsed.</summary>
    public const string InvalidEnvelopeKeyId = "<invalid>";

    /// <summary>
    ///     True when the key contains a secret in clear text (an element marked <c>requiresEncryption="true"</c>).
    /// </summary>
    public static bool ContainsUnencryptedSecret(XElement key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return FindUnencryptedSecrets(key).Any();
    }

    /// <summary>
    ///     True when the key contains at least one secret wrapped with the platform key ring.
    /// </summary>
    public static bool IsPlatformEncrypted(XElement key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return FindPlatformSecrets(key).Any();
    }

    /// <summary>
    ///     Returns a copy of <paramref name="key" /> with every clear-text secret wrapped by
    ///     <paramref name="encryptor" />. A key without clear-text secrets is returned as an unchanged copy.
    /// </summary>
    /// <exception cref="SecretEncryptionNotConfiguredException">No active platform key</exception>
    public static XElement EncryptSecrets(XElement key, PlatformKeyRingXmlEncryptor encryptor)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(encryptor);

        var copy = new XElement(key);
        foreach (var secret in FindUnencryptedSecrets(copy).ToList())
        {
            var encrypted = encryptor.Encrypt(new XElement(secret));
            secret.ReplaceWith(new XElement(EncryptedSecretElementName,
                new XAttribute(DecryptorTypeAttributeName, DecryptorTypeName),
                encrypted.EncryptedElement));
        }

        // ASP.NET adds "<!-- Warning: the key below is in an unencrypted form. -->" to keys written without an
        // encryptor; it is wrong once the secret is wrapped.
        foreach (var comment in copy.DescendantNodes().OfType<XComment>()
                     .Where(c => c.Value.Contains("unencrypted form", StringComparison.OrdinalIgnoreCase)).ToList())
        {
            comment.Remove();
        }

        return copy;
    }

    /// <summary>
    ///     Returns the platform key ids the key's secrets are wrapped with (empty for a plain key);
    ///     <see cref="InvalidEnvelopeKeyId" /> for an envelope that cannot be parsed.
    /// </summary>
    public static IReadOnlyList<string> GetPlatformKeyIds(XElement key, ISecretAttributeProtector secretProtector)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(secretProtector);

        return FindPlatformSecrets(key)
            .Select(secret => TryGetKeyId(secret, secretProtector) ?? InvalidEnvelopeKeyId)
            .ToList();
    }

    /// <summary>
    ///     Returns a copy of <paramref name="key" /> whose platform-wrapped secrets are re-wrapped with the active
    ///     platform key, and whether anything changed. Secrets already wrapped with the active key id stay as they are.
    /// </summary>
    /// <exception cref="UnknownSecretKeyIdException">A secret is wrapped with a key id that is not in the key ring</exception>
    public static XElement RewrapSecrets(XElement key, PlatformKeyRingXmlDecryptor decryptor,
        PlatformKeyRingXmlEncryptor encryptor, ISecretAttributeProtector secretProtector, out bool changed)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(decryptor);
        ArgumentNullException.ThrowIfNull(encryptor);
        ArgumentNullException.ThrowIfNull(secretProtector);

        changed = false;
        var copy = new XElement(key);
        var activeKeyId = encryptor.ActiveKeyId;
        if (activeKeyId == null)
        {
            return copy;
        }

        foreach (var secret in FindPlatformSecrets(copy).ToList())
        {
            var keyId = TryGetKeyId(secret, secretProtector);
            if (string.Equals(keyId, activeKeyId, StringComparison.Ordinal))
            {
                continue;
            }

            var inner = secret.Elements().Single();
            var plaintext = decryptor.Decrypt(inner);
            inner.ReplaceWith(encryptor.Encrypt(plaintext).EncryptedElement);
            changed = true;
        }

        return copy;
    }

    private static IEnumerable<XElement> FindUnencryptedSecrets(XElement key)
    {
        return key.DescendantsAndSelf()
            .Where(e => string.Equals((string?)e.Attribute(RequiresEncryptionAttributeName), "true",
                            StringComparison.OrdinalIgnoreCase)
                        && !e.Ancestors(EncryptedSecretElementName).Any());
    }

    private static IEnumerable<XElement> FindPlatformSecrets(XElement key)
    {
        return key.Descendants(EncryptedSecretElementName)
            .Where(e => IsPlatformDecryptorType((string?)e.Attribute(DecryptorTypeAttributeName)));
    }

    private static bool IsPlatformDecryptorType(string? decryptorType)
    {
        if (string.IsNullOrWhiteSpace(decryptorType))
        {
            return false;
        }

        var typeName = decryptorType.Split(',')[0].Trim();
        return string.Equals(typeName, typeof(PlatformKeyRingXmlDecryptor).FullName, StringComparison.Ordinal);
    }

    private static string? TryGetKeyId(XElement encryptedSecret, ISecretAttributeProtector secretProtector)
    {
        var inner = encryptedSecret.Elements().FirstOrDefault();
        if (inner == null)
        {
            return null;
        }

        try
        {
            var envelope = PlatformKeyRingXmlDecryptor.GetEnvelope(inner);
            return secretProtector.TryParseEnvelope(envelope, out var info) && info.Version == 2 ? info.KeyId : null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }
}
