using System.Xml.Linq;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace IdentityServerPersistence.SystemStores.DataProtection;

/// <summary>
///     Wraps the secret part of an ASP.NET Data Protection key (the <c>masterKey</c> element) with the platform key
///     ring <c>SecretEncryption</c> (AB#5530): AES-256-GCM through <see cref="ISecretAttributeProtector" />, envelope
///     <c>enc:v2:&lt;kid&gt;:...</c>. No certificate and no new secret: the key ring is already delivered to every
///     cluster (AB#5528/AB#5536).
/// </summary>
/// <remarks>
///     Output: <c>&lt;platformKeyRingEncryptedKey xmlns="urn:meshmakers:octo:dataprotection:v1"&gt;&lt;value&gt;enc:v2:k1:...&lt;/value&gt;&lt;/platformKeyRingEncryptedKey&gt;</c>.
///     The key id of the platform key ring is part of the envelope header (readable without a key); the plaintext
///     element is serialized without formatting and is never logged.
/// </remarks>
public sealed class PlatformKeyRingXmlEncryptor(ISecretAttributeProtector secretProtector) : IXmlEncryptor
{
    /// <summary>XML namespace of the encrypted element.</summary>
    public const string XmlNamespace = "urn:meshmakers:octo:dataprotection:v1";

    /// <summary>Name of the element that replaces the secret part of a key.</summary>
    public static readonly XName EncryptedElementName = XName.Get("platformKeyRingEncryptedKey", XmlNamespace);

    /// <summary>Name of the child element that carries the envelope.</summary>
    public static readonly XName ValueElementName = XName.Get("value", XmlNamespace);

    /// <summary>
    ///     True when an active platform key is configured, i.e. <see cref="Encrypt" /> can work.
    /// </summary>
    public bool IsConfigured => secretProtector.IsConfigured;

    /// <summary>
    ///     The platform key id new elements are wrapped with; <c>null</c> when not configured.
    /// </summary>
    public string? ActiveKeyId => secretProtector.ActiveKeyId;

    /// <inheritdoc />
    /// <exception cref="SecretEncryptionNotConfiguredException">No active platform key is configured</exception>
    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        ArgumentNullException.ThrowIfNull(plaintextElement);

        var envelope = secretProtector.Protect(plaintextElement.ToString(SaveOptions.DisableFormatting)).Envelope
                       ?? throw new InvalidOperationException("The platform key ring returned no envelope.");

        var encryptedElement = new XElement(EncryptedElementName, new XElement(ValueElementName, envelope));
        return new EncryptedXmlInfo(encryptedElement, typeof(PlatformKeyRingXmlDecryptor));
    }
}
