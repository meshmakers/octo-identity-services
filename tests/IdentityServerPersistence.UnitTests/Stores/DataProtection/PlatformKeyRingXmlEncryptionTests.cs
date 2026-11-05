using System.Security.Cryptography;
using System.Xml.Linq;
using FluentAssertions;
using IdentityServerPersistence.SystemStores.DataProtection;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Stores.DataProtection;

/// <summary>
///     AB#5530: the Data Protection key XML is wrapped with the platform key ring. Unit level: round trip, tamper,
///     wrong key, unknown key id, plain pass-through, and the real ASP.NET Data Protection stack reading keys the
///     key store wrote (encrypted on write, migrated in place, re-wrapped after a key ring rotation).
///     All keys are generated per test run.
/// </summary>
public sealed class PlatformKeyRingXmlEncryptionTests : IDisposable
{
    private const string Purpose = "AB5530.Tests";
    private readonly List<IDisposable> _disposables = [];

    public void Dispose()
    {
        foreach (var disposable in _disposables)
        {
            disposable.Dispose();
        }
    }

    private T Track<T>(T disposable) where T : IDisposable
    {
        _disposables.Add(disposable);
        return disposable;
    }

    [Fact]
    public void EncryptDecrypt_RoundTripsTheElement()
    {
        var ring = Track(PlatformKeyRing.CreateK1());
        var element = XElement.Parse("<masterKey xmlns:d=\"x\" d:requiresEncryption=\"true\"><value>c2VjcmV0</value></masterKey>");

        var encrypted = new PlatformKeyRingXmlEncryptor(ring.Protector).Encrypt(element);
        var decrypted = new PlatformKeyRingXmlDecryptor(ring.Protector).Decrypt(encrypted.EncryptedElement);

        decrypted.ToString(SaveOptions.DisableFormatting).Should().Be(element.ToString(SaveOptions.DisableFormatting));
        encrypted.DecryptorType.Should().Be(typeof(PlatformKeyRingXmlDecryptor));
    }

    [Fact]
    public void Encrypt_OutputCarriesOnlyTheEnvelopeWithTheKeyIdInItsHeader()
    {
        var ring = Track(PlatformKeyRing.CreateK1());
        var element = XElement.Parse("<masterKey><value>c2VjcmV0LWtleS1tYXRlcmlhbA==</value></masterKey>");

        var encrypted = new PlatformKeyRingXmlEncryptor(ring.Protector).Encrypt(element).EncryptedElement;
        var xml = encrypted.ToString(SaveOptions.DisableFormatting);

        xml.Should().NotContain("c2VjcmV0LWtleS1tYXRlcmlhbA==").And.NotContain("masterKey");
        encrypted.Name.Should().Be(PlatformKeyRingXmlEncryptor.EncryptedElementName);
        encrypted.Element(PlatformKeyRingXmlEncryptor.ValueElementName)!.Value.Should().StartWith("enc:v2:k1:");
    }

    [Fact]
    public void Decrypt_TamperedEnvelope_Throws()
    {
        var ring = Track(PlatformKeyRing.CreateK1());
        var encrypted = new PlatformKeyRingXmlEncryptor(ring.Protector)
            .Encrypt(new XElement("masterKey", "secret")).EncryptedElement;
        var value = encrypted.Element(PlatformKeyRingXmlEncryptor.ValueElementName)!;
        var envelope = value.Value;
        var last = envelope[^2];
        value.Value = envelope[..^2] + (last == 'A' ? 'B' : 'A') + envelope[^1];

        var act = () => new PlatformKeyRingXmlDecryptor(ring.Protector).Decrypt(encrypted);

        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Decrypt_SameKeyIdOtherKeyMaterial_Throws()
    {
        var writer = Track(PlatformKeyRing.CreateK1());
        var reader = Track(PlatformKeyRing.CreateK1()); // same id "k1", different key
        var encrypted = new PlatformKeyRingXmlEncryptor(writer.Protector)
            .Encrypt(new XElement("masterKey", "secret")).EncryptedElement;

        var act = () => new PlatformKeyRingXmlDecryptor(reader.Protector).Decrypt(encrypted);

        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Decrypt_UnknownKeyId_Throws()
    {
        var writer = Track(PlatformKeyRing.CreateK1());
        var reader = Track(PlatformKeyRing.Create(
            new Dictionary<string, byte[]> { ["k2"] = RandomNumberGenerator.GetBytes(32) }, "k2"));
        var encrypted = new PlatformKeyRingXmlEncryptor(writer.Protector)
            .Encrypt(new XElement("masterKey", "secret")).EncryptedElement;

        var act = () => new PlatformKeyRingXmlDecryptor(reader.Protector).Decrypt(encrypted);

        act.Should().Throw<UnknownSecretKeyIdException>();
    }

    [Fact]
    public void Decrypt_PlainElement_IsRefused()
    {
        var ring = Track(PlatformKeyRing.CreateK1());
        var notOurs = new XElement(PlatformKeyRingXmlEncryptor.EncryptedElementName,
            new XElement(PlatformKeyRingXmlEncryptor.ValueElementName, "<masterKey>plain</masterKey>"));

        var act = () => new PlatformKeyRingXmlDecryptor(ring.Protector).Decrypt(notOurs);

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Encrypt_WithoutKeyRing_Throws()
    {
        var empty = Track(PlatformKeyRing.CreateEmpty());
        var encryptor = new PlatformKeyRingXmlEncryptor(empty.Protector);

        encryptor.IsConfigured.Should().BeFalse();
        var act = () => encryptor.Encrypt(new XElement("masterKey", "secret"));

        act.Should().Throw<SecretEncryptionNotConfiguredException>();
    }

    [Fact]
    public void DecryptorTypeName_ResolvesToTheDecryptor_WithoutAssemblyVersion()
    {
        Type.GetType(DataProtectionKeyXml.DecryptorTypeName, throwOnError: true)
            .Should().Be(typeof(PlatformKeyRingXmlDecryptor));
        DataProtectionKeyXml.DecryptorTypeName.Should().NotContain("Version=");
    }

    [Fact]
    public void EncryptSecrets_RealKey_RemovesTheKeyMaterial_AndKeepsIdAndDates()
    {
        var ring = Track(PlatformKeyRing.CreateK1());
        var plainKey = CreatePlainKeyXml(ring);
        var masterKeyValue = GetMasterKeyValue(plainKey);

        var encrypted = DataProtectionKeyXml.EncryptSecrets(plainKey, new PlatformKeyRingXmlEncryptor(ring.Protector));
        var xml = encrypted.ToString(SaveOptions.DisableFormatting);

        xml.Should().NotContain(masterKeyValue).And.NotContain("masterKey").And.NotContain("unencrypted form");
        xml.Should().Contain("enc:v2:k1:");
        DataProtectionKeyXml.ContainsUnencryptedSecret(encrypted).Should().BeFalse();
        DataProtectionKeyXml.IsPlatformEncrypted(encrypted).Should().BeTrue();
        DataProtectionKeyXml.GetPlatformKeyIds(encrypted, ring.Protector).Should().Equal("k1");
        encrypted.Attribute("id")!.Value.Should().Be(plainKey.Attribute("id")!.Value);
        foreach (var date in new[] { "creationDate", "activationDate", "expirationDate" })
        {
            encrypted.Element(date)!.Value.Should().Be(plainKey.Element(date)!.Value);
        }

        encrypted.Descendants(DataProtectionKeyXml.EncryptedSecretElementName).Single()
            .Attribute(DataProtectionKeyXml.DecryptorTypeAttributeName)!.Value
            .Should().Be(DataProtectionKeyXml.DecryptorTypeName);
    }

    [Fact]
    public void EncryptSecrets_ElementWithoutSecret_PassesThroughUnchanged()
    {
        var ring = Track(PlatformKeyRing.CreateK1());
        var revocation = XElement.Parse(
            "<revocation version=\"1\"><revocationDate>2026-11-01T00:00:00Z</revocationDate><key id=\"*\" /><reason>test</reason></revocation>");

        var result = DataProtectionKeyXml.EncryptSecrets(revocation, new PlatformKeyRingXmlEncryptor(ring.Protector));

        result.ToString(SaveOptions.DisableFormatting).Should().Be(revocation.ToString(SaveOptions.DisableFormatting));
        DataProtectionKeyXml.ContainsUnencryptedSecret(revocation).Should().BeFalse();
        DataProtectionKeyXml.IsPlatformEncrypted(revocation).Should().BeFalse();
    }

    [Fact]
    public void AspNetDataProtection_ReadsPlainKeys_Unchanged()
    {
        var ring = Track(PlatformKeyRing.CreateK1());
        var repository = new InMemoryXmlRepository();
        var payload = CreateProvider(repository, ring).CreateProtector(Purpose).Protect("hello");

        DataProtectionKeyXml.ContainsUnencryptedSecret(repository.Elements.Single()).Should().BeTrue();
        CreateProvider(repository, ring).CreateProtector(Purpose).Unprotect(payload).Should().Be("hello");
    }

    [Fact]
    public void AspNetDataProtection_KeyEncryptedOnWrite_IsReadableByAnotherInstance()
    {
        var podA = Track(PlatformKeyRing.CreateK1());
        var podB = Track(PlatformKeyRing.Create(podA.Keys, "k1")); // same cluster key ring, other process
        var repository = new InMemoryXmlRepository(e =>
            DataProtectionKeyXml.EncryptSecrets(e, new PlatformKeyRingXmlEncryptor(podA.Protector)));

        var payload = CreateProvider(repository, podA).CreateProtector(Purpose).Protect("hello");

        var stored = repository.Elements.Single();
        DataProtectionKeyXml.ContainsUnencryptedSecret(stored).Should().BeFalse();
        stored.ToString(SaveOptions.DisableFormatting).Should().NotContain("masterKey");
        CreateProvider(repository, podB).CreateProtector(Purpose).Unprotect(payload).Should().Be("hello");
    }

    [Fact]
    public void AspNetDataProtection_PlainKeyMigratedInPlace_KeepsProtectedPayloadsValid()
    {
        var ring = Track(PlatformKeyRing.CreateK1());
        var repository = new InMemoryXmlRepository();
        var cachedProvider = CreateProvider(repository, ring);
        var payload = cachedProvider.CreateProtector(Purpose).Protect("session-cookie");
        var keyId = repository.Elements.Single().Attribute("id")!.Value;

        repository.ReplaceAll(e => DataProtectionKeyXml.EncryptSecrets(e, new PlatformKeyRingXmlEncryptor(ring.Protector)));

        repository.Elements.Single().Attribute("id")!.Value.Should().Be(keyId);
        DataProtectionKeyXml.ContainsUnencryptedSecret(repository.Elements.Single()).Should().BeFalse();
        cachedProvider.CreateProtector(Purpose).Unprotect(payload).Should().Be("session-cookie",
            "a pod that loaded the key ring before the migration keeps working");
        CreateProvider(repository, ring).CreateProtector(Purpose).Unprotect(payload).Should().Be("session-cookie",
            "a pod that loads the migrated key ring reads the same key");
    }

    [Fact]
    public void AspNetDataProtection_PlatformKeyRotation_OldKeyIdStaysReadable_RewrapAllowsRemovingIt()
    {
        var k1 = Track(PlatformKeyRing.CreateK1());
        var repository = new InMemoryXmlRepository(e =>
            DataProtectionKeyXml.EncryptSecrets(e, new PlatformKeyRingXmlEncryptor(k1.Protector)));
        var payload = CreateProvider(repository, k1).CreateProtector(Purpose).Protect("token");

        // ActiveKeyId k1 -> k2, k1 kept: the stored key (wrapped with k1) is still readable.
        var k2 = Track(k1.RotateTo("k2"));
        CreateProvider(repository, k2).CreateProtector(Purpose).Unprotect(payload).Should().Be("token");

        // Removing k1 BEFORE the re-wrap makes the key unreadable - the documented order matters.
        var k2Only = Track(k2.Without("k1", "k2"));
        var tooEarly = () => CreateProvider(repository, k2Only).CreateProtector(Purpose).Unprotect(payload);
        tooEarly.Should().Throw<CryptographicException>();

        // Re-wrap with the active key k2, then k1 can go.
        repository.ReplaceAll(e => DataProtectionKeyXml.RewrapSecrets(e, new PlatformKeyRingXmlDecryptor(k2.Protector),
            new PlatformKeyRingXmlEncryptor(k2.Protector), k2.Protector, out _));
        // (The "too early" instance could not read the key and created a second one; both are re-wrapped.)
        repository.Elements.SelectMany(e => DataProtectionKeyXml.GetPlatformKeyIds(e, k2.Protector))
            .Should().NotBeEmpty().And.OnlyContain(keyId => keyId == "k2");
        CreateProvider(repository, k2Only).CreateProtector(Purpose).Unprotect(payload).Should().Be("token");
    }

    [Fact]
    public void RewrapSecrets_KeyAlreadyOnTheActiveKeyId_IsUnchanged()
    {
        var ring = Track(PlatformKeyRing.CreateK1());
        var encrypted = DataProtectionKeyXml.EncryptSecrets(CreatePlainKeyXml(ring),
            new PlatformKeyRingXmlEncryptor(ring.Protector));

        var result = DataProtectionKeyXml.RewrapSecrets(encrypted, new PlatformKeyRingXmlDecryptor(ring.Protector),
            new PlatformKeyRingXmlEncryptor(ring.Protector), ring.Protector, out var changed);

        changed.Should().BeFalse();
        result.ToString(SaveOptions.DisableFormatting).Should().Be(encrypted.ToString(SaveOptions.DisableFormatting));
    }

    private XElement CreatePlainKeyXml(PlatformKeyRing ring)
    {
        var repository = new InMemoryXmlRepository();
        CreateProvider(repository, ring).CreateProtector(Purpose).Protect("x");
        return repository.Elements.Single();
    }

    private static string GetMasterKeyValue(XElement key)
    {
        var value = key.Descendants().Single(e => e.Name.LocalName == "masterKey").Elements()
            .Single(e => e.Name.LocalName == "value").Value;
        value.Should().NotBeNullOrWhiteSpace();
        return value;
    }

    private IDataProtectionProvider CreateProvider(IXmlRepository repository, PlatformKeyRing ring)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(ring.Protector);
        services.AddDataProtection().SetApplicationName(OctoDataProtectionServiceCollectionExtensions.ApplicationName);
        services.Configure<KeyManagementOptions>(options => options.XmlRepository = repository);
        var provider = Track(services.BuildServiceProvider());
        return provider.GetRequiredService<IDataProtectionProvider>();
    }

    /// <summary>
    ///     In-memory key repository; <c>onStore</c> models what <c>DataProtectionKeyStore</c> does on write.
    /// </summary>
    private sealed class InMemoryXmlRepository(Func<XElement, XElement>? onStore = null) : IXmlRepository
    {
        private readonly List<XElement> _elements = [];

        public IReadOnlyList<XElement> Elements => _elements;

        public IReadOnlyCollection<XElement> GetAllElements()
        {
            // Round trip through text like the database does.
            return _elements.Select(e => XElement.Parse(e.ToString(SaveOptions.DisableFormatting))).ToList();
        }

        public void StoreElement(XElement element, string friendlyName)
        {
            _elements.Add(onStore?.Invoke(element) ?? element);
        }

        public void ReplaceAll(Func<XElement, XElement> transform)
        {
            for (var i = 0; i < _elements.Count; i++)
            {
                _elements[i] = transform(_elements[i]);
            }
        }
    }
}
