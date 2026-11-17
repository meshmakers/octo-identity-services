using System.Xml.Linq;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores;
using IdentityServerPersistence.SystemStores.DataProtection;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#5530 on a real MongoDB: the identity Data Protection key ring is encrypted at rest with the platform key
///     ring. Every "host" below is an own ASP.NET Data Protection stack (own service provider, own in-memory key
///     ring cache) on the shared system database - a model of identity pods. Each fact starts from an empty key
///     store; all keys are generated per test run.
/// </summary>
public class DataProtectionKeyEncryptionIntegrationTests : IClassFixture<IdentityServicesFixture>, IDisposable
{
    private const string Purpose = "AB5530.IntegrationTests";
    private readonly List<IDisposable> _disposables = [];
    private readonly IdentityServicesFixture _fixture;

    public DataProtectionKeyEncryptionIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    public void Dispose()
    {
        foreach (var disposable in _disposables)
        {
            disposable.Dispose();
        }
    }

    [Fact]
    public async Task FreshStore_FirstKey_IsStoredEncrypted_AndProtectsAcrossHosts()
    {
        await GivenEmptyKeyStoreAsync();
        var ring = Track(PlatformKeyRing.CreateK1());
        var otherPodRing = Track(PlatformKeyRing.Create(ring.Keys, "k1"));

        // Flag off (release-1 default), but the store is empty: no older pod can depend on a plain key.
        var payload = CreateHost(CreateStore(ring, encryptExistingKeys: false), ring).GetDataProtector(Purpose)
            .Protect("cookie");

        var stored = (await LoadRawKeysAsync()).Single();
        stored.XmlData.Should().NotContain("masterKey").And.Contain("enc:v2:k1:");
        DataProtectionKeyXml.ContainsUnencryptedSecret(XElement.Parse(stored.XmlData)).Should().BeFalse();

        CreateHost(CreateStore(otherPodRing, encryptExistingKeys: false), otherPodRing).GetDataProtector(Purpose)
            .Unprotect(payload).Should().Be("cookie", "a key created by pod A is readable by pod B");
    }

    [Fact]
    public async Task RawDatabaseDump_ContainsNoUsableKeyMaterial()
    {
        await GivenEmptyKeyStoreAsync();
        var ring = Track(PlatformKeyRing.CreateK1());
        await GivenRawKeyAsync(CreatePlainKeyXml(ring)); // prod today: one plain key
        var store = CreateStore(ring, encryptExistingKeys: true);
        CreateHost(store, ring).GetRequiredService<IKeyManager>()
            .CreateNewKey(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90)); // a new key with the flag on

        (await store.CheckAndProtectStoredKeysAsync(encryptPlainKeys: true)).EncryptedKeys.Should().Be(1);

        // The master keys, as ASP.NET holds them in memory (decrypted with the platform key ring).
        var masterKeys = (await LoadRawKeysAsync())
            .Select(k => GetMasterKeyValue(XElement.Parse(k.XmlData), ring))
            .ToList();
        masterKeys.Should().HaveCount(2);

        // A dump of every collection of the system database, read directly with the MongoDB driver.
        var dump = await DumpSystemDatabaseAsync();
        dump.Should().Contain("enc:v2:k1:");
        dump.Should().NotContain("masterKey");
        foreach (var masterKey in masterKeys)
        {
            dump.Should().NotContain(masterKey, "the database must not contain the Data Protection key material");
        }
    }

    [Fact]
    public async Task ExistingPlainKeys_FlagOff_AreReadUnchanged_AndNewKeysStayPlain()
    {
        await GivenEmptyKeyStoreAsync();
        var ring = Track(PlatformKeyRing.CreateK1());
        var plainKey = CreatePlainKeyXml(ring);
        await GivenRawKeyAsync(plainKey);

        var host = CreateHost(CreateStore(ring, encryptExistingKeys: false), ring);
        var payload = host.GetDataProtector(Purpose).Protect("cookie");
        host.GetRequiredService<IKeyManager>()
            .CreateNewKey(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90));

        var keys = await LoadRawKeysAsync();
        keys.Should().HaveCount(2);
        keys.Should().OnlyContain(k => DataProtectionKeyXml.ContainsUnencryptedSecret(XElement.Parse(k.XmlData)),
            "with the flag off a store that holds keys gets plain keys, so pods of the previous image keep reading them");
        keys.Should().Contain(k => k.XmlData == plainKey.ToString(SaveOptions.DisableFormatting),
            "the existing key is not touched");
        CreateHost(CreateStore(ring, encryptExistingKeys: false), ring).GetDataProtector(Purpose)
            .Unprotect(payload).Should().Be("cookie");
    }

    [Fact]
    public async Task FlagOn_Migration_EncryptsInPlace_SessionsSurvive_AcrossReplicas_Idempotently()
    {
        await GivenEmptyKeyStoreAsync();
        var ring = Track(PlatformKeyRing.CreateK1());
        var plainKey = CreatePlainKeyXml(ring);
        await GivenRawKeyAsync(plainKey);
        var before = (await LoadRawKeysAsync()).Single();

        // Pod B runs and has loaded the key ring before the migration.
        var podB = CreateHost(CreateStore(ring, encryptExistingKeys: false), ring);
        var payload = podB.GetDataProtector(Purpose).Protect("session-cookie");

        // Pod A starts with the flag on and migrates.
        var storeA = CreateStore(ring, encryptExistingKeys: true);
        var first = await storeA.CheckAndProtectStoredKeysAsync(encryptPlainKeys: true);
        first.Should().Be(new DataProtectionKeyMaintenanceResult(true, 1, 1, 0, 0));

        var after = (await LoadRawKeysAsync()).Single();
        after.RtId.Should().Be(before.RtId, "the key is rewritten in place, no duplicate");
        after.FriendlyName.Should().Be(before.FriendlyName);
        var migrated = XElement.Parse(after.XmlData);
        DataProtectionKeyXml.ContainsUnencryptedSecret(migrated).Should().BeFalse();
        migrated.Attribute("id")!.Value.Should().Be(plainKey.Attribute("id")!.Value);
        foreach (var date in new[] { "creationDate", "activationDate", "expirationDate" })
        {
            migrated.Element(date)!.Value.Should().Be(plainKey.Element(date)!.Value);
        }

        podB.GetDataProtector(Purpose).Unprotect(payload).Should().Be("session-cookie",
            "pod B keeps working with its cached key ring");
        CreateHost(CreateStore(ring, encryptExistingKeys: false), ring).GetDataProtector(Purpose)
            .Unprotect(payload).Should().Be("session-cookie", "a pod that reloads the key ring reads the migrated key");

        // A second pod running the same startup step at the same time / later changes nothing.
        var second = await CreateStore(ring, encryptExistingKeys: true).CheckAndProtectStoredKeysAsync(true);
        second.Should().Be(new DataProtectionKeyMaintenanceResult(true, 1, 0, 0, 0));

        // Key rotation with the flag on: new key and the key after RevokeAllKeys are written encrypted.
        var hostA = CreateHost(storeA, ring);
        var keyManager = hostA.GetRequiredService<IKeyManager>();
        keyManager.CreateNewKey(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90));
        keyManager.RevokeAllKeys(DateTimeOffset.UtcNow, "AB#5530 test");
        CreateHost(storeA, ring).GetDataProtector(Purpose).Protect("after-revoke");

        var all = await LoadRawKeysAsync();
        all.Count.Should().BeGreaterThanOrEqualTo(3);
        all.Should().OnlyContain(k => !DataProtectionKeyXml.ContainsUnencryptedSecret(XElement.Parse(k.XmlData)));
    }

    [Fact]
    public async Task PlatformKeyRotation_OldKeyIdStaysReadable_AndStartupRewrapsWithTheNewActiveKey()
    {
        await GivenEmptyKeyStoreAsync();
        var k1 = Track(PlatformKeyRing.CreateK1());
        var payload = CreateHost(CreateStore(k1, encryptExistingKeys: true), k1).GetDataProtector(Purpose)
            .Protect("token");

        var k2 = Track(k1.RotateTo("k2"));
        CreateHost(CreateStore(k2, encryptExistingKeys: true), k2).GetDataProtector(Purpose)
            .Unprotect(payload).Should().Be("token", "k1 is kept in the ring after the rotation");

        var result = await CreateStore(k2, encryptExistingKeys: false).CheckAndProtectStoredKeysAsync(false);
        result.RewrappedKeys.Should().Be(1);
        DataProtectionKeyXml.GetPlatformKeyIds(XElement.Parse((await LoadRawKeysAsync()).Single().XmlData),
            k2.Protector).Should().Equal("k2");

        var k2Only = Track(k2.Without("k1", "k2"));
        CreateHost(CreateStore(k2Only, encryptExistingKeys: true), k2Only).GetDataProtector(Purpose)
            .Unprotect(payload).Should().Be("token", "after the re-wrap k1 can be removed");
    }

    [Fact]
    public async Task MissingPlatformKey_IdentityRefusesToStart()
    {
        await GivenEmptyKeyStoreAsync();
        var k1 = Track(PlatformKeyRing.CreateK1());
        CreateHost(CreateStore(k1, encryptExistingKeys: true), k1).GetDataProtector(Purpose).Protect("x");
        var friendlyName = (await LoadRawKeysAsync()).Single().FriendlyName;

        var otherRing = Track(PlatformKeyRing.Create(
            new Dictionary<string, byte[]> { ["k9"] = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32) },
            "k9"));
        var startup = CreateStartupService(otherRing, encryptExistingKeys: false);

        var act = () => startup.StartAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<DataProtectionKeyRingException>())
            .Which.Message.Should().Contain(friendlyName).And.Contain("k1");

        var noRing = Track(PlatformKeyRing.CreateEmpty());
        var withoutAnyKey = () => CreateStartupService(noRing, encryptExistingKeys: false)
            .StartAsync(TestContext.Current.CancellationToken);
        await withoutAnyKey.Should().ThrowAsync<DataProtectionKeyRingException>(
            "encrypted keys and no key ring at all: never start and silently create plain keys");
    }

    [Fact]
    public async Task SameKeyIdOtherKeyMaterial_IsReportedAndLeftUnchanged_NotFatal()
    {
        await GivenEmptyKeyStoreAsync();
        var sourceCluster = Track(PlatformKeyRing.CreateK1());
        CreateHost(CreateStore(sourceCluster, encryptExistingKeys: true), sourceCluster).GetDataProtector(Purpose)
            .Protect("x");
        var before = (await LoadRawKeysAsync()).Single().XmlData;

        // Database restored into a cluster whose key is also called "k1" (other material), which has rotated to k2.
        var targetCluster = Track(Track(PlatformKeyRing.CreateK1()).RotateTo("k2"));
        var result = await CreateStore(targetCluster, encryptExistingKeys: true).CheckAndProtectStoredKeysAsync(true);

        result.Should().Be(new DataProtectionKeyMaintenanceResult(true, 1, 0, 0, 0));
        (await LoadRawKeysAsync()).Single().XmlData.Should().Be(before, "an unreadable key is never rewritten");
    }

    [Fact]
    public async Task FlagOnWithoutKeyRing_IdentityRefusesToStart_AndNeverWritesPlain()
    {
        await GivenEmptyKeyStoreAsync();
        var noRing = Track(PlatformKeyRing.CreateEmpty());

        var startup = () => CreateStartupService(noRing, encryptExistingKeys: true)
            .StartAsync(TestContext.Current.CancellationToken);
        (await startup.Should().ThrowAsync<DataProtectionKeyRingException>())
            .Which.Message.Should().Contain("OCTO_SECRETENCRYPTION__KEYS__");

        var write = () => CreateStore(noRing, encryptExistingKeys: true)
            .StoreElement(CreatePlainKeyXml(Track(PlatformKeyRing.CreateK1())), $"key-{Guid.NewGuid():D}");
        write.Should().Throw<DataProtectionKeyRingException>();
        (await LoadRawKeysAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task FlagOffWithoutKeyRing_StartsAndStoresPlain_WithAWarning()
    {
        await GivenEmptyKeyStoreAsync();
        var noRing = Track(PlatformKeyRing.CreateEmpty());

        await CreateStartupService(noRing, encryptExistingKeys: false).StartAsync(TestContext.Current.CancellationToken);
        var payload = CreateHost(CreateStore(noRing, encryptExistingKeys: false), noRing).GetDataProtector(Purpose)
            .Protect("x");

        DataProtectionKeyXml.ContainsUnencryptedSecret(XElement.Parse((await LoadRawKeysAsync()).Single().XmlData))
            .Should().BeTrue();
        CreateHost(CreateStore(noRing, encryptExistingKeys: false), noRing).GetDataProtector(Purpose)
            .Unprotect(payload).Should().Be("x");
    }

    [Fact]
    public async Task LegacyFileSeed_FlagOn_ImportsOnce_AndStoresEncrypted()
    {
        await GivenEmptyKeyStoreAsync();
        var ring = Track(PlatformKeyRing.CreateK1());
        var plainKey = CreatePlainKeyXml(ring, out var payload);
        var tempDir = Path.Combine(Path.GetTempPath(), $"dp-seed-ab5530-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(tempDir, $"key-{plainKey.Attribute("id")!.Value}.xml"),
                plainKey.ToString(), TestContext.Current.CancellationToken);

            var store = CreateStore(ring, encryptExistingKeys: true, legacyPath: tempDir);
            CreateHost(store, ring).GetDataProtector(Purpose).Unprotect(payload).Should().Be("seeded");

            var stored = (await LoadRawKeysAsync()).Single();
            stored.XmlData.Should().NotContain("masterKey");
            XElement.Parse(stored.XmlData).Attribute("id")!.Value.Should().Be(plainKey.Attribute("id")!.Value);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    /// <summary>
    ///     Key rings of other services (shared Data Protection key store of octo-common-services) live in the same
    ///     collection under the stored name <c>&lt;ApplicationName&gt;/key-…</c>, with a <c>decryptorType</c> identity
    ///     cannot resolve. Identity keeps its own ring: it neither starts to use nor rewrites nor refuses such a key.
    /// </summary>
    [Fact]
    public async Task ForeignServiceKeys_InTheSharedStore_AreIgnoredByIdentity()
    {
        await GivenEmptyKeyStoreAsync();
        var ring = Track(PlatformKeyRing.CreateK1());
        var identityKey = CreatePlainKeyXml(ring, out var identityPayload);
        await GivenRawKeyAsync(identityKey);

        // A newer key of another service: encrypted with the platform key ring like identity's, but referencing the
        // decryptor of the shared helper, and another plain one (a service without SecretEncryption).
        var encryptedServiceKey = CreateServiceKeyXml(ring, encrypted: true);
        var plainServiceKey = CreateServiceKeyXml(ring, encrypted: false);
        await GivenRawKeyAsync(encryptedServiceKey, $"{ServiceApplicationName}/key-{encryptedServiceKey.Attribute("id")!.Value}");
        await GivenRawKeyAsync(plainServiceKey, $"{ServiceApplicationName}/key-{plainServiceKey.Attribute("id")!.Value}");
        var before = await LoadRawKeysAsync();

        // Startup check with the flag on: no refusal, no rewrite of the service keys.
        await CreateStartupService(ring, encryptExistingKeys: true).StartAsync(TestContext.Current.CancellationToken);
        var after = await LoadRawKeysAsync();
        foreach (var serviceKey in before.Where(k => k.FriendlyName.Contains('/')))
        {
            after.Single(k => k.FriendlyName == serviceKey.FriendlyName).XmlData.Should().Be(serviceKey.XmlData,
                "identity must never rewrite the key of another service");
        }

        // Key ring: identity reads its own payloads and protects with its own key.
        var host = CreateHost(CreateStore(ring, encryptExistingKeys: true), ring);
        host.GetDataProtector(Purpose).Unprotect(identityPayload).Should().Be("seeded");
        var keyManager = host.GetRequiredService<IKeyManager>();
        keyManager.GetAllKeys().Select(k => k.KeyId.ToString())
            .Should().BeEquivalentTo([identityKey.Attribute("id")!.Value],
                "the key ring of identity holds only the identity keys");
        var payload = host.GetDataProtector(Purpose).Protect("new-cookie");
        CreateHost(CreateStore(ring, encryptExistingKeys: true), ring).GetDataProtector(Purpose).Unprotect(payload)
            .Should().Be("new-cookie");
    }

    /// <summary>
    ///     The shared key store of octo-common-services on the real system database, next to the identity key ring:
    ///     replicas of a service share their keys, the keys survive a restart, they are stored encrypted under the
    ///     service prefix, and identity neither loads nor rewrites them.
    /// </summary>
    [Fact]
    public async Task SharedServiceKeyRing_OnTheSystemDatabase_IsSharedAndKeptApartFromIdentity()
    {
        await GivenEmptyKeyStoreAsync();
        var ring = Track(PlatformKeyRing.CreateK1());
        var identityPayload = CreateHost(CreateStore(ring, encryptExistingKeys: true), ring).GetDataProtector(Purpose)
            .Protect("identity-cookie");

        var replicaA = CreateServiceHost(ServiceApplicationName, ring);
        var replicaB = CreateServiceHost(ServiceApplicationName, ring);
        var payload = replicaA.GetDataProtector(Purpose).Protect("oidc-state");
        replicaB.GetDataProtector(Purpose).Unprotect(payload).Should().Be("oidc-state");
        CreateServiceHost(ServiceApplicationName, ring).GetDataProtector(Purpose).Unprotect(payload)
            .Should().Be("oidc-state", "the key survives a restart of all replicas");

        var otherService = CreateServiceHost("OctoBotServices", ring);
        otherService.Invoking(h => h.GetDataProtector(Purpose).Unprotect(payload))
            .Should().Throw<System.Security.Cryptography.CryptographicException>();

        var stored = await LoadRawKeysAsync();
        var serviceKeys = stored.Where(k => k.FriendlyName.StartsWith(ServiceApplicationName + "/key-",
            StringComparison.Ordinal)).ToList();
        serviceKeys.Should().ContainSingle();
        serviceKeys.Single().XmlData.Should().NotContain("masterKey").And.Contain("enc:v2:k1:")
            .And.Contain(ServiceDecryptorTypeName);
        stored.Should().ContainSingle(k => k.FriendlyName.StartsWith("OctoBotServices/key-", StringComparison.Ordinal));

        var before = await LoadRawKeysAsync();
        await CreateStartupService(ring, encryptExistingKeys: true).StartAsync(TestContext.Current.CancellationToken);
        (await LoadRawKeysAsync()).Select(k => (k.FriendlyName, k.XmlData))
            .Should().BeEquivalentTo(before.Select(k => (k.FriendlyName, k.XmlData)));
        var identity = CreateHost(CreateStore(ring, encryptExistingKeys: true), ring);
        identity.GetDataProtector(Purpose).Unprotect(identityPayload).Should().Be("identity-cookie");
        identity.GetRequiredService<IKeyManager>().GetAllKeys().Should().ContainSingle(
            "identity loads only its own key, not the two service keys");
    }

    /// <summary>A replica of another service: the shared key store of octo-common-services on the fixture's database.</summary>
    private ServiceProvider CreateServiceHost(string applicationName, PlatformKeyRing ring)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(ring.Protector);
        services.AddSingleton(_fixture.GetSystemContext());
        Meshmakers.Octo.Services.Infrastructure.DataProtection.OctoDataProtectionServiceCollectionExtensions
            .AddOctoDataProtectionKeyRing(services, applicationName);
        return Track(services.BuildServiceProvider());
    }

    private const string ServiceApplicationName = "OctoAssetRepositoryServices";

    /// <summary>
    ///     Version-free decryptor type name the shared key store of octo-common-services writes; deliberately a string
    ///     here, so the test also models an identity image that does not ship the type.
    /// </summary>
    private const string ServiceDecryptorTypeName =
        "Meshmakers.Octo.Services.Infrastructure.DataProtection.PlatformKeyRingXmlDecryptor, " +
        "Meshmakers.Octo.Services.Infrastructure";

    /// <summary>A key as the shared key store of another service writes it.</summary>
    private XElement CreateServiceKeyXml(PlatformKeyRing ring, bool encrypted)
    {
        var plain = CreatePlainKeyXml(ring);
        if (!encrypted)
        {
            return plain;
        }

        var key = DataProtectionKeyXml.EncryptSecrets(plain, new PlatformKeyRingXmlEncryptor(ring.Protector));
        foreach (var secret in key.Descendants(DataProtectionKeyXml.EncryptedSecretElementName))
        {
            secret.SetAttributeValue(DataProtectionKeyXml.DecryptorTypeAttributeName, ServiceDecryptorTypeName);
        }

        return key;
    }

    private async Task GivenRawKeyAsync(XElement key, string friendlyName)
    {
        var repository = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        await repository.InsertOneRtEntityAsync(session, new RtDataProtectionKey
        {
            RtId = OctoObjectId.GenerateNewId(),
            FriendlyName = friendlyName,
            XmlData = key.ToString(SaveOptions.DisableFormatting),
            CreationDateTime = DateTime.UtcNow
        });
        await session.CommitTransactionAsync();
    }

    private T Track<T>(T disposable) where T : IDisposable
    {
        _disposables.Add(disposable);
        return disposable;
    }

    private DataProtectionKeyStore CreateStore(PlatformKeyRing ring, bool encryptExistingKeys, string? legacyPath = null)
    {
        return new DataProtectionKeyStore(
            _fixture.Provider!.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new OctoIdentityServicesOptions
            {
                DataProtectionKeysPath = legacyPath,
                DataProtection = new IdentityDataProtectionOptions { EncryptExistingKeys = encryptExistingKeys }
            }),
            ring.Protector);
    }

    private DataProtectionKeyRingStartupService CreateStartupService(PlatformKeyRing ring, bool encryptExistingKeys)
    {
        var options = Options.Create(new OctoIdentityServicesOptions
        {
            DataProtection = new IdentityDataProtectionOptions { EncryptExistingKeys = encryptExistingKeys }
        });
        return new DataProtectionKeyRingStartupService(
            new DataProtectionKeyStore(_fixture.Provider!.GetRequiredService<IServiceScopeFactory>(), options,
                ring.Protector),
            ring.Protector, options);
    }

    /// <summary>An identity "pod": own Data Protection stack on the given key store.</summary>
    private ServiceProvider CreateHost(IXmlRepository store, PlatformKeyRing ring)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(ring.Protector);
        services.AddDataProtection().SetApplicationName(OctoDataProtectionServiceCollectionExtensions.ApplicationName);
        services.Configure<KeyManagementOptions>(options => options.XmlRepository = store);
        return Track(services.BuildServiceProvider());
    }

    private XElement CreatePlainKeyXml(PlatformKeyRing ring)
    {
        return CreatePlainKeyXml(ring, out _);
    }

    /// <summary>A key as an image without AB#5530 writes it (plain XML), plus a payload protected with it.</summary>
    private XElement CreatePlainKeyXml(PlatformKeyRing ring, out string payload)
    {
        var repository = new MemoryRepository();
        payload = CreateHost(repository, ring).GetDataProtector(Purpose).Protect("seeded");
        return repository.Elements.Single();
    }

    private static string GetMasterKeyValue(XElement key, PlatformKeyRing ring)
    {
        var decryptor = new PlatformKeyRingXmlDecryptor(ring.Protector);
        var secret = key.Descendants(DataProtectionKeyXml.EncryptedSecretElementName).Single();
        var masterKey = decryptor.Decrypt(secret.Elements().Single());
        var value = masterKey.Elements().Single(e => e.Name.LocalName == "value").Value;
        value.Should().NotBeNullOrWhiteSpace();
        return value;
    }

    private async Task GivenEmptyKeyStoreAsync()
    {
        await _fixture.InitializeAsync();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);

        var repository = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        foreach (var key in await LoadRawKeysAsync())
        {
            using var session = await repository.GetSessionAsync();
            session.StartTransaction();
            await repository.DeleteOneRtEntityByRtIdAsync<RtDataProtectionKey>(session, key.RtId, Meshmakers.Octo.Runtime.Contracts.Repositories.DeleteOptions.Erase);
            await session.CommitTransactionAsync();
        }
    }

    private async Task GivenRawKeyAsync(XElement key)
    {
        var repository = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        await repository.InsertOneRtEntityAsync(session, new RtDataProtectionKey
        {
            RtId = OctoObjectId.GenerateNewId(),
            FriendlyName = $"key-{key.Attribute("id")!.Value}",
            XmlData = key.ToString(SaveOptions.DisableFormatting),
            CreationDateTime = DateTime.UtcNow
        });
        await session.CommitTransactionAsync();
    }

    private async Task<List<RtDataProtectionKey>> LoadRawKeysAsync()
    {
        var repository = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var result = await repository.GetRtEntitiesByTypeAsync<RtDataProtectionKey>(session,
            RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return result.Items.ToList();
    }

    private async Task<string> DumpSystemDatabaseAsync()
    {
        var config = _fixture.GetService<IOptions<OctoSystemConfiguration>>().Value;
        var client = new MongoClient(new MongoUrlBuilder
        {
            Server = MongoServerAddress.Parse(config.DatabaseHost),
            Username = config.AdminUser,
            Password = config.AdminUserPassword,
            AuthenticationSource = config.AuthenticationDatabaseName,
            DatabaseName = config.AuthenticationDatabaseName,
            DirectConnection = config.UseDirectConnection
        }.ToMongoUrl());
        var database = client.GetDatabase(config.SystemDatabaseName);
        var ct = TestContext.Current.CancellationToken;

        var dump = new System.Text.StringBuilder();
        var names = await (await database.ListCollectionNamesAsync(cancellationToken: ct)).ToListAsync(ct);
        foreach (var name in names)
        {
            var documents = await database.GetCollection<BsonDocument>(name)
                .Find(FilterDefinition<BsonDocument>.Empty).ToListAsync(ct);
            foreach (var document in documents)
            {
                dump.AppendLine(document.ToJson());
            }
        }

        return dump.ToString();
    }

    private sealed class MemoryRepository : IXmlRepository
    {
        private readonly List<XElement> _elements = [];

        public IReadOnlyList<XElement> Elements => _elements;

        public IReadOnlyCollection<XElement> GetAllElements()
        {
            return _elements.ToList();
        }

        public void StoreElement(XElement element, string friendlyName)
        {
            _elements.Add(element);
        }
    }
}
