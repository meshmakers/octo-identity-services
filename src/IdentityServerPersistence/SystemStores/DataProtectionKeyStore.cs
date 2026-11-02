using System.Xml.Linq;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores.DataProtection;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NLog;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     ASP.NET Data Protection key-ring repository backed by the CK runtime (MongoDB).
/// </summary>
/// <remarks>
///     The key ring is service-global (shared by all pods, used across all tenants), so it is
///     stored in the SYSTEM tenant database via <see cref="ISystemContext" /> — the per-request
///     tenant resolver cannot be used because Data Protection runs outside any HTTP context.
///     <para>
///     Zero-logout migration: when the store is EMPTY and the legacy file path
///     (<c>Identity:DataProtectionKeysPath</c>) still exists (old chart still mounts the PVC),
///     all key-*.xml files are imported ONCE so existing cookies/sessions keep decrypting.
///     </para>
///     <para>
///     Encryption at rest (AB#5530): the secret part of a key is wrapped with the platform key ring
///     (<see cref="PlatformKeyRingXmlEncryptor" />) when <c>Identity:DataProtection:EncryptExistingKeys</c> is on,
///     or when the store holds no key yet (fresh installation - no pod of an older image can depend on a plain
///     key there). Otherwise new keys are written as plain XML, so pods of the previous image keep reading them
///     during a rolling update. Stored keys are returned as they are; ASP.NET decrypts wrapped ones through the
///     <c>decryptorType</c> attribute. <see cref="CheckAndProtectStoredKeysAsync" /> is the startup step that
///     refuses unreadable keys and rewrites plain / old-key-id keys.
///     </para>
///     <para>
///     <see cref="IXmlRepository" /> is synchronous by contract; the rare calls (key-ring load on
///     first use, key creation/rotation every ~90 days) make sync-over-async acceptable here.
///     </para>
/// </remarks>
public class DataProtectionKeyStore(
    IServiceScopeFactory serviceScopeFactory,
    IOptions<OctoIdentityServicesOptions> identityOptions,
    ISecretAttributeProtector secretProtector) : IXmlRepository
{
    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
    private readonly PlatformKeyRingXmlEncryptor _encryptor = new(secretProtector);
    private readonly PlatformKeyRingXmlDecryptor _decryptor = new(secretProtector);
    private readonly object _seedLock = new();
    private bool _seedAttempted;

    /// <inheritdoc />
    public IReadOnlyCollection<XElement> GetAllElements()
    {
        return GetAllElementsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc />
    public void StoreElement(XElement element, string? friendlyName)
    {
        ArgumentNullException.ThrowIfNull(element);
        var name = string.IsNullOrWhiteSpace(friendlyName)
            ? $"key-{Guid.NewGuid():D}"
            : friendlyName;
        StoreElementAsync(element, name).GetAwaiter().GetResult();
    }

    private async Task<IReadOnlyCollection<XElement>> GetAllElementsAsync()
    {
        using var scope = serviceScopeFactory.CreateScope();
        var systemContext = scope.ServiceProvider.GetRequiredService<ISystemContext>();
        var repository = systemContext.GetSystemTenantRepositoryAsAdmin();

        var keys = await LoadAllKeysAsync(repository);

        // The bootstrap guard mirrors StoreElementAsync. Skipping the seed does NOT set the
        // _seedAttempted latch, so the legacy import still happens on the first load after the
        // system tenant exists.
        if (keys.Count == 0 && await systemContext.IsSystemTenantExistingAsync())
        {
            await TrySeedFromLegacyFilesAsync(repository);
            keys = await LoadAllKeysAsync(repository);
        }

        return keys.Select(k => XElement.Parse(k.XmlData)).ToList();
    }

    private static async Task<List<RtDataProtectionKey>> LoadAllKeysAsync(ITenantRepository repository)
    {
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var result = await repository.GetRtEntitiesByTypeAsync<RtDataProtectionKey>(session,
            RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return result.Items.ToList();
    }

    private async Task StoreElementAsync(XElement element, string friendlyName)
    {
        using var scope = serviceScopeFactory.CreateScope();
        var systemContext = scope.ServiceProvider.GetRequiredService<ISystemContext>();

        // Never persist into a system database the bootstrap has not created yet (AB#4854): the
        // Data Protection key-ring preload runs before the setup initializer, and a key written
        // here (as admin) materializes a collection outside the engine's infrastructure allowlist —
        // the bootstrap then refuses the database and the fresh install wedges. The preload treats
        // a failed persist as best-effort; the key is re-created and persisted on the first real
        // Data Protection use after the bootstrap.
        if (!await systemContext.IsSystemTenantExistingAsync())
        {
            throw new InvalidOperationException(
                $"Data protection key '{friendlyName}' cannot be persisted before the system tenant is bootstrapped.");
        }

        var repository = systemContext.GetSystemTenantRepositoryAsAdmin();

        await StoreElementInternalAsync(repository, element, friendlyName, isNewKey: true);
    }

    private bool EncryptExistingKeys => identityOptions.Value.DataProtection.EncryptExistingKeys;

    private async Task StoreElementInternalAsync(ITenantRepository repository, XElement element,
        string friendlyName, bool isNewKey)
    {
        try
        {
            using var session = await repository.GetSessionAsync();
            session.StartTransaction();

            var existing = await repository.GetRtEntitiesByTypeAsync<RtDataProtectionKey>(session,
                RtEntityQueryOptions.Create()
                    .FieldFilter(nameof(RtDataProtectionKey.FriendlyName), FieldFilterOperator.Equals,
                        friendlyName));
            if (existing.Items.Any())
            {
                // Same key already persisted (concurrent first-boot of multiple pods) — done.
                await session.CommitTransactionAsync();
                return;
            }

            // A new key of a store without any key (fresh installation) is encrypted even with the flag off;
            // legacy file imports follow the flag only (AC: imported keys are encrypted when the flag is on).
            var encrypt = EncryptExistingKeys;
            if (!encrypt && isNewKey)
            {
                var anyKey = await repository.GetRtEntitiesByTypeAsync<RtDataProtectionKey>(session,
                    RtEntityQueryOptions.Create());
                encrypt = !anyKey.Items.Any();
            }

            var rtKey = new RtDataProtectionKey
            {
                RtId = OctoObjectId.GenerateNewId(),
                FriendlyName = friendlyName,
                XmlData = PrepareForStorage(element, friendlyName, encrypt).ToString(SaveOptions.DisableFormatting),
                CreationDateTime = DateTime.UtcNow
            };
            await repository.InsertOneRtEntityAsync(session, rtKey);
            await session.CommitTransactionAsync();
        }
        catch (Exception ex) when (ex is not DataProtectionKeyRingException)
        {
            // Unique index on FriendlyName: a concurrent pod won the race — the key IS persisted,
            // which is all the Data Protection stack needs. Anything else is a real error.
            Logger.Warn("Storing data protection key '{FriendlyName}' hit a conflict ({Message}); verifying",
                friendlyName, ex.Message);

            using var session = await repository.GetSessionAsync();
            session.StartTransaction();
            var verify = await repository.GetRtEntitiesByTypeAsync<RtDataProtectionKey>(session,
                RtEntityQueryOptions.Create()
                    .FieldFilter(nameof(RtDataProtectionKey.FriendlyName), FieldFilterOperator.Equals,
                        friendlyName));
            await session.CommitTransactionAsync();

            if (!verify.Items.Any())
            {
                throw;
            }
        }
    }

    private async Task TrySeedFromLegacyFilesAsync(ITenantRepository repository)
    {
        lock (_seedLock)
        {
            if (_seedAttempted)
            {
                return;
            }
            _seedAttempted = true;
        }

        var legacyPath = identityOptions.Value.DataProtectionKeysPath;
        if (string.IsNullOrWhiteSpace(legacyPath) || !Directory.Exists(legacyPath))
        {
            return;
        }

        var keyFiles = Directory.GetFiles(legacyPath, "key-*.xml");
        if (keyFiles.Length == 0)
        {
            return;
        }

        Logger.Info("Seeding {Count} data protection keys from legacy path '{Path}' into MongoDB",
            keyFiles.Length, legacyPath);

        foreach (var keyFile in keyFiles)
        {
            try
            {
                var element = XElement.Parse(await File.ReadAllTextAsync(keyFile));
                var friendlyName = Path.GetFileNameWithoutExtension(keyFile);
                await StoreElementInternalAsync(repository, element, friendlyName, isNewKey: false);
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to seed data protection key from '{File}': {Message}", keyFile, ex.Message);
            }
        }
    }
    /// <summary>
    ///     Returns the XML to persist: the key with its secret wrapped by the platform key ring when
    ///     <paramref name="encrypt" /> is set, otherwise the key unchanged.
    /// </summary>
    /// <exception cref="DataProtectionKeyRingException">
    ///     <c>EncryptExistingKeys</c> is on and no platform key is configured - never falls back to clear text.
    /// </exception>
    private XElement PrepareForStorage(XElement element, string friendlyName, bool encrypt)
    {
        if (!DataProtectionKeyXml.ContainsUnencryptedSecret(element))
        {
            return element;
        }

        if (!encrypt)
        {
            Logger.Warn(
                "Data protection key '{FriendlyName}' is stored unencrypted: Identity:DataProtection:EncryptExistingKeys " +
                "is false and the key store already holds keys (AB#5530 rollout step 1)", friendlyName);
            return element;
        }

        if (!_encryptor.IsConfigured)
        {
            if (EncryptExistingKeys)
            {
                throw new DataProtectionKeyRingException(
                    $"Data protection key '{friendlyName}' cannot be stored: Identity:DataProtection:EncryptExistingKeys " +
                    "is true but no SecretEncryption key is configured (OCTO_SECRETENCRYPTION__KEYS__<id>, " +
                    "OCTO_SECRETENCRYPTION__ACTIVEKEYID).");
            }

            Logger.Warn(
                "Data protection key '{FriendlyName}' is stored unencrypted: no SecretEncryption key ring is configured " +
                "(OCTO_SECRETENCRYPTION__KEYS__<id>, OCTO_SECRETENCRYPTION__ACTIVEKEYID)", friendlyName);
            return element;
        }

        var encrypted = DataProtectionKeyXml.EncryptSecrets(element, _encryptor);
        Logger.Info("Data protection key '{FriendlyName}' is stored encrypted with platform key id '{KeyId}'",
            friendlyName, _encryptor.ActiveKeyId);
        return encrypted;
    }

    /// <summary>
    ///     Startup step (AB#5530), safe to run on every pod at the same time:
    ///     <list type="number">
    ///         <item>refuses keys that cannot be decrypted with the configured platform key ring (missing key id or no
    ///         key ring at all) with <see cref="DataProtectionKeyRingException" /> - identity must not start then;</item>
    ///         <item>re-wraps keys wrapped with another than the active platform key id (key ring rotation);</item>
    ///         <item>with <paramref name="encryptPlainKeys" />, rewrites every plain key encrypted.</item>
    ///     </list>
    ///     Each key is rewritten in place (same entity, friendly name, key id, dates and key material) in its own
    ///     transaction and only if it is unchanged since it was read, so concurrent pods neither duplicate nor
    ///     clobber keys. Without a system tenant (virgin server) nothing is done.
    /// </summary>
    /// <param name="encryptPlainKeys">Rewrite plain keys encrypted (<c>EncryptExistingKeys</c>)</param>
    /// <returns>What was found and changed</returns>
    /// <exception cref="DataProtectionKeyRingException">A stored key cannot be decrypted with the configured key ring</exception>
    public async Task<DataProtectionKeyMaintenanceResult> CheckAndProtectStoredKeysAsync(bool encryptPlainKeys)
    {
        using var scope = serviceScopeFactory.CreateScope();
        var systemContext = scope.ServiceProvider.GetRequiredService<ISystemContext>();
        if (!await systemContext.IsSystemTenantExistingAsync())
        {
            return DataProtectionKeyMaintenanceResult.SystemTenantMissing;
        }

        var repository = systemContext.GetSystemTenantRepositoryAsAdmin();
        var keys = await LoadAllKeysAsync(repository);

        var unreadable = new List<string>();
        foreach (var key in keys)
        {
            var element = XElement.Parse(key.XmlData);
            var unknown = DataProtectionKeyXml.GetPlatformKeyIds(element, secretProtector)
                .Where(keyId => keyId == DataProtectionKeyXml.InvalidEnvelopeKeyId || !secretProtector.IsKnownKeyId(keyId))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (unknown.Count > 0)
            {
                unreadable.Add($"'{key.FriendlyName}' (platform key id {string.Join(", ", unknown)})");
            }
        }

        if (unreadable.Count > 0)
        {
            throw new DataProtectionKeyRingException(
                "Identity refuses to start: stored Data Protection keys are encrypted with a platform key id that is " +
                "not in the SecretEncryption key ring: " + string.Join("; ", unreadable) + ". Configure the missing " +
                "key (OCTO_SECRETENCRYPTION__KEYS__<id>); never remove a key id before every Data Protection key was " +
                "re-wrapped with the new active key (docs/rollout-identity-dataprotection-encryption.md).");
        }

        // Known key id, wrong key material (every cluster names its key "k1"; a database restored from another
        // environment): ASP.NET ignores such a key and creates a new one, which logs users out but does not stop
        // the service. Reported, never re-wrapped, not fatal.
        var wrongKeyMaterial = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            if (!CanDecryptPlatformSecrets(XElement.Parse(key.XmlData)))
            {
                wrongKeyMaterial.Add(key.FriendlyName);
            }
        }

        if (wrongKeyMaterial.Count > 0)
        {
            Logger.Error(
                "Data protection keys {FriendlyNames} cannot be decrypted with the configured SecretEncryption key " +
                "material (same key id, other key - e.g. a database restored from another environment); they are " +
                "unusable and left unchanged", string.Join(", ", wrongKeyMaterial));
        }

        var encrypted = 0;
        var rewrapped = 0;
        var plainLeft = 0;
        foreach (var key in keys.Where(k => !wrongKeyMaterial.Contains(k.FriendlyName)))
        {
            var original = XElement.Parse(key.XmlData);
            var updated = original;
            var change = DataProtectionKeyChange.None;

            if (_encryptor.IsConfigured && DataProtectionKeyXml.IsPlatformEncrypted(updated))
            {
                updated = DataProtectionKeyXml.RewrapSecrets(updated, _decryptor, _encryptor, secretProtector,
                    out var changed);
                if (changed)
                {
                    change = DataProtectionKeyChange.Rewrapped;
                }
            }

            if (DataProtectionKeyXml.ContainsUnencryptedSecret(updated))
            {
                if (encryptPlainKeys && _encryptor.IsConfigured)
                {
                    updated = DataProtectionKeyXml.EncryptSecrets(updated, _encryptor);
                    change = DataProtectionKeyChange.Encrypted;
                }
                else
                {
                    plainLeft++;
                }
            }

            if (change == DataProtectionKeyChange.None)
            {
                continue;
            }

            if (await TryReplaceXmlAsync(repository, key.FriendlyName, key.XmlData,
                    updated.ToString(SaveOptions.DisableFormatting)))
            {
                if (change == DataProtectionKeyChange.Encrypted)
                {
                    encrypted++;
                }
                else
                {
                    rewrapped++;
                }
            }
        }

        return new DataProtectionKeyMaintenanceResult(true, keys.Count, encrypted, rewrapped, plainLeft);
    }

    private bool CanDecryptPlatformSecrets(XElement key)
    {
        foreach (var secret in key.Descendants(DataProtectionKeyXml.EncryptedSecretElementName))
        {
            var inner = secret.Elements().FirstOrDefault();
            if (inner?.Name != PlatformKeyRingXmlEncryptor.EncryptedElementName)
            {
                continue;
            }

            try
            {
                _decryptor.Decrypt(inner);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return false;
            }
        }

        return true;
    }

    private static async Task<bool> TryReplaceXmlAsync(ITenantRepository repository, string friendlyName,
        string expectedXml, string newXml)
    {
        try
        {
            using var session = await repository.GetSessionAsync();
            session.StartTransaction();
            var current = await repository.GetRtEntitiesByTypeAsync<RtDataProtectionKey>(session,
                RtEntityQueryOptions.Create()
                    .FieldFilter(nameof(RtDataProtectionKey.FriendlyName), FieldFilterOperator.Equals, friendlyName));
            var entity = current.Items.SingleOrDefault();
            if (entity == null || !string.Equals(entity.XmlData, expectedXml, StringComparison.Ordinal))
            {
                // Another pod rewrote (or removed) the key since we read it - its result is as good as ours.
                await session.CommitTransactionAsync();
                return false;
            }

            entity.XmlData = newXml;
            await repository.ReplaceOneRtEntityByIdAsync(session, entity.RtId, entity);
            await session.CommitTransactionAsync();
            return true;
        }
        catch (Exception ex) when (ex is not DataProtectionKeyRingException)
        {
            // Write conflict with a concurrent pod: the next start retries; the key stays readable either way.
            Logger.Warn("Rewriting data protection key '{FriendlyName}' failed ({Message}); retried on the next start",
                friendlyName, ex.Message);
            return false;
        }
    }

    private enum DataProtectionKeyChange
    {
        None,
        Encrypted,
        Rewrapped
    }
}
