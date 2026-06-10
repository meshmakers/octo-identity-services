using System.Xml.Linq;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NLog;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

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
///     <see cref="IXmlRepository" /> is synchronous by contract; the rare calls (key-ring load on
///     first use, key creation/rotation every ~90 days) make sync-over-async acceptable here.
///     </para>
/// </remarks>
public class DataProtectionKeyStore(
    IServiceScopeFactory serviceScopeFactory,
    IOptions<OctoIdentityServicesOptions> identityOptions) : IXmlRepository
{
    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
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

        if (keys.Count == 0)
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
        var repository = systemContext.GetSystemTenantRepositoryAsAdmin();

        await StoreElementInternalAsync(repository, element, friendlyName);
    }

    private static async Task StoreElementInternalAsync(ITenantRepository repository, XElement element,
        string friendlyName)
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

            var rtKey = new RtDataProtectionKey
            {
                RtId = OctoObjectId.GenerateNewId(),
                FriendlyName = friendlyName,
                XmlData = element.ToString(SaveOptions.DisableFormatting),
                CreationDateTime = DateTime.UtcNow
            };
            await repository.InsertOneRtEntityAsync(session, rtKey);
            await session.CommitTransactionAsync();
        }
        catch (Exception ex)
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
                await StoreElementInternalAsync(repository, element, friendlyName);
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to seed data protection key from '{File}': {Message}", keyFile, ex.Message);
            }
        }
    }
}
