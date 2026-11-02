namespace IdentityServerPersistence.SystemStores.DataProtection;

/// <summary>
///     Result of <see cref="DataProtectionKeyStore.CheckAndProtectStoredKeysAsync" /> (AB#5530).
/// </summary>
/// <param name="SystemTenantExists">False on a virgin server: nothing was checked</param>
/// <param name="TotalKeys">Stored keys</param>
/// <param name="EncryptedKeys">Plain keys rewritten encrypted by this run</param>
/// <param name="RewrappedKeys">Keys re-wrapped with the active platform key id by this run</param>
/// <param name="PlainKeys">Keys still stored with a clear-text secret after this run</param>
public sealed record DataProtectionKeyMaintenanceResult(
    bool SystemTenantExists,
    int TotalKeys,
    int EncryptedKeys,
    int RewrappedKeys,
    int PlainKeys)
{
    /// <summary>Result for a server without a system tenant.</summary>
    public static DataProtectionKeyMaintenanceResult SystemTenantMissing { get; } = new(false, 0, 0, 0, 0);
}
