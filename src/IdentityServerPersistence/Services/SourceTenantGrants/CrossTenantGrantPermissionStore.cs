using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Models.System.Generated.System.v2;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;

namespace IdentityServerPersistence.Services.SourceTenantGrants;

/// <summary>
///     The allow-list of a source tenant S (AB#8345, <c>docs/CONCEPT-SIBLING-TENANT-GRANTS.md</c> §6): the target tenants
///     whose administrators may look up S's users by exact user name or e-mail and grant them access. Stored as the
///     tenant configuration row <see cref="CrossTenantGrantPermissionStore.ConfigurationKey" /> in S's own database.
/// </summary>
public sealed class CrossTenantGrantPermissions
{
    /// <summary>Normalized (trimmed, lower-case), distinct, sorted target tenant ids. Empty = nobody.</summary>
    public List<string> TargetTenantIds { get; set; } = [];

    /// <summary>When the list was last replaced (UTC); <c>null</c> for a tenant that never set it.</summary>
    public DateTime? ChangedAtUtc { get; set; }

    /// <summary>User name or client id of the administrator who last replaced the list.</summary>
    public string? ChangedBy { get; set; }
}

/// <summary>Reads and replaces the allow-list of a tenant (AB#8345).</summary>
public interface ICrossTenantGrantPermissionStore
{
    /// <summary>
    ///     The allow-list stored in <paramref name="repository" />. A tenant without the row (every tenant before
    ///     AB#8345) has an empty list. A row that cannot be read throws; the policy treats that as "not permitted".
    /// </summary>
    Task<CrossTenantGrantPermissions> GetAsync(ITenantRepository repository);

    /// <summary>Replaces the allow-list stored in <paramref name="repository" />.</summary>
    Task SetAsync(ITenantRepository repository, CrossTenantGrantPermissions permissions);
}

/// <inheritdoc />
/// <remarks>
///     Configuration storage instead of a CK model change (story AB#8345: preferred when equally auditable): the row is a
///     <c>System/TenantConfiguration</c> entity, the same storage <c>ITenantContext.GetConfigurationAsync</c> /
///     <c>SetConfigurationAsync</c> use (identical JSON serialization), but read through the lightweight tenant
///     repository so the lookup and exchange hot paths do not resolve a full tenant context. Changes are audited in
///     S's event log by the controller.
/// </remarks>
public sealed class CrossTenantGrantPermissionStore : ICrossTenantGrantPermissionStore
{
    /// <summary>Well-known name of the tenant configuration row that holds the allow-list.</summary>
    public const string ConfigurationKey = "CrossTenantGrantPermissions";

    /// <inheritdoc />
    public async Task<CrossTenantGrantPermissions> GetAsync(ITenantRepository repository)
    {
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var row = await FindRowAsync(repository, session);
        await session.CommitTransactionAsync();

        if (string.IsNullOrEmpty(row?.ConfigurationValue))
        {
            return new CrossTenantGrantPermissions();
        }

        var stored = row.ConfigurationValue.Deserialize<CrossTenantGrantPermissions?>()
                     ?? new CrossTenantGrantPermissions();
        // Defensive: whatever was written by hand is read in normalized form.
        stored.TargetTenantIds = CrossTenantGrantPermissionList.Normalize(stored.TargetTenantIds ?? []);
        return stored;
    }

    /// <inheritdoc />
    public async Task SetAsync(ITenantRepository repository, CrossTenantGrantPermissions permissions)
    {
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var row = await FindRowAsync(repository, session);
        var value = permissions.Serialize();
        if (row == null)
        {
            await repository.InsertOneRtEntityAsync(session,
                new RtTenantConfiguration
                {
                    RtId = OctoObjectId.GenerateNewId(), RtWellKnownName = ConfigurationKey, ConfigurationValue = value
                });
        }
        else
        {
            row.ConfigurationValue = value;
            await repository.ReplaceOneRtEntityByIdAsync(session, row.RtId, row);
        }

        await session.CommitTransactionAsync();
    }

    private static async Task<RtTenantConfiguration?> FindRowAsync(ITenantRepository repository,
        Meshmakers.Octo.Runtime.Contracts.IOctoSession session)
    {
        var result = await repository.GetRtEntitiesByTypeAsync<RtTenantConfiguration>(session,
            RtEntityQueryOptions.Create().FieldEquals(nameof(RtTenantConfiguration.RtWellKnownName), ConfigurationKey));
        // Oldest row wins if a race ever wrote two (the engine's configuration API reads the first one, too).
        return result.Items.OrderBy(r => r.RtId).FirstOrDefault();
    }
}

/// <summary>Normalization and validation of an allow-list as an administrator submits it (AB#8345).</summary>
public static class CrossTenantGrantPermissionList
{
    /// <summary>At most this many target tenants per source tenant.</summary>
    public const int MaxEntries = 200;

    /// <summary>Longest tenant id the engine accepts (<c>TenantContext.ValidateTenantIdFormat</c>).</summary>
    public const int MaxTenantIdLength = 64;

    /// <summary>Trimmed, lower-case, distinct, ordinal-sorted; empty entries dropped.</summary>
    public static List<string> Normalize(IEnumerable<string?> tenantIds)
        => tenantIds
            .Select(t => t?.Trim().ToLowerInvariant() ?? string.Empty)
            .Where(t => t.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

    /// <summary>
    ///     The validation errors of a submitted list for source tenant <paramref name="sourceTenantId" />; empty when
    ///     valid. No entry is checked for existence: the list may name a tenant that does not exist (yet), so the API is
    ///     no way to find out which tenants exist.
    /// </summary>
    public static IReadOnlyList<string> Validate(string sourceTenantId, IReadOnlyList<string?>? submitted)
    {
        if (submitted == null)
        {
            return ["targetTenantIds is required; send [] to permit no tenant."];
        }

        var errors = new List<string>();
        if (submitted.Any(t => string.IsNullOrWhiteSpace(t)))
        {
            errors.Add("targetTenantIds must not contain empty entries.");
        }

        var normalized = Normalize(submitted);
        if (normalized.Count > MaxEntries)
        {
            errors.Add($"targetTenantIds may name at most {MaxEntries} tenants.");
        }

        var invalid = normalized.Where(t => t.Length > MaxTenantIdLength ||
                                            t.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_'))
            .ToList();
        if (invalid.Count > 0)
        {
            errors.Add(
                $"Invalid tenant ids (at most {MaxTenantIdLength} ASCII letters, digits, '-' or '_'): {string.Join(", ", invalid)}.");
        }

        if (normalized.Contains(sourceTenantId.Trim().ToLowerInvariant(), StringComparer.Ordinal))
        {
            errors.Add("A tenant cannot permit itself.");
        }

        return errors;
    }
}
