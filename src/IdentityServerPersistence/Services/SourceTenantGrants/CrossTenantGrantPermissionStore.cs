using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Models.System.Generated.System.v2;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
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

    /// <summary>
    ///     Replaces the allow-list stored in <paramref name="repository" /> with <paramref name="targetTenantIds" />
    ///     (already normalized) as one compare-and-set (AB#8432): the stored list is read, compared against
    ///     <paramref name="ifMatch" /> and written in one transaction, so a concurrent change can never be overwritten
    ///     unnoticed.
    /// </summary>
    /// <param name="repository">Repository of the source tenant.</param>
    /// <param name="targetTenantIds">The new list, normalized (<see cref="CrossTenantGrantPermissionList.Normalize" />).</param>
    /// <param name="ifMatch">
    ///     <c>null</c>: no precondition (last writer wins). Otherwise a predicate over the current entity tag
    ///     (<see cref="CrossTenantGrantPermissionList.ETagOf" />); <c>false</c> refuses the change with
    ///     <see cref="CrossTenantGrantPermissionsReplaceOutcome.PreconditionFailed" /> and writes nothing.
    /// </param>
    /// <param name="changedBy">User name or client id of the caller; written only when the list changes.</param>
    /// <param name="changedAtUtc">Time of the change; written only when the list changes.</param>
    Task<CrossTenantGrantPermissionsReplaceResult> ReplaceAsync(ITenantRepository repository,
        IReadOnlyList<string> targetTenantIds, Func<string, bool>? ifMatch, string changedBy, DateTime changedAtUtc);
}

/// <summary>Outcome of <see cref="ICrossTenantGrantPermissionStore.ReplaceAsync" /> (AB#8432).</summary>
public enum CrossTenantGrantPermissionsReplaceOutcome
{
    /// <summary>The list was written.</summary>
    Replaced,

    /// <summary>The new list equals the stored one; nothing was written, not even <c>ChangedBy</c>/<c>ChangedAtUtc</c>.</summary>
    Unchanged,

    /// <summary>The precondition did not match the current list; nothing was written.</summary>
    PreconditionFailed
}

/// <summary>Result of <see cref="ICrossTenantGrantPermissionStore.ReplaceAsync" /> (AB#8432).</summary>
/// <param name="Outcome">What happened.</param>
/// <param name="Before">The effective list before the call (empty for a missing or unreadable row).</param>
/// <param name="Current">The effective list after the call (the stored one when nothing was written).</param>
public sealed record CrossTenantGrantPermissionsReplaceResult(
    CrossTenantGrantPermissionsReplaceOutcome Outcome,
    IReadOnlyList<string> Before,
    IReadOnlyList<string> Current)
{
    /// <summary>Entity tag of <see cref="Current" />.</summary>
    public string ETag => CrossTenantGrantPermissionList.ETagOf(Current);
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

    /// <summary>Attempts of one replace when the transaction collides with a concurrent one.</summary>
    private const int MaxAttempts = 5;

    /// <summary>
    ///     Runtime id of a row this store inserts (AB#8432): the same in every tenant database, so two first writes of a
    ///     tenant collide on the unique <c>_id</c> instead of creating two rows. Timestamp part zero, so it also sorts
    ///     first (<see cref="FindRowAsync" /> reads the oldest row).
    /// </summary>
    internal static readonly OctoObjectId RowRtId = new("00000000" + Convert.ToHexString(
        System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(ConfigurationKey)), 0, 8)
        .ToLowerInvariant());

    /// <inheritdoc />
    /// <remarks>
    ///     Concurrency (AB#8432): the read, the precondition and the write run in one MongoDB transaction. A concurrent
    ///     transaction that changed the row after our snapshot makes MongoDB refuse our write (write conflict); two first
    ///     inserts collide on <see cref="RowRtId" /> (write conflict or duplicate key). The whole transaction then runs
    ///     again on the new state, so the precondition is evaluated against what is really stored and a stale entity tag
    ///     ends in <see cref="CrossTenantGrantPermissionsReplaceOutcome.PreconditionFailed" />.
    /// </remarks>
    public async Task<CrossTenantGrantPermissionsReplaceResult> ReplaceAsync(ITenantRepository repository,
        IReadOnlyList<string> targetTenantIds, Func<string, bool>? ifMatch, string changedBy, DateTime changedAtUtc)
    {
        for (var attempt = 1;; attempt++)
        {
            try
            {
                return await ReplaceOnceAsync(repository, targetTenantIds, ifMatch, changedBy, changedAtUtc);
            }
            catch (Exception ex) when (attempt < MaxAttempts && IsCollision(ex))
            {
                await Task.Delay(Random.Shared.Next(5, 10 + 15 * attempt));
            }
        }
    }

    private static bool IsCollision(Exception exception)
    {
        if (MongoWriteRetry.IsWriteConflict(exception))
        {
            return true;
        }

        for (var ex = exception; ex != null; ex = ex.InnerException)
        {
            switch (ex)
            {
                case DuplicateKeyException:
                case MongoDB.Driver.MongoWriteException { WriteError.Category: MongoDB.Driver.ServerErrorCategory.DuplicateKey }:
                case MongoDB.Driver.MongoCommandException { Code: 11000 }:
                    return true;
            }
        }

        return false;
    }

    private static async Task<CrossTenantGrantPermissionsReplaceResult> ReplaceOnceAsync(ITenantRepository repository, IReadOnlyList<string> targetTenantIds,
            Func<string, bool>? ifMatch, string changedBy, DateTime changedAtUtc)
    {
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var row = await FindRowAsync(repository, session);
        var (before, readable) = Parse(row);

        if (ifMatch != null && !ifMatch(CrossTenantGrantPermissionList.ETagOf(before)))
        {
            await session.AbortTransactionAsync();
            return new CrossTenantGrantPermissionsReplaceResult(
                CrossTenantGrantPermissionsReplaceOutcome.PreconditionFailed, before, before);
        }

        // An unreadable row reads as empty but is always rewritten, so a PUT repairs it.
        if (readable && before.SequenceEqual(targetTenantIds, StringComparer.Ordinal))
        {
            await session.AbortTransactionAsync();
            return new CrossTenantGrantPermissionsReplaceResult(
                CrossTenantGrantPermissionsReplaceOutcome.Unchanged, before, before);
        }

        var value = new CrossTenantGrantPermissions
        {
            TargetTenantIds = targetTenantIds.ToList(), ChangedAtUtc = changedAtUtc, ChangedBy = changedBy
        }.Serialize();
        if (row == null)
        {
            await repository.InsertOneRtEntityAsync(session,
                new RtTenantConfiguration
                {
                    RtId = RowRtId, RtWellKnownName = ConfigurationKey, ConfigurationValue = value
                });
        }
        else
        {
            row.ConfigurationValue = value;
            await repository.ReplaceOneRtEntityByIdAsync(session, row.RtId, row);
        }

        await session.CommitTransactionAsync();
        return new CrossTenantGrantPermissionsReplaceResult(
            CrossTenantGrantPermissionsReplaceOutcome.Replaced, before, targetTenantIds.ToList());
    }

    private static (List<string> List, bool Readable) Parse(RtTenantConfiguration? row)
    {
        if (string.IsNullOrEmpty(row?.ConfigurationValue))
        {
            return ([], true);
        }

        try
        {
            var stored = row.ConfigurationValue.Deserialize<CrossTenantGrantPermissions?>();
            return (CrossTenantGrantPermissionList.Normalize(stored?.TargetTenantIds ?? []), stored != null);
        }
        catch (System.Text.Json.JsonException)
        {
            return ([], false);
        }
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

    /// <summary>
    ///     Strong entity tag of an allow-list (AB#8432), quoted as HTTP sends it, e.g. <c>"q3b0…"</c>: derived from
    ///     the normalized list only, so the same list always has the same tag (also a tenant that never set it and one
    ///     that set <c>[]</c>), and a PUT that changes nothing keeps it. <c>ChangedBy</c>/<c>ChangedAtUtc</c> are not
    ///     part of it.
    /// </summary>
    public static string ETagOf(IReadOnlyList<string> normalizedTargetTenantIds)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(string.Join("\n", normalizedTargetTenantIds)));
        return $"\"{Convert.ToBase64String(hash, 0, 16).TrimEnd('=').Replace('+', '-').Replace('/', '_')}\"";
    }

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
