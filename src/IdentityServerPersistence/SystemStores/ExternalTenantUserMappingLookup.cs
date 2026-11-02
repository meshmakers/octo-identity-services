using System.Collections.Concurrent;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
/// The one lookup of an <see cref="RtExternalTenantUserMapping"/> by (source tenant, source user).
/// A mapping is meant to be unique per pair, but nothing in the database enforces it (no unique index on
/// runtime entities), so legacy data and races can hold several. The lookup therefore never throws on
/// duplicates: the oldest mapping (smallest RtId, an ObjectId that starts with its creation time) wins,
/// deterministically, and a WARN names all ids (AB#6975).
/// </summary>
public static class ExternalTenantUserMappingLookup
{
    /// <summary>
    /// Remembers which duplicate sets were already reported, so that the several lookups of one request (a login or a
    /// token exchange looks the mapping up in more than one place) log the WARN once. Keep one instance per
    /// request scope; a later lookup of the same set logs at Debug level only.
    /// </summary>
    public sealed class DuplicateWarningGate
    {
        private readonly ConcurrentDictionary<string, byte> _reported = new(StringComparer.Ordinal);

        /// <summary>True the first time <paramref name="key"/> is seen.</summary>
        public bool ShouldWarn(string key) => _reported.TryAdd(key, 0);
    }

    /// <summary>
    /// Picks the oldest mapping of <paramref name="candidates"/> (smallest RtId); null for an empty list.
    /// Logs a WARN naming every id when there is more than one.
    /// </summary>
    public static RtExternalTenantUserMapping? PickOldest(
        IReadOnlyCollection<RtExternalTenantUserMapping> candidates,
        string sourceTenantId,
        string sourceUserId,
        ILogger? logger = null,
        DuplicateWarningGate? warningGate = null)
    {
        if (candidates.Count == 0)
        {
            return null;
        }

        // ObjectId strings are fixed-length lower-case hex, so the ordinal order is the creation order.
        var ordered = candidates
            .OrderBy(m => m.RtId.ToString(), StringComparer.Ordinal)
            .ToList();

        if (ordered.Count > 1 && logger != null)
        {
            var ids = string.Join(", ", ordered.Select(m => m.RtId.ToString()));
            var level = warningGate == null || warningGate.ShouldWarn($"{sourceTenantId}\u001f{sourceUserId}\u001f{ids}")
                ? LogLevel.Warning
                : LogLevel.Debug;
            logger.Log(level,
                "Found {Count} cross-tenant user mappings for source user '{SourceUserId}' of tenant '{SourceTenantId}' ({MappingIds}); using the oldest '{ChosenId}'. Delete the duplicates.",
                ordered.Count, sourceUserId, sourceTenantId, ids, ordered[0].RtId.ToString());
        }

        return ordered[0];
    }

    /// <summary>
    /// Reads the mappings of (<paramref name="sourceTenantId"/>, <paramref name="sourceUserId"/>) from the
    /// tenant of <paramref name="repository"/> and returns the oldest one, or null.
    /// </summary>
    public static async Task<RtExternalTenantUserMapping?> FindOldestAsync(
        ITenantRepository repository,
        string sourceTenantId,
        string sourceUserId,
        ILogger? logger = null,
        DuplicateWarningGate? warningGate = null)
    {
        var session = await repository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceTenantId), sourceTenantId)
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceUserId), sourceUserId);

        var result = await repository
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, queryOptions);
        await session.CommitTransactionAsync();

        return PickOldest(result.Items.ToList(), sourceTenantId, sourceUserId, logger, warningGate);
    }
}
