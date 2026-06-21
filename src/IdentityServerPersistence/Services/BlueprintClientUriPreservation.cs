using IdentityServerPersistence;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Step-2 (AB#4209) source-aware preservation logic for the three URI list attributes on
///     blueprint-managed <see cref="RtClient"/> entities — <see cref="RtClient.RedirectUris"/>,
///     <see cref="RtClient.PostLogoutRedirectUris"/>, <see cref="RtClient.AllowedCorsOrigins"/>.
/// </summary>
/// <remarks>
///     <para>
///         The Identity service-managed <c>System.Identity.Bootstrap</c> blueprint re-applies on
///         every restart and overwrites the URI lists on the 5 stable-rtId clients
///         (660…30..34) with the seed values. Before AB#4209 the URI lists were
///         <see cref="string"/> arrays; operator-added URIs (Studio Client-UI / future overlay
///         cmdlet) had no provenance marker and were destroyed silently on every re-apply.
///     </para>
///     <para>
///         AB#4209 Step 1 added the <c>ClientUriEntry.Source</c> marker — <c>"base"</c> for seed
///         entries, <c>"api"</c> for REST-API-added entries, <c>"overlay:&lt;name&gt;"</c> for
///         future overlay-cmdlet entries. Step 2 (this helper) closes the loop: capture every
///         <c>Source != "base"</c> entry BEFORE the apply, let the apply rewrite the lists with the
///         seed values, then merge the captured entries back in. Step-3+4 overlay URIs that ship
///         later get this preservation for free.
///     </para>
///     <para>
///         The capture is intentionally restricted to blueprint-stable rtIds (660…00..660…FF).
///         Operator-created clients (random rtId outside the range) are outside the blueprint's
///         re-apply path anyway — their state is owned by the operator, not the service, and the
///         apply leaves them alone.
///     </para>
///     <para>
///         Both operations are pure functions over already-loaded entities so the orchestration
///         layer in <see cref="DefaultConfigurationCreatorService.SetupTenantAsync"/> can wire
///         them around the apply call with a single repository round-trip each side.
///     </para>
/// </remarks>
internal static class BlueprintClientUriPreservation
{
    /// <summary>
    ///     Inclusive lower bound of the blueprint's stable rtId range. The first byte of every
    ///     <c>System.Identity.Bootstrap</c> seed-data rtId is <c>0x66</c>; everything outside this
    ///     range is operator-created and not in scope for preservation.
    /// </summary>
    internal static readonly OctoObjectId StableRtIdRangeStart =
        new("660000000000000000000000");

    /// <summary>
    ///     Exclusive upper bound. ObjectId comparison is byte-by-byte. Used both by
    ///     <see cref="IsBlueprintStableRtId"/> (in-memory defense-in-depth) and by the query-level
    ///     <c>FieldLessThan</c> filter in
    ///     <see cref="DefaultConfigurationCreatorService.CaptureBlueprintClientNonBaseUrisAsync"/>.
    /// </summary>
    internal static readonly OctoObjectId StableRtIdRangeEndExclusive =
        new("670000000000000000000000");

    /// <summary>
    ///     Walks the given client set, picks blueprint-stable-rtId clients that carry at least one
    ///     URI entry with <c>Source != "base"</c>, and returns a per-client capture of just those
    ///     non-base entries. Clients whose URI lists are entirely <c>"base"</c>-sourced (or empty)
    ///     are absent from the result — the post-apply restore is a fast read-and-skip for them.
    /// </summary>
    /// <param name="clients">
    ///     The pre-apply RtClient set, typically the result of querying every Identity client in
    ///     the tenant repository. The capture preserves the entries by reference, so the caller is
    ///     responsible for not mutating them between capture and restore.
    /// </param>
    /// <returns>
    ///     A dictionary keyed by client rtId. Empty when there is nothing to preserve.
    /// </returns>
    public static IReadOnlyDictionary<OctoObjectId, NonBaseUriCapture> Capture(
        IEnumerable<RtClient> clients)
    {
        ArgumentNullException.ThrowIfNull(clients);

        var captures = new Dictionary<OctoObjectId, NonBaseUriCapture>();

        foreach (var client in clients)
        {
            if (!IsBlueprintStableRtId(client.RtId))
            {
                continue;
            }

            var redirect = CollectNonBaseEntries(client.RedirectUris);
            var postLogout = CollectNonBaseEntries(client.PostLogoutRedirectUris);
            var cors = CollectNonBaseEntries(client.AllowedCorsOrigins);

            if (redirect.Count == 0 && postLogout.Count == 0 && cors.Count == 0)
            {
                continue;
            }

            captures[client.RtId] = new NonBaseUriCapture(
                client.RtId, client.ClientId, redirect, postLogout, cors);
        }

        return captures;
    }

    /// <summary>
    ///     Re-applies a captured non-base entry set onto a post-apply client by appending the
    ///     entries that aren't already present (matched by URI string). Returns <c>true</c> when at
    ///     least one entry was appended on at least one of the three URI lists — the caller uses
    ///     that signal to decide whether the entity needs to be written back to MongoDB.
    /// </summary>
    /// <remarks>
    ///     Dedup by URI string is the right contract: if the seed re-asserts a URI that previously
    ///     had a non-base source, the seed value wins (carries <c>"base"</c>) and the captured
    ///     non-base copy is dropped. That matches the source-precedence rule in the concept doc:
    ///     <c>"base"</c> is the configuration source of truth, <c>"api"</c> / <c>"overlay:*"</c>
    ///     are additive on top.
    /// </remarks>
    public static bool Merge(RtClient postApplyClient, NonBaseUriCapture capture)
    {
        ArgumentNullException.ThrowIfNull(postApplyClient);
        ArgumentNullException.ThrowIfNull(capture);

        var mutated = false;
        mutated |= MergeIntoList(postApplyClient.RedirectUris, capture.RedirectUris);
        mutated |= MergeIntoList(postApplyClient.PostLogoutRedirectUris, capture.PostLogoutRedirectUris);
        mutated |= MergeIntoList(postApplyClient.AllowedCorsOrigins, capture.AllowedCorsOrigins);
        return mutated;
    }

    internal static bool IsBlueprintStableRtId(OctoObjectId rtId)
    {
        return rtId.CompareTo(StableRtIdRangeStart) >= 0
               && rtId.CompareTo(StableRtIdRangeEndExclusive) < 0;
    }

    private static List<RtClientUriEntryRecord> CollectNonBaseEntries(
        IEnumerable<RtClientUriEntryRecord> entries)
    {
        var result = new List<RtClientUriEntryRecord>();
        foreach (var entry in entries)
        {
            if (!string.Equals(entry.Source, ClientUriSources.Base, StringComparison.Ordinal))
            {
                result.Add(entry);
            }
        }
        return result;
    }

    private static bool MergeIntoList(
        IAttributeValueList<RtClientUriEntryRecord> postApplyList,
        IReadOnlyList<RtClientUriEntryRecord> capturedNonBase)
    {
        if (capturedNonBase.Count == 0)
        {
            return false;
        }

        // Build a set of currently-present URI values so the merge stays O(N+M) instead of O(N*M).
        var presentUris = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in postApplyList)
        {
            presentUris.Add(entry.Uri);
        }

        var mutated = false;
        foreach (var captured in capturedNonBase)
        {
            if (presentUris.Add(captured.Uri))
            {
                postApplyList.Add(new RtClientUriEntryRecord
                {
                    Uri = captured.Uri,
                    Source = captured.Source
                });
                mutated = true;
            }
        }
        return mutated;
    }
}

/// <summary>
///     Snapshot of non-base URI entries captured off a single blueprint-managed RtClient before a
///     blueprint re-apply. The three lists hold references to the captured
///     <see cref="RtClientUriEntryRecord"/> instances (not clones) — safe because the apply re-loads
///     the entities from MongoDB and <see cref="BlueprintClientUriPreservation.Merge"/> constructs
///     new <see cref="RtClientUriEntryRecord"/> instances from the captured Uri / Source values on
///     write-back, so nothing on the post-apply path ever mutates the captured records.
/// </summary>
internal sealed record NonBaseUriCapture(
    OctoObjectId ClientRtId,
    string ClientId,
    IReadOnlyList<RtClientUriEntryRecord> RedirectUris,
    IReadOnlyList<RtClientUriEntryRecord> PostLogoutRedirectUris,
    IReadOnlyList<RtClientUriEntryRecord> AllowedCorsOrigins);
