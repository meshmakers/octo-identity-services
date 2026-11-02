using System.Text.RegularExpressions;
using IdentityServerPersistence;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Step-2b (AB#4209) late-binding URI-family reconciler for blueprint-managed
///     <see cref="RtClient"/> entities. Walks the three URI list attributes —
///     <see cref="RtClient.RedirectUris"/>, <see cref="RtClient.PostLogoutRedirectUris"/>,
///     <see cref="RtClient.AllowedCorsOrigins"/> — and reconciles their <c>family:*</c>
///     entries against the current <c>OctoIdentityServicesOptions.UriFamilies</c>
///     configuration.
/// </summary>
/// <remarks>
///     <para>
///         The engine's <c>${octo.*}</c> apply-time variable substitution is 1:1 (one
///         placeholder → one string) and runs inside the blueprint apply transaction.
///         Families need 1:N (one placeholder → 0..N entries) and a per-Identity-instance
///         configuration source. They therefore run AFTER the engine apply, in a separate
///         pass orchestrated by
///         <see cref="DefaultConfigurationCreatorService.ExpandBlueprintClientUriFamiliesAsync"/>.
///     </para>
///     <para>
///         Reconciliation contract — a family is associated with a (client, list) pair when EITHER
///         of these signals is present:
///         <list type="bullet">
///             <item>
///                 A <c>{{family.NAME}}</c> placeholder is present in that list (fresh seed
///                 apply, first activation of the family on that list).
///             </item>
///             <item>
///                 At least one <c>Source = "family:NAME"</c> entry already exists in that
///                 list (carried over from a previous expansion that this run is now reconciling).
///             </item>
///         </list>
///         For every such (client, list, familyName) tuple the reconciler:
///         <list type="number">
///             <item>Drops the placeholder (if any) from the list contents.</item>
///             <item>Drops every existing <c>family:NAME</c> entry from the list contents.</item>
///             <item>
///                 Re-adds one entry per current configured family member with
///                 <c>Source = "family:NAME"</c>, normalising the URI value per
///                 <see cref="NormaliseForList"/> (CORS origins get trailing slashes stripped
///                 to satisfy IdentityServer's <c>ValidatingClientStore</c> origin contract).
///             </item>
///         </list>
///         Non-family, non-placeholder entries (<c>base</c>, <c>api</c>, <c>overlay:*</c>) are
///         preserved verbatim and kept in their original list position.
///     </para>
///     <para>
///         Scope: same blueprint-stable rtId range as the Step 2a preservation pass
///         (660…00..660…FF). Operator-created clients are out of scope — they have no
///         seed-managed URI lists that a family signal could land in.
///     </para>
///     <para>
///         A family that was never seeded AND has no existing entries on a given list will
///         not be added there. Without a signal the reconciler doesn't know which list wants
///         which family — it stays inert rather than guessing. Operators who want to introduce
///         a family on a new list edit the seed YAML and bump the blueprint version.
///     </para>
/// </remarks>
internal static class BlueprintClientUriFamilyResolver
{
    // Family-source values land in the DB as "family:NAME" — same prefix the Step 2a Capture
    // filter skips, see ClientUriSources.FamilyPrefix.
    private static readonly string SourcePrefix = ClientUriSources.FamilyPrefix;

    /// <summary>
    ///     Matches the <c>{{family.NAME}}</c> placeholder in a <see cref="RtClientUriEntryRecord.Uri"/>
    ///     value. <c>NAME</c> captures alphanumeric plus dash / dot / underscore — the same
    ///     character class the Identity options binder allows for env-var dict keys (e.g.
    ///     <c>OCTO_IDENTITY__URIFAMILIES__LOCAL-DEV__0</c>).
    /// </summary>
    /// <remarks>
    ///     The match must be the entire value: a placeholder mixed with literal characters
    ///     (e.g. <c>https://prefix/{{family.x}}/suffix</c>) is intentionally NOT supported.
    ///     Families expand to whole URIs, not URI fragments.
    /// </remarks>
    private static readonly Regex PlaceholderRegex = new(
        @"^\s*\{\{\s*family\.(?<name>[A-Za-z0-9._-]+)\s*\}\}\s*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    ///     Inclusive lower bound of the blueprint's stable rtId range. Mirrors
    ///     <see cref="BlueprintClientUriPreservation.StableRtIdRangeStart"/> so the two
    ///     passes share an identical client scope.
    /// </summary>
    internal static readonly OctoObjectId StableRtIdRangeStart =
        BlueprintClientUriPreservation.StableRtIdRangeStart;

    /// <summary>
    ///     Exclusive upper bound. Mirrors
    ///     <see cref="BlueprintClientUriPreservation.StableRtIdRangeEndExclusive"/>.
    /// </summary>
    internal static readonly OctoObjectId StableRtIdRangeEndExclusive =
        BlueprintClientUriPreservation.StableRtIdRangeEndExclusive;

    /// <summary>
    ///     Computes the reconciled URI list contents for every blueprint-stable client and
    ///     returns a per-client summary for those whose contents actually change. Clients with
    ///     no family signal in any of the three lists (no placeholder AND no existing
    ///     <c>family:*</c> entry) are absent from the result — the orchestrator skips them
    ///     with no DB write.
    /// </summary>
    public static IReadOnlyDictionary<OctoObjectId, FamilyExpansion> Reconcile(
        IEnumerable<RtClient> clients,
        IReadOnlyDictionary<string, IReadOnlyList<string>> families)
    {
        ArgumentNullException.ThrowIfNull(clients);
        ArgumentNullException.ThrowIfNull(families);

        var familyLookup = new Dictionary<string, IReadOnlyList<string>>(
            families, StringComparer.OrdinalIgnoreCase);

        var results = new Dictionary<OctoObjectId, FamilyExpansion>();

        foreach (var client in clients)
        {
            if (!BlueprintClientUriPreservation.IsBlueprintStableRtId(client.RtId))
            {
                continue;
            }

            var redirect = ReconcileList(client.RedirectUris, familyLookup, UriListKind.RedirectUri);
            var postLogout = ReconcileList(client.PostLogoutRedirectUris, familyLookup, UriListKind.PostLogoutRedirectUri);
            var cors = ReconcileList(client.AllowedCorsOrigins, familyLookup, UriListKind.CorsOrigin);

            if (!redirect.Changed && !postLogout.Changed && !cors.Changed)
            {
                continue;
            }

            results[client.RtId] = new FamilyExpansion(
                client.RtId,
                client.ClientId,
                redirect.Result,
                postLogout.Result,
                cors.Result);
        }

        return results;
    }

    /// <summary>
    ///     Applies a pre-computed <see cref="FamilyExpansion"/> to a freshly re-loaded
    ///     <see cref="RtClient"/> by replacing each of the three URI lists' contents with
    ///     the reconciled entries. The orchestration layer calls this immediately before the
    ///     write-back to MongoDB.
    /// </summary>
    public static void ApplyToClient(RtClient postApplyClient, FamilyExpansion expansion)
    {
        ArgumentNullException.ThrowIfNull(postApplyClient);
        ArgumentNullException.ThrowIfNull(expansion);

        ReplaceListContents(postApplyClient.RedirectUris, expansion.RedirectUris);
        ReplaceListContents(postApplyClient.PostLogoutRedirectUris, expansion.PostLogoutRedirectUris);
        ReplaceListContents(postApplyClient.AllowedCorsOrigins, expansion.AllowedCorsOrigins);
    }

    /// <summary>
    ///     Extracts the family name from a single URI value, returning <c>null</c> when the
    ///     value is not a family placeholder. Exposed as <c>internal</c> for unit tests that
    ///     want to pin the placeholder syntax independent of the full list-walk path.
    /// </summary>
    internal static string? TryParseFamilyName(string uri)
    {
        if (string.IsNullOrEmpty(uri))
        {
            return null;
        }

        var match = PlaceholderRegex.Match(uri);
        return match.Success ? match.Groups["name"].Value : null;
    }

    /// <summary>
    ///     Per-list normalisation. CORS origins must be valid HTTP origins per IdentityServer's
    ///     <c>ValidatingClientStore</c> — no trailing slash, no path, no query, no fragment. Only
    ///     the trailing slash is normalised here (the common ergonomics trap when an operator
    ///     puts the same family member URL in both <c>RedirectUris</c> and <c>AllowedCorsOrigins</c>);
    ///     other malformations are left for IdentityServer to reject loudly.
    /// </summary>
    /// <remarks>
    ///     Exposed as <c>internal</c> so the unit tests can pin the per-list rule.
    /// </remarks>
    internal static string NormaliseForList(string uri, UriListKind listKind)
    {
        return listKind switch
        {
            UriListKind.CorsOrigin => uri.TrimEnd('/'),
            _ => uri,
        };
    }

    private static (List<RtClientUriEntryRecord> Result, bool Changed) ReconcileList(
        IEnumerable<RtClientUriEntryRecord> sourceList,
        IReadOnlyDictionary<string, IReadOnlyList<string>> families,
        UriListKind listKind)
    {
        // Walk the source list once, partition into:
        //   - non-family entries: preserved verbatim in their original position
        //   - placeholder entries: dropped; their family names go into requestedFamilies
        //   - existing family:* entries: dropped; their family names go into presentFamilies
        var original = sourceList.ToList();
        var nonFamily = new List<RtClientUriEntryRecord>(original.Count);
        var requestedFamilies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var presentFamilies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in original)
        {
            var placeholderName = TryParseFamilyName(entry.Uri);
            if (placeholderName != null)
            {
                requestedFamilies.Add(placeholderName);
                continue;
            }

            if (entry.Source != null && entry.Source.StartsWith(SourcePrefix, StringComparison.Ordinal))
            {
                var familyName = entry.Source.Substring(SourcePrefix.Length);
                presentFamilies.Add(familyName);
                continue;
            }

            nonFamily.Add(entry);
        }

        // No family signal on this list → reconciler is inert. Return a copy of the original so
        // the comparison below is well-defined; Changed=false signals the caller to skip the
        // write.
        if (requestedFamilies.Count == 0 && presentFamilies.Count == 0)
        {
            return (original, false);
        }

        // Build the reconciled list: non-family entries first (preserving original relative
        // ordering), then for each known family name (placeholder ∪ existing) append the
        // current configured members. Iterate placeholder names first so a fresh activation
        // lands in the same position the seed declared, then existing-only names afterwards
        // (purely cosmetic — both arrive at the same list-tail).
        var reconciled = new List<RtClientUriEntryRecord>(nonFamily);
        var allFamilies = new List<string>(requestedFamilies.Count + presentFamilies.Count);
        allFamilies.AddRange(requestedFamilies);
        foreach (var name in presentFamilies)
        {
            if (!requestedFamilies.Contains(name))
            {
                allFamilies.Add(name);
            }
        }

        foreach (var familyName in allFamilies)
        {
            if (!families.TryGetValue(familyName, out var members) || members.Count == 0)
            {
                continue;
            }

            var sourceTag = SourcePrefix + familyName;
            foreach (var member in members)
            {
                if (string.IsNullOrWhiteSpace(member))
                {
                    continue;
                }

                reconciled.Add(new RtClientUriEntryRecord
                {
                    Uri = NormaliseForList(member, listKind),
                    Source = sourceTag
                });
            }
        }

        return (reconciled, !ListsEquivalent(original, reconciled));
    }

    private static bool ListsEquivalent(
        List<RtClientUriEntryRecord> left,
        List<RtClientUriEntryRecord> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        for (var i = 0; i < left.Count; i++)
        {
            if (!string.Equals(left[i].Uri, right[i].Uri, StringComparison.Ordinal)
                || !string.Equals(left[i].Source, right[i].Source, StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    private static void ReplaceListContents(
        IAttributeValueList<RtClientUriEntryRecord> target,
        IReadOnlyList<RtClientUriEntryRecord> replacement)
    {
        target.Clear();
        foreach (var entry in replacement)
        {
            target.Add(entry);
        }
    }
}

/// <summary>
///     Per-list-kind tag passed to <see cref="BlueprintClientUriFamilyResolver.NormaliseForList"/>
///     so the resolver can apply per-list format contracts (e.g. CORS origins drop trailing
///     slash) without coupling the per-list logic to the three concrete attribute names.
/// </summary>
internal enum UriListKind
{
    RedirectUri,
    PostLogoutRedirectUri,
    CorsOrigin,
}

/// <summary>
///     Per-client summary of a successful family reconciliation. The three list
///     properties are the FULL reconciled contents the orchestrator writes back into
///     the client entity — non-family entries (e.g. <c>${octo.*}</c>-resolved base URIs)
///     are preserved as-is alongside the freshly materialised family members.
/// </summary>
internal sealed record FamilyExpansion(
    OctoObjectId ClientRtId,
    string ClientId,
    IReadOnlyList<RtClientUriEntryRecord> RedirectUris,
    IReadOnlyList<RtClientUriEntryRecord> PostLogoutRedirectUris,
    IReadOnlyList<RtClientUriEntryRecord> AllowedCorsOrigins);
