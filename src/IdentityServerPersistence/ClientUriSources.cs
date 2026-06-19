namespace IdentityServerPersistence;

/// <summary>
///     Canonical values of <c>ClientUriEntry.Source</c> — the provenance marker on every entry
///     of <c>RtClient.RedirectUris</c> / <c>PostLogoutRedirectUris</c> / <c>AllowedCorsOrigins</c>.
/// </summary>
/// <remarks>
///     <para>
///         The cleanup gate (<c>PreBlueprintCleanupMigration</c>) and the blueprint engine's
///         <c>force: true</c> re-apply both rewrite only <see cref="Base"/> entries. <see cref="Api"/>
///         entries and overlay-named entries (<c>"overlay:&lt;name&gt;"</c>) survive every lifecycle
///         event — that is the load-bearing property the Phase 3 follow-up depends on
///         (concept §4.5).
///     </para>
///     <para>
///         There is intentionally no <c>Overlay</c> constant here: overlay sources are
///         runtime-named (e.g. <c>"overlay:local-dev"</c>) and the cmdlet that writes them owns
///         the suffix. Detect them with
///         <c>source.StartsWith("overlay:", StringComparison.Ordinal)</c>.
///     </para>
/// </remarks>
public static class ClientUriSources
{
    /// <summary>
    ///     Blueprint-seed and cross-service identity-bootstrap entries. Rewritten on every
    ///     blueprint re-apply. <see cref="ClientUriSources"/> remarks list the rule.
    /// </summary>
    public const string Base = "base";

    /// <summary>
    ///     REST-API-added entries (typically through the Studio Client-UI editing flow). Survive
    ///     every blueprint re-apply and every cleanup-gate sweep — an operator who adds a URI
    ///     through the API meant the URI to be persistent.
    /// </summary>
    public const string Api = "api";

    /// <summary>
    ///     Prefix on every overlay-managed source value. <see cref="ClientUriSources"/> remarks
    ///     explain why there is no per-overlay constant here.
    /// </summary>
    public const string OverlayPrefix = "overlay:";
}
