// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global

using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;

namespace IdentityServerPersistence.Configuration.Options;

public class OctoIdentityServicesOptions
{
    public OctoIdentityServicesOptions()
    {
        AuthorityUrl = "https://localhost:5003";
        RefineryStudioUrl = "https://localhost:4200";
        BrokerHost = "localhost";
        EnableTokenCleanup = true;
        TokenCleanupInterval = 60 * 60; // default: once an hour
        AllowDisplayInIframe = false;
#if DEBUGL || DEBUG
        MinLogLevel = LogLevelDto.Trace;
#else
        MinLogLevel = LogLevelDto.Warn;
#endif
    }

    /// <summary>
    /// The license key for the IdentityServer.
    /// </summary>
    public required string IdentityServerLicenseKey { get; set; }

    /// <summary>
    /// The license key for the AutoMapper.
    /// </summary>
    public required string AutoMapperLicenseKey { get; set; }

    /// <summary>
    ///     Gets or sets the prefix for the OctoMesh installation instance.
    /// </summary>
    public string? InstancePrefix { get; set; }

    /// <summary>
    ///     Gets or sets the RabbitMq host name
    /// </summary>
    public string BrokerHost { get; set; }

    /// <summary>
    ///     Gets or sets the RabbitMq user
    /// </summary>
    public string? BrokerUser { get; set; }

    /// <summary>
    ///     Gets or sets the RabbitMq password
    /// </summary>
    public string? BrokerPassword { get; set; }

    /// <summary>
    /// Gets or sets the public URL of the Identity service.
    /// </summary>
    public string AuthorityUrl { get; set; }

    /// <summary>
    /// Gets or sets the path to the certificate file used for signing tokens.
    /// </summary>
    public string? KeyFilePath { get; set; }

    /// <summary>
    /// Gets or sets the password for the certificate file used for signing tokens.
    /// </summary>
    public string? KeyFilePassword { get; set; }

    /// <summary>
    ///     If true, a host service is started to check periodically for expired tokens in grant store
    /// </summary>
    public bool EnableTokenCleanup { get; set; }

    /// <summary>
    ///     The interval in seconds, expired tokens in grant store are checked to be deleted.
    /// </summary>
    public int TokenCleanupInterval { get; set; }

    /// <summary>
    ///     Configure the SecurityHeaders so that displaying
    ///     Identity service in an iframe is allowed.
    /// </summary>
    public bool AllowDisplayInIframe { get; set; }

    /// <summary>
    /// Gets or sets the minimal log level to be logged
    /// </summary>
    public LogLevelDto MinLogLevel { get; set; }

    /// <summary>
    /// LEGACY/SEED-ONLY: former filesystem path for ASP.NET Data Protection keys.
    /// Keys are now always persisted in MongoDB (system tenant). When this path is set and
    /// contains key-*.xml files, they are imported once at first key-ring load so existing
    /// sessions survive the migration. Safe to remove after all environments have migrated.
    /// </summary>
    public string? DataProtectionKeysPath { get; set; }

    /// <summary>
    /// Gets or sets the public URL of the Data Refinery Studio SPA.
    /// Used to auto-provision the <c>octo-data-refinery-studio</c> OIDC client with correct
    /// redirect URIs, post-logout URIs, CORS origins, and front-channel logout URI.
    /// When null or empty, the Refinery Studio client is not auto-provisioned.
    /// </summary>
    public string? RefineryStudioUrl { get; set; }

    /// <summary>
    ///     Per-service public-URL overrides consumed by the blueprint apply pipeline. Keys are
    ///     the service slug (e.g. <c>"mcp"</c>); values are the explicit URL to surface as
    ///     <c>${octo.&lt;slug&gt;.publicUrl}</c> at blueprint apply time. Used in dev / Start-Octo
    ///     environments where services run natively on localhost with different ports and the
    ///     <c>${octo.scheme}://&lt;slug&gt;.${octo.domain}</c> composition pattern does not fit.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         Resolution order in <see cref="IdentityServerPersistence.Services.IdentityBlueprintVariableProvider"/>:
    ///         <list type="number">
    ///             <item>If this dictionary has an entry for the slug → use it verbatim.</item>
    ///             <item>Else if <c>octo.domain</c> is non-empty →
    ///                 <c>${octo.scheme}://&lt;slug&gt;.${octo.domain}</c>.</item>
    ///             <item>Else → empty string (the blueprint apply still succeeds; the OIDC
    ///                 failure at user login is the deliberate signal the operator forgot to
    ///                 set the URL — same pattern as <see cref="RefineryStudioUrl"/>).</item>
    ///         </list>
    ///     </para>
    ///     <para>
    ///         Configure via <c>OCTO_IDENTITY__SERVICEPUBLICURLOVERRIDES__MCP=https://localhost:5017</c>
    ///         in local dev. Cluster deployments leave it empty and rely on
    ///         <c>OCTO_BLUEPRINTS__DOMAIN</c> + the composition pattern.
    ///     </para>
    /// </remarks>
    public Dictionary<string, string> ServicePublicUrlOverrides { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    ///     Named families of additional URI entries injected into blueprint-managed
    ///     <c>RtClient</c> URI lists at Identity startup via the <c>{{family.NAME}}</c>
    ///     placeholder in the <c>System.Identity.Bootstrap</c> seed (AB#4209 Step 2b).
    ///     Each placeholder expands to <em>all</em> entries under <paramref name="NAME"/>
    ///     (0..N) with <c>Source = "family:NAME"</c> on the resulting <c>ClientUriEntry</c>
    ///     records.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         Configure via repeated env vars, e.g.
    ///         <c>OCTO_IDENTITY__URIFAMILIES__LOCAL-DEV__0=http://localhost:4200/</c>,
    ///         <c>OCTO_IDENTITY__URIFAMILIES__LOCAL-DEV__1=http://localhost:5173/</c>.
    ///         Empty / unset families resolve to no entries — the seed placeholder is
    ///         dropped silently so production clusters that leave dev families unconfigured
    ///         stay clean.
    ///     </para>
    ///     <para>
    ///         Entries are stored verbatim. The resolver is intentionally dumb about list
    ///         semantics (redirect-URI vs. CORS-origin): the operator is responsible for
    ///         picking values that match the target list's format contract. When the same
    ///         family is referenced from lists with incompatible formats (e.g. a trailing
    ///         slash matters for redirect URIs but breaks CORS origins on some IdentityServer
    ///         versions), configure two families with different names.
    ///     </para>
    ///     <para>
    ///         Family entries are <em>ephemeral</em>: every blueprint re-apply regenerates
    ///         them from the current configuration. The Step 2a preservation pass explicitly
    ///         skips <c>Source: "family:*"</c> entries when capturing pre-apply state, so
    ///         removing a family member from env config and restarting is enough to drop
    ///         the URI from the DB — no manual cleanup needed.
    ///     </para>
    /// </remarks>
    public Dictionary<string, List<string>> UriFamilies { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);
}