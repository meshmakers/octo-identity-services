using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Runtime.Contracts.Blueprints;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IdentityServerPersistence.Services;

/// <summary>
///     <see cref="IBlueprintVariableProvider"/> for the Identity service. Replaces the
///     engine's default registration with a richer set that includes the OctoMesh-standard
///     <c>octo.*</c> variables AND the Identity-specific keys consumed by
///     <c>System.Identity.Bootstrap-1.0.0</c> seed entities.
/// </summary>
/// <remarks>
///     <para>
///         The engine's <c>DefaultBlueprintVariableProvider</c> is <c>internal sealed</c>, so
///         this class re-implements its small set of keys rather than wrapping the type.
///         The duplicated logic (version normalisation, environment → mode mapping) is
///         intentionally kept aligned with the default implementation; any divergence in
///         behaviour would break blueprints that reference both standard and Identity-specific
///         variables from the same seed entity.
///     </para>
///     <para>
///         Identity-specific keys exposed:
///         <list type="bullet">
///             <item><c>octo.identity.authorityUrl</c> — public URL of the Identity service
///                 (from <c>OctoIdentityServicesOptions.AuthorityUrl</c>), trailing slash
///                 stripped. The <c>IdentityServicesSwaggerClient</c> seed entity composes
///                 redirect URIs on top of this base.</item>
///             <item><c>octo.identity.refineryStudioUrl</c> — public URL of the Refinery
///                 Studio SPA (from <c>OctoIdentityServicesOptions.RefineryStudioUrl</c>),
///                 trailing slash stripped. The <c>RefineryStudioClient</c> seed entity
///                 composes redirect URIs / CORS origins / front-channel logout URI on top.
///                 Resolves to the empty string when the option is unset — the blueprint
///                 still applies; the OIDC failure on user login is the deliberate signal
///                 the operator forgot to set the URL.</item>
///         </list>
///     </para>
/// </remarks>
public sealed class IdentityBlueprintVariableProvider : IBlueprintVariableProvider
{
    private readonly IOptionsMonitor<OctoBlueprintVariablesOptions> _baseOptions;
    private readonly IOptionsMonitor<OctoIdentityServicesOptions> _identityOptions;
    private readonly ILogger<IdentityBlueprintVariableProvider> _logger;

    public IdentityBlueprintVariableProvider(
        IOptionsMonitor<OctoBlueprintVariablesOptions> baseOptions,
        IOptionsMonitor<OctoIdentityServicesOptions> identityOptions,
        ILogger<IdentityBlueprintVariableProvider> logger)
    {
        _baseOptions = baseOptions;
        _identityOptions = identityOptions;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task<IReadOnlyDictionary<string, string>> GetVariablesAsync(
        string tenantId,
        CancellationToken cancellationToken = default)
    {
        var baseSnapshot = _baseOptions.CurrentValue;
        var identitySnapshot = _identityOptions.CurrentValue;

        var systemTenantId = baseSnapshot.SystemTenantId ?? OctoBlueprintVariablesOptions.DefaultSystemTenantId;
        var environment = baseSnapshot.Environment ?? OctoBlueprintVariablesOptions.DefaultEnvironment;
        var isSystemTenant = string.Equals(tenantId, systemTenantId, StringComparison.OrdinalIgnoreCase);

        IReadOnlyDictionary<string, string> variables = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["octo.version"] = NormalizeOctoVersion(baseSnapshot.OctoVersion ?? string.Empty),
            ["octo.environment"] = environment,
            ["octo.environmentMode"] = MapEnvironmentToMode(environment),
            ["octo.tenantId"] = tenantId,
            ["octo.systemTenantId"] = systemTenantId,
            ["octo.isSystemTenant"] = isSystemTenant ? "true" : "false",
            ["octo.identity.authorityUrl"] = (identitySnapshot.AuthorityUrl ?? string.Empty).TrimEnd('/'),
            ["octo.identity.refineryStudioUrl"] = (identitySnapshot.RefineryStudioUrl ?? string.Empty).TrimEnd('/'),
        };

        return Task.FromResult(variables);
    }

    /// <summary>
    /// Trims a .NET-style 4-segment version (<c>MAJOR.MINOR.PATCH.REVISION</c>) down to a
    /// Helm-compatible 3-segment SemVer, preserving any pre-release / build-metadata suffix.
    /// Mirrors the engine's <c>DefaultBlueprintVariableProvider.NormalizeOctoVersion</c>.
    /// </summary>
    private static string NormalizeOctoVersion(string version)
    {
        if (string.IsNullOrEmpty(version))
        {
            return string.Empty;
        }

        var suffixStart = version.IndexOfAny(new[] { '-', '+' });
        var core = suffixStart >= 0 ? version.Substring(0, suffixStart) : version;
        var suffix = suffixStart >= 0 ? version.Substring(suffixStart) : string.Empty;

        var parts = core.Split('.');
        if (parts.Length <= 3)
        {
            return version;
        }

        return string.Join(".", parts.Take(3)) + suffix;
    }

    /// <summary>
    /// Maps the helm-injected <c>octo.environment</c> token to the matching
    /// <c>System/EnvironmentModes</c> CK-enum value name. Unknown environments log a
    /// warning and fall back to <c>Development</c>. Mirrors the engine's
    /// <c>DefaultBlueprintVariableProvider.MapEnvironmentToMode</c>.
    /// </summary>
    private string MapEnvironmentToMode(string environment)
    {
        var mapped = environment.Trim().ToLowerInvariant() switch
        {
            "dev" => "Development",
            "test" => "Testing",
            "staging" => "Staging",
            "production" => "Production",
            _ => (string?)null,
        };

        if (mapped != null)
        {
            return mapped;
        }

        _logger.LogWarning(
            "Blueprint variable octo.environment='{Environment}' does not map to a known System/EnvironmentModes value (dev/test/staging/production). Falling back to 'Development' for ${{octo.environmentMode}}. Set OCTO_BLUEPRINTS__ENVIRONMENT to one of the known values to silence this warning.",
            environment);

        return "Development";
    }
}
