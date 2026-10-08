using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;

namespace IdentityServerPersistence.Services;

/// <summary>How the CK model installed in a tenant relates to the version this service embeds.</summary>
public enum CkModelCompatibilityState
{
    /// <summary>No usable model of that name is installed.</summary>
    NotInstalled,

    /// <summary>An older version is installed (the embedded import upgrades it).</summary>
    Older,

    /// <summary>Exactly the embedded version is installed.</summary>
    Same,

    /// <summary>A newer version of the same major is installed: compatible, the service runs against it.</summary>
    NewerSameMajor,

    /// <summary>A higher major is installed: this service is too old for the tenant.</summary>
    NewerMajor
}

/// <summary>Result of <see cref="CkModelCompatibility.GetAsync" />.</summary>
/// <param name="Embedded">The version the service embeds.</param>
/// <param name="Installed">The highest installed version of the same name, if any.</param>
/// <param name="State">Classification of <paramref name="Installed" /> against <paramref name="Embedded" />.</param>
public sealed record CkModelCompatibilityResult(CkModelId Embedded, CkModelId? Installed, CkModelCompatibilityState State)
{
    /// <summary>The installed model satisfies the embedded one: same version or newer within the same major.</summary>
    public bool IsSatisfied => State is CkModelCompatibilityState.Same or CkModelCompatibilityState.NewerSameMajor;
}

/// <summary>
///     By-name CK model compatibility checks ("embedded version or newer, same major") — CK v2 Phase 1 G-H2.
/// </summary>
/// <remarks>
///     <para>
///         <c>ITenantContext.IsCkModelExistingAsync(CkModelId)</c> matches the EXACT version (<c>[x.y.z]</c>). That was
///         harmless while every embedded import downgraded the tenant to the service's version. With the engine's
///         downgrade guard (F1.0-S1, AB#5900) a tenant may keep a NEWER model than this service embeds, and an exact
///         check would then report "not installed": identity data creation answered "no identity CK" and every setup
///         re-ran a (skipped) import. Use these helpers for every existence/version decision on embedded models.
///     </para>
///     <para>
///         Only <c>Available</c> models count: a <c>ResolveFailed</c> model is not in the CK cache, so its types are
///         unusable; <c>Importing</c> rows are transient.
///     </para>
/// </remarks>
public static class CkModelCompatibility
{
    /// <summary>Pure classification of <paramref name="installed" /> against <paramref name="embedded" />.</summary>
    public static CkModelCompatibilityState Classify(CkModelId embedded, CkModelId? installed)
    {
        ArgumentNullException.ThrowIfNull(embedded);
        if (installed == null)
        {
            return CkModelCompatibilityState.NotInstalled;
        }

        var comparison = installed.Version.CompareTo(embedded.Version);
        if (comparison == 0)
        {
            return CkModelCompatibilityState.Same;
        }

        if (comparison < 0)
        {
            return CkModelCompatibilityState.Older;
        }

        return installed.Version.Major > embedded.Version.Major
            ? CkModelCompatibilityState.NewerMajor
            : CkModelCompatibilityState.NewerSameMajor;
    }

    /// <summary>
    ///     Picks the highest <c>Available</c> version named like <paramref name="embedded" /> from
    ///     <paramref name="installedModels" /> and classifies it.
    /// </summary>
    public static CkModelCompatibilityResult Evaluate(CkModelId embedded,
        IEnumerable<(CkModelId Id, ModelState State)> installedModels)
    {
        ArgumentNullException.ThrowIfNull(embedded);
        ArgumentNullException.ThrowIfNull(installedModels);

        var installed = installedModels
            .Where(m => m.State == ModelState.Available &&
                        string.Equals(m.Id.Name, embedded.Name, StringComparison.Ordinal))
            .Select(m => m.Id)
            .OrderByDescending(id => id.Version)
            .FirstOrDefault();

        return new CkModelCompatibilityResult(embedded, installed, Classify(embedded, installed));
    }

    /// <summary>Reads the tenant's installed CK models and evaluates <paramref name="embedded" /> by name.</summary>
    public static async Task<CkModelCompatibilityResult> GetAsync(ITenantContext tenantContext, CkModelId embedded)
    {
        ArgumentNullException.ThrowIfNull(tenantContext);

        var repository = tenantContext.GetTenantRepository();
        using var session = await repository.GetSessionAsync();
        var models = await repository.GetCkModelsAsync(session, null, RtEntityQueryOptions.Create());
        return Evaluate(embedded, models.Items.Select(m => (m.Id, m.ModelState)));
    }

    /// <summary>The message for a tenant whose installed major is higher than the embedded one.</summary>
    public static string TooOldMessage(string tenantId, CkModelCompatibilityResult result) =>
        $"Tenant '{tenantId}' has CK model '{result.Installed}' (major {result.Installed?.Version.Major}), but this " +
        $"service embeds '{result.Embedded}' (major {result.Embedded.Version.Major}). The service is too old for the " +
        "tenant; upgrade the service.";
}
