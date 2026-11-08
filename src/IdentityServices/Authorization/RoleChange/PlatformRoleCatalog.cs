using Meshmakers.Octo.ConstructionKit.Contracts.BlueprintCatalogs;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using YamlDotNet.RepresentationModel;

namespace Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;

/// <summary>
///     Tells platform roles from app roles (AB#8564). A <b>platform role</b> is a built-in role (a role with an
///     <c>rtWellKnownName</c>) that the identity service's own blueprint <c>System.Identity.Bootstrap</c> seeds, e.g.
///     <c>TenantManagement</c>, <c>UserManagement</c>, <c>StreamDataAdmin</c>, <c>SecretManagement</c>,
///     <c>DataModelManagement</c>. Every other built-in role is an <b>app role</b>: a role an installed blueprint seeds,
///     e.g. <c>EnergyCommunityManagement</c> from EnergyCommunity.Base. Custom roles (no <c>rtWellKnownName</c>) are neither.
/// </summary>
public interface IPlatformRoleCatalog
{
    /// <summary><c>true</c> when <paramref name="role" /> is a built-in role seeded by <c>System.Identity.Bootstrap</c>.</summary>
    bool IsPlatformRole(RtRole role);
}

/// <summary>
///     Reads the role set from the seed data of the embedded <c>System.Identity.Bootstrap</c> blueprint, the same files the
///     service applies to every tenant, so the list follows the blueprint and is never kept by hand. A role counts as a
///     platform role when its <c>rtWellKnownName</c> or its <c>rtId</c> is one of the seed's roles.
/// </summary>
/// <remarks>
///     Fails closed: when the seed cannot be read (no embedded source, no role found), every built-in role counts as a
///     platform role, which is the rule of AB#7914 before AB#8564.
/// </remarks>
internal sealed class BootstrapPlatformRoleCatalog : IPlatformRoleCatalog
{
    /// <summary>Name of the identity service's own blueprint.</summary>
    public const string BootstrapBlueprintName = "System.Identity.Bootstrap";

    private const string RoleCkTypeId = "System.Identity/Role";

    private readonly Lazy<PlatformRoleSet> _roles;

    public BootstrapPlatformRoleCatalog(IEnumerable<IBlueprintEmbeddedSource> sources,
        ILogger<BootstrapPlatformRoleCatalog> logger)
    {
        var bootstrapSources = sources
            .Where(s => string.Equals(s.BlueprintId.Name, BootstrapBlueprintName, StringComparison.Ordinal))
            .ToList();
        _roles = new Lazy<PlatformRoleSet>(() => Load(bootstrapSources, logger));
    }

    /// <summary>The <c>rtWellKnownName</c>s of the seed's roles (empty when the seed could not be read).</summary>
    public IReadOnlyCollection<string> WellKnownNames => _roles.Value.WellKnownNames;

    public bool IsPlatformRole(RtRole role)
    {
        if (string.IsNullOrEmpty(role.RtWellKnownName))
        {
            return false;
        }

        var roles = _roles.Value;
        return roles.IsEmpty ||
               roles.WellKnownNames.Contains(role.RtWellKnownName) ||
               roles.RtIds.Contains(role.RtId.ToString());
    }

    private static PlatformRoleSet Load(IReadOnlyCollection<IBlueprintEmbeddedSource> sources, ILogger logger)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var source in sources)
            {
                var prefix = source.ResourceNamespace + ".";
                var manifest = source.ResourceNamespace + ".blueprint.yaml";
                foreach (var resource in source.Assembly.GetManifestResourceNames()
                             .Where(r => r.StartsWith(prefix, StringComparison.Ordinal) &&
                                         r.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase) &&
                                         !string.Equals(r, manifest, StringComparison.Ordinal)))
                {
                    using var stream = source.Assembly.GetManifestResourceStream(resource);
                    if (stream != null)
                    {
                        using var reader = new StreamReader(stream);
                        ReadRoles(reader, names, ids);
                    }
                }
            }
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Could not read the roles of {Blueprint}; every built-in role is treated as a platform role",
                BootstrapBlueprintName);
            return PlatformRoleSet.Empty;
        }

        if (names.Count == 0)
        {
            logger.LogError(
                "No role found in the embedded {Blueprint} seed; every built-in role is treated as a platform role",
                BootstrapBlueprintName);
            return PlatformRoleSet.Empty;
        }

        logger.LogInformation("Platform roles from {Blueprint}: {Roles}", BootstrapBlueprintName,
            string.Join(", ", names.Order(StringComparer.Ordinal)));
        return new PlatformRoleSet(names, ids);
    }

    /// <summary>Collects <c>rtWellKnownName</c> and <c>rtId</c> of every <c>System.Identity/Role</c> entity of one seed file.</summary>
    internal static void ReadRoles(TextReader reader, ISet<string> names, ISet<string> ids)
    {
        var yaml = new YamlStream();
        yaml.Load(reader);
        foreach (var document in yaml.Documents)
        {
            if (document.RootNode is not YamlMappingNode root ||
                !root.Children.TryGetValue(new YamlScalarNode("entities"), out var entitiesNode) ||
                entitiesNode is not YamlSequenceNode entities)
            {
                continue;
            }

            foreach (var entity in entities.OfType<YamlMappingNode>())
            {
                if (!string.Equals(Scalar(entity, "ckTypeId"), RoleCkTypeId, StringComparison.Ordinal))
                {
                    continue;
                }

                var wellKnownName = Scalar(entity, "rtWellKnownName");
                if (!string.IsNullOrEmpty(wellKnownName))
                {
                    names.Add(wellKnownName);
                }

                var rtId = Scalar(entity, "rtId");
                if (!string.IsNullOrEmpty(rtId))
                {
                    ids.Add(rtId);
                }
            }
        }
    }

    private static string? Scalar(YamlMappingNode node, string key) =>
        node.Children.TryGetValue(new YamlScalarNode(key), out var value) && value is YamlScalarNode scalar
            ? scalar.Value
            : null;

    private sealed record PlatformRoleSet(IReadOnlySet<string> WellKnownNames, IReadOnlySet<string> RtIds)
    {
        public static PlatformRoleSet Empty { get; } =
            new(new HashSet<string>(StringComparer.Ordinal), new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        public bool IsEmpty => WellKnownNames.Count == 0;
    }
}
