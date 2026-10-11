using Meshmakers.Octo.Communication.Contracts;
using YamlDotNet.RepresentationModel;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Blueprints;

/// <summary>
///     AB#5544: the <c>System.Identity.Bootstrap</c> blueprint seeds the tenant role <c>SecretManagement</c>
///     (stable rtId 660…60) next to AdminPanelManagement, assigns it to the TenantOwners group, and bumps
///     the blueprint version so existing tenants re-import the seed. Pinned against the seed files
///     themselves, because the integration fixtures do not apply the blueprint.
/// </summary>
public class SecretManagementRoleSeedTests
{
    private const string SecretManagementRtId = "660000000000000000000060";
    private const string TenantOwnersRtId = "660000000000000000000040";

    private static readonly string BlueprintDirectory = Path.Combine(FindRepositoryRoot(), "src",
        "Persistence.IdentityCkModel", "Blueprints", "System.Identity.Bootstrap");

    [Fact]
    public void RolesSeed_ContainsSecretManagement_WithTheWellKnownNameAndNormalizedName()
    {
        var roles = LoadEntities("seed-data/roles.yaml");

        var role = Assert.Single(roles, e => Scalar(e, "rtWellKnownName") == "SecretManagement");
        Assert.Equal(SecretManagementRtId, Scalar(role, "rtId"));
        Assert.Equal("System.Identity/Role", Scalar(role, "ckTypeId"));
        Assert.Equal(CommonConstants.SecretManagementRole, Attribute(role, "System/Name"));
        Assert.Equal("SECRETMANAGEMENT", Attribute(role, "System.Identity/NormalizedName"));

        // Next to AdminPanelManagement, with a unique rtId.
        Assert.Single(roles, e => Scalar(e, "rtWellKnownName") == CommonConstants.AdminPanelManagementRole);
        Assert.Single(roles, e => Scalar(e, "rtId") == SecretManagementRtId);
    }

    [Fact]
    public void SecretManagementRtId_IsNotUsedByAnyOtherSeedEntity()
    {
        var all = Directory.EnumerateFiles(Path.Combine(BlueprintDirectory, "seed-data"), "*.yaml",
                SearchOption.AllDirectories)
            .SelectMany(file => LoadEntities(Path.GetRelativePath(BlueprintDirectory, file)))
            .Where(e => Scalar(e, "rtId") == SecretManagementRtId)
            .ToList();

        Assert.Single(all);
    }

    [Fact]
    public void TenantOwnersGroup_IsAssignedSecretManagement()
    {
        var group = Assert.Single(LoadEntities("seed-data/groups.yaml"), e => Scalar(e, "rtId") == TenantOwnersRtId);

        var targets = ((YamlSequenceNode)group.Children[new YamlScalarNode("associations")]).Children
            .OfType<YamlMappingNode>()
            .Where(a => Scalar(a, "roleId") == "System.Identity/AssignedRole")
            .Select(a => Scalar(a, "targetRtId"))
            .ToList();

        Assert.Contains(SecretManagementRtId, targets);
    }

    [Fact]
    public void BlueprintVersion_IsBumpedForTheNewRole()
    {
        var manifest = LoadDocument("blueprint.yaml");

        var blueprintId = Scalar(manifest, "blueprintId");
        Assert.NotNull(blueprintId);
        var version = Version.Parse(blueprintId!["System.Identity.Bootstrap-".Length..]);
        Assert.True(version >= new Version(1, 7, 0), $"blueprint version {version} must be at least 1.7.0 (SECRET line)");
    }

    [Fact]
    public void RoleConstant_MatchesTheContractName()
    {
        Assert.Equal("SecretManagement", CommonConstants.SecretManagementRole);
    }

    private static List<YamlMappingNode> LoadEntities(string relativePath)
    {
        var root = LoadDocument(relativePath);
        return ((YamlSequenceNode)root.Children[new YamlScalarNode("entities")]).Children
            .OfType<YamlMappingNode>()
            .ToList();
    }

    private static YamlMappingNode LoadDocument(string relativePath)
    {
        using var reader = new StreamReader(Path.Combine(BlueprintDirectory, relativePath));
        var stream = new YamlStream();
        stream.Load(reader);
        return (YamlMappingNode)stream.Documents[0].RootNode;
    }

    private static string? Scalar(YamlMappingNode node, string key)
    {
        return node.Children.TryGetValue(new YamlScalarNode(key), out var value) ? (value as YamlScalarNode)?.Value : null;
    }

    private static string? Attribute(YamlMappingNode entity, string attributeId)
    {
        var attributes = (YamlSequenceNode)entity.Children[new YamlScalarNode("attributes")];
        return attributes.Children.OfType<YamlMappingNode>()
            .Where(a => Scalar(a, "id") == attributeId)
            .Select(a => Scalar(a, "value"))
            .SingleOrDefault();
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Octo.Identity.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ??
               throw new InvalidOperationException("Octo.Identity.sln not found above the test output directory.");
    }
}
