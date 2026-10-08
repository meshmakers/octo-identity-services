using YamlDotNet.RepresentationModel;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Blueprints;

/// <summary>
///     AB#6180: the <c>System.Identity.Bootstrap</c> blueprint seeds the tenant roles <c>FileManagement</c>
///     (660…61) and <c>FileViewer</c> (660…62), assigns both to the TenantOwners group, and bumps the blueprint
///     version so existing tenants re-import the seed. Pinned against the seed files themselves, because the
///     integration fixtures do not apply the blueprint.
/// </summary>
public class FileRolesSeedTests
{
    private const string FileManagementRtId = "660000000000000000000061";
    private const string FileViewerRtId = "660000000000000000000062";
    private const string TenantOwnersRtId = "660000000000000000000040";

    /// <summary>Reserved by the SecretManagement role of AB#5544 (not on main yet) — must never be reused.</summary>
    private const string ReservedSecretManagementRtId = "660000000000000000000060";

    private static readonly string BlueprintDirectory = Path.Combine(FindRepositoryRoot(), "src",
        "Persistence.IdentityCkModel", "Blueprints", "System.Identity.Bootstrap");

    [Theory]
    [InlineData(IdentityServiceConstants.FileManagementRole, FileManagementRtId, "FILEMANAGEMENT")]
    [InlineData(IdentityServiceConstants.FileViewerRole, FileViewerRtId, "FILEVIEWER")]
    public void RolesSeed_ContainsFileRole_WithTheWellKnownNameAndNormalizedName(
        string roleName, string rtId, string normalizedName)
    {
        var roles = LoadEntities("seed-data/roles.yaml");

        var role = Assert.Single(roles, e => Scalar(e, "rtWellKnownName") == roleName);
        Assert.Equal(rtId, Scalar(role, "rtId"));
        Assert.Equal("System.Identity/Role", Scalar(role, "ckTypeId"));
        Assert.Equal(roleName, Attribute(role, "System/Name"));
        Assert.Equal(normalizedName, Attribute(role, "System.Identity/NormalizedName"));
    }

    [Theory]
    [InlineData(FileManagementRtId)]
    [InlineData(FileViewerRtId)]
    public void FileRoleRtId_IsNotUsedByAnyOtherSeedEntity(string rtId)
    {
        Assert.Single(AllSeedEntities(), e => Scalar(e, "rtId") == rtId);
    }

    [Fact]
    public void ReservedSecretManagementRtId_IsNotTakenByTheFileRoles()
    {
        Assert.DoesNotContain(AllSeedEntities(),
            e => Scalar(e, "rtId") == ReservedSecretManagementRtId
                 && Scalar(e, "rtWellKnownName") != "SecretManagement");
    }

    [Fact]
    public void TenantOwnersGroup_IsAssignedBothFileRoles()
    {
        var group = Assert.Single(LoadEntities("seed-data/groups.yaml"), e => Scalar(e, "rtId") == TenantOwnersRtId);

        var targets = ((YamlSequenceNode)group.Children[new YamlScalarNode("associations")]).Children
            .OfType<YamlMappingNode>()
            .Where(a => Scalar(a, "roleId") == "System.Identity/AssignedRole")
            .Select(a => Scalar(a, "targetRtId"))
            .ToList();

        Assert.Contains(FileManagementRtId, targets);
        Assert.Contains(FileViewerRtId, targets);
    }

    [Fact]
    public void TenantOwnersGroup_IsAssignedEveryBuiltInRole()
    {
        var roleIds = LoadEntities("seed-data/roles.yaml").Select(e => Scalar(e, "rtId")).ToHashSet();
        var group = Assert.Single(LoadEntities("seed-data/groups.yaml"), e => Scalar(e, "rtId") == TenantOwnersRtId);
        var targets = ((YamlSequenceNode)group.Children[new YamlScalarNode("associations")]).Children
            .OfType<YamlMappingNode>()
            .Where(a => Scalar(a, "roleId") == "System.Identity/AssignedRole")
            .Select(a => Scalar(a, "targetRtId"))
            .ToHashSet();

        Assert.Equal(roleIds, targets);
    }

    [Fact]
    public void BlueprintVersion_IsBumpedForTheFileRoles()
    {
        var manifest = LoadDocument("blueprint.yaml");

        var blueprintId = Scalar(manifest, "blueprintId");
        Assert.NotNull(blueprintId);
        var version = Version.Parse(blueprintId!["System.Identity.Bootstrap-".Length..]);
        // 1.4.0 belongs to the SecretManagement role of AB#5544, so the File roles start at 1.5.0.
        Assert.True(version >= new Version(1, 5, 0), $"blueprint version {version} must be at least 1.5.0");
    }

    [Fact]
    public void LocalRoleConstants_MatchTheContractNames()
    {
        // TODO(AB#6180): compare with CommonConstants.FileManagementRole / FileViewerRole once the SDK is in the feed.
        Assert.Equal("FileManagement", IdentityServiceConstants.FileManagementRole);
        Assert.Equal("FileViewer", IdentityServiceConstants.FileViewerRole);
    }

    private static IEnumerable<YamlMappingNode> AllSeedEntities() =>
        Directory.EnumerateFiles(Path.Combine(BlueprintDirectory, "seed-data"), "*.yaml", SearchOption.AllDirectories)
            .SelectMany(file => LoadEntities(Path.GetRelativePath(BlueprintDirectory, file)))
            .ToList();

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
