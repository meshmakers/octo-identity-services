using YamlDotNet.RepresentationModel;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Blueprints;

/// <summary>
///     AB#6467 (blueprint 1.6.0): the file roles are linked to data permissions on System.Files, so FileViewer
///     reads, FileManagement reads and writes, and a caller with the API scope but no file role gets nothing.
///     Pinned against the seed files themselves, because the integration fixtures do not apply the blueprint.
/// </summary>
public class FilesDataPermissionsSeedTests
{
    private const string ReadPermissionRtId = "660000000000000000000052";
    private const string ManagePermissionRtId = "660000000000000000000053";
    private const string ReadPolicyRtId = "660000000000000000000054";
    private const string ManagePolicyRtId = "660000000000000000000055";
    private const string FileManagementRtId = "660000000000000000000061";
    private const string FileViewerRtId = "660000000000000000000062";

    private static readonly string BlueprintDirectory = Path.Combine(FindRepositoryRoot(), "src",
        "Persistence.IdentityCkModel", "Blueprints", "System.Identity.Bootstrap");

    [Theory]
    [InlineData(ReadPermissionRtId, "files.read")]
    [InlineData(ManagePermissionRtId, "files.manage")]
    public void Permissions_AreSeeded_WithTheIdsTheAssetRepositoryBaselineUses(string rtId, string permissionId)
    {
        var permission = Assert.Single(Entities("seed-data/data-permissions.yaml"), e => Scalar(e, "rtId") == rtId);
        Assert.Equal("System.Identity/DataPermission", Scalar(permission, "ckTypeId"));
        Assert.Equal(permissionId, Attribute(permission, "System.Identity/PermissionId"));
    }

    [Theory]
    [InlineData(ReadPolicyRtId, ReadPermissionRtId, "Read")]
    [InlineData(ManagePolicyRtId, ManagePermissionRtId, "Write,Delete")]
    public void Policies_TargetSystemFiles_AreEnforcing_AndLinkTheirPermission(string policyRtId,
        string permissionRtId, string actions)
    {
        var policy = Assert.Single(Entities("seed-data/data-permissions.yaml"), e => Scalar(e, "rtId") == policyRtId);
        Assert.Equal("System.Identity/DataPolicy", Scalar(policy, "ckTypeId"));
        Assert.Equal(["System.Files/FileSystemEntity"], Sequence(policy, "System.Identity/TargetCkTypeIds"));
        Assert.Equal(actions.Split(','), Sequence(policy, "System.Identity/PolicyActions"));
        Assert.Equal("0", Attribute(policy, "System.Identity/PolicyEnforcementMode")); // Enforce
        Assert.Equal("0", Attribute(policy, "System.Identity/PolicyScope")); // full access, not owned-only

        var association = Assert.Single(Associations(policy, "System.Identity/PolicyPermission"));
        Assert.Equal(permissionRtId, Scalar(association, "targetRtId"));
    }

    [Fact]
    public void FileViewer_ReadsOnly_FileManagement_ReadsAndWrites()
    {
        var roles = Entities("seed-data/roles.yaml");
        var viewer = Assert.Single(roles, e => Scalar(e, "rtId") == FileViewerRtId);
        var manager = Assert.Single(roles, e => Scalar(e, "rtId") == FileManagementRtId);

        Assert.Equal([ReadPermissionRtId], GrantedPermissions(viewer));
        Assert.Equal([ReadPermissionRtId, ManagePermissionRtId], GrantedPermissions(manager).Order().ToList());
    }

    [Fact]
    public void NewRtIds_AreUnique_AndTheSecretManagementIdIsUsedExactlyOnce()
    {
        var all = Directory.EnumerateFiles(Path.Combine(BlueprintDirectory, "seed-data"), "*.yaml",
                SearchOption.AllDirectories)
            .SelectMany(f => Entities(Path.GetRelativePath(BlueprintDirectory, f)))
            .Select(e => Scalar(e, "rtId"))
            .ToList();

        foreach (var rtId in new[] { ReadPermissionRtId, ManagePermissionRtId, ReadPolicyRtId, ManagePolicyRtId })
        {
            Assert.Single(all, x => x == rtId);
        }

        Assert.Equal(all.Count, all.Distinct().Count());
        // 660…60 belongs to the SecretManagement role of the SECRET line (AB#5544, blueprint 1.7.0):
        // present exactly once, and none of the Files ids above collides with it.
        Assert.Single(all, x => x == "660000000000000000000060");
    }

    [Fact]
    public void BlueprintVersion_IsAboveTheFilesRolesVersion()
    {
        var manifest = Document("blueprint.yaml");
        var blueprintId = Scalar(manifest, "blueprintId")!;
        var version = Version.Parse(blueprintId["System.Identity.Bootstrap-".Length..]);
        Assert.True(version > new Version(1, 5, 0), $"blueprint version {version} must be above 1.5.0 (Files roles)");
    }

    // ---------------------------------------------------------------------------------------------

    private static List<string> GrantedPermissions(YamlMappingNode role) =>
        Associations(role, "System.Identity/GrantsPermission").Select(a => Scalar(a, "targetRtId")!).ToList();

    private static IEnumerable<YamlMappingNode> Associations(YamlMappingNode entity, string roleId)
    {
        if (!entity.Children.TryGetValue(new YamlScalarNode("associations"), out var node))
        {
            return [];
        }

        return ((YamlSequenceNode)node).Children.OfType<YamlMappingNode>().Where(a => Scalar(a, "roleId") == roleId);
    }

    private static List<YamlMappingNode> Entities(string relativePath) =>
        ((YamlSequenceNode)Document(relativePath).Children[new YamlScalarNode("entities")]).Children
        .OfType<YamlMappingNode>().ToList();

    private static YamlMappingNode Document(string relativePath)
    {
        using var reader = new StreamReader(Path.Combine(BlueprintDirectory, relativePath));
        var stream = new YamlStream();
        stream.Load(reader);
        return (YamlMappingNode)stream.Documents[0].RootNode;
    }

    private static string? Scalar(YamlMappingNode node, string key) =>
        node.Children.TryGetValue(new YamlScalarNode(key), out var value) ? (value as YamlScalarNode)?.Value : null;

    private static YamlMappingNode AttributeNode(YamlMappingNode entity, string attributeId) =>
        ((YamlSequenceNode)entity.Children[new YamlScalarNode("attributes")]).Children.OfType<YamlMappingNode>()
        .Single(a => Scalar(a, "id") == attributeId);

    private static string? Attribute(YamlMappingNode entity, string attributeId) =>
        Scalar(AttributeNode(entity, attributeId), "value");

    private static List<string> Sequence(YamlMappingNode entity, string attributeId) =>
        ((YamlSequenceNode)AttributeNode(entity, attributeId).Children[new YamlScalarNode("value")]).Children
        .OfType<YamlScalarNode>().Select(n => n.Value!).ToList();

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
