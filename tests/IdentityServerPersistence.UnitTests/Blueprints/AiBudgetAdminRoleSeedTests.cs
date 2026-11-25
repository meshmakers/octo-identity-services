using YamlDotNet.RepresentationModel;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Blueprints;

/// <summary>
///     The <c>System.Identity.Bootstrap</c> blueprint seeds the platform role <c>AiBudgetAdmin</c> (stable rtId
///     660…63), keeps it off the TenantOwners group and bumps the blueprint version to 1.11.0 so existing tenants re-import
///     the seed. The AI service accepts the role only in a token of the system tenant. Pinned against the seed files.
/// </summary>
public class AiBudgetAdminRoleSeedTests
{
    private const string AiBudgetAdminRtId = "660000000000000000000063";
    private const string TenantOwnersRtId = "660000000000000000000040";

    private static readonly string BlueprintDirectory = Path.Combine(FindRepositoryRoot(), "src",
        "Persistence.IdentityCkModel", "Blueprints", "System.Identity.Bootstrap");

    [Fact]
    public void RolesSeed_ContainsAiBudgetAdmin_WithTheWellKnownNameAndNormalizedName()
    {
        var role = Assert.Single(LoadEntities("seed-data/roles.yaml"),
            e => Scalar(e, "rtWellKnownName") == "AiBudgetAdmin");

        Assert.Equal(AiBudgetAdminRtId, Scalar(role, "rtId"));
        Assert.Equal("System.Identity/Role", Scalar(role, "ckTypeId"));
        Assert.Equal("AiBudgetAdmin", Attribute(role, "System/Name"));
        Assert.Equal("AIBUDGETADMIN", Attribute(role, "System.Identity/NormalizedName"));
    }

    [Fact]
    public void RolesSeed_HasEighteenRoles()
    {
        Assert.Equal(18, LoadEntities("seed-data/roles.yaml").Count(e => Scalar(e, "ckTypeId") == "System.Identity/Role"));
    }

    [Fact]
    public void AiBudgetAdminRtId_IsNotUsedByAnyOtherSeedEntity()
    {
        var all = Directory.EnumerateFiles(Path.Combine(BlueprintDirectory, "seed-data"), "*.yaml",
                SearchOption.AllDirectories)
            .SelectMany(file => LoadEntities(Path.GetRelativePath(BlueprintDirectory, file)))
            .Where(e => Scalar(e, "rtId") == AiBudgetAdminRtId)
            .ToList();

        Assert.Single(all);
    }

    [Fact]
    public void TenantOwnersGroup_IsNotAssignedAiBudgetAdmin()
    {
        // TenantOwners exists in every tenant and holds client accounts and provisioned parent administrators; the
        // budget role is granted by the platform owner to named holders of the system tenant only.
        var group = Assert.Single(LoadEntities("seed-data/groups.yaml"), e => Scalar(e, "rtId") == TenantOwnersRtId);

        var targets = ((YamlSequenceNode)group.Children[new YamlScalarNode("associations")]).Children
            .OfType<YamlMappingNode>()
            .Where(a => Scalar(a, "roleId") == "System.Identity/AssignedRole")
            .Select(a => Scalar(a, "targetRtId"))
            .ToList();

        Assert.DoesNotContain(AiBudgetAdminRtId, targets);
    }

    [Fact]
    public void BlueprintVersion_IsAtLeast1_11_0()
    {
        var blueprintId = Scalar(LoadDocument("blueprint.yaml"), "blueprintId");

        Assert.NotNull(blueprintId);
        var version = Version.Parse(blueprintId!["System.Identity.Bootstrap-".Length..]);
        Assert.True(version >= new Version(1, 11, 0),
            $"blueprint version {version} must be at least 1.11.0 (AiBudgetAdmin), or existing tenants never get the role");
    }

    private static List<YamlMappingNode> LoadEntities(string relativePath) =>
        ((YamlSequenceNode)LoadDocument(relativePath).Children[new YamlScalarNode("entities")]).Children
        .OfType<YamlMappingNode>()
        .ToList();

    private static string? Attribute(YamlMappingNode entity, string attributeId)
    {
        if (!entity.Children.TryGetValue(new YamlScalarNode("attributes"), out var node) ||
            node is not YamlSequenceNode attributes)
        {
            return null;
        }

        var attribute = attributes.Children.OfType<YamlMappingNode>().FirstOrDefault(a => Scalar(a, "id") == attributeId);
        return attribute == null ? null : Scalar(attribute, "value");
    }

    private static YamlMappingNode LoadDocument(string relativePath)
    {
        using var reader = new StreamReader(Path.Combine(BlueprintDirectory, relativePath));
        var stream = new YamlStream();
        stream.Load(reader);
        return (YamlMappingNode)stream.Documents[0].RootNode;
    }

    private static string? Scalar(YamlMappingNode node, string key) =>
        node.Children.TryGetValue(new YamlScalarNode(key), out var value) && value is YamlScalarNode scalar
            ? scalar.Value
            : null;

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Octo.Identity.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Octo.Identity.sln not found above the test output directory.");
    }
}
