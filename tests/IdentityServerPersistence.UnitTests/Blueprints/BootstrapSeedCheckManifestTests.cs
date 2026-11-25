using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;
using YamlDotNet.RepresentationModel;

namespace IdentityServerPersistence.UnitTests.Blueprints;

/// <summary>
///     The read-only seed check <c>scripts/identity-bootstrap-seed-check.sh</c> compares every tenant database with the
///     entities and associations of <c>System.Identity.Bootstrap</c> embedded in
///     <c>scripts/identity-bootstrap-seed-check.inventory.js</c>. That list must stay equal to the seed files: a seed change
///     without a manifest update would make the check report missing or unexpected entities that are fine (or miss real
///     ones).
/// </summary>
public class BootstrapSeedCheckManifestTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    private static readonly string BlueprintDirectory = Path.Combine(RepositoryRoot, "src",
        "Persistence.IdentityCkModel", "Blueprints", "System.Identity.Bootstrap");

    private static readonly string ScriptPath =
        Path.Combine(RepositoryRoot, "scripts", "identity-bootstrap-seed-check.inventory.js");

    [Fact]
    public void Manifest_NamesTheCurrentBlueprintVersion()
    {
        var blueprintId = Scalar(LoadDocument("blueprint.yaml"), "blueprintId");

        Regex.Match(Script(), "const SEED_BLUEPRINT = \"([^\"]+)\";").Groups[1].Value.Should().Be(blueprintId,
            "the seed check prints the blueprint it checks; bump it together with the seed");
    }

    [Fact]
    public void ManifestEntities_EqualTheSeedEntities()
    {
        var seed = SeedEntities()
            .Select(e => (RtId: Scalar(e, "rtId")!.ToLowerInvariant(), CkTypeId: Scalar(e, "ckTypeId")!))
            .ToList();

        seed.Should().HaveCount(42, "System.Identity.Bootstrap 1.11.0 seeds 42 entities");
        ManifestEntities().Should().BeEquivalentTo(seed);
    }

    [Fact]
    public void ManifestAssociations_EqualTheSeedAssociations()
    {
        var seed = new List<(string Origin, string Role, string Target, string TargetCkTypeId)>();
        foreach (var entity in SeedEntities())
        {
            if (!entity.Children.TryGetValue(new YamlScalarNode("associations"), out var node))
            {
                continue;
            }

            foreach (var association in ((YamlSequenceNode)node).Children.OfType<YamlMappingNode>())
            {
                seed.Add((Scalar(entity, "rtId")!.ToLowerInvariant(), Scalar(association, "roleId")!,
                    Scalar(association, "targetRtId")!.ToLowerInvariant(), Scalar(association, "targetCkTypeId")!));
            }
        }

        seed.Should().NotBeEmpty();
        ManifestAssociations().Should().BeEquivalentTo(seed);
    }

    private static string Script() => File.ReadAllText(ScriptPath);

    private static string Block(string name)
    {
        var script = Script();
        var start = script.IndexOf("const " + name + " = [", StringComparison.Ordinal);
        start.Should().BeGreaterThanOrEqualTo(0, "{0} is declared in the script", name);
        var end = script.IndexOf("];", start, StringComparison.Ordinal);
        return script[start..end];
    }

    private static List<(string RtId, string CkTypeId)> ManifestEntities() =>
        Regex.Matches(Block("SEED_ENTITIES"), "\\{ rtId: \"([0-9a-f]{24})\", ckTypeId: \"([^\"]+)\" \\}")
            .Select(m => (m.Groups[1].Value, m.Groups[2].Value))
            .ToList();

    private static List<(string, string, string, string)> ManifestAssociations() =>
        Regex.Matches(Block("SEED_ASSOCIATIONS"),
                "\\[\"([0-9a-f]{24})\", \"([^\"]+)\", \"([0-9a-f]{24})\", \"([^\"]+)\"\\]")
            .Select(m => (m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value, m.Groups[4].Value))
            .ToList();

    private static IEnumerable<YamlMappingNode> SeedEntities() =>
        ((YamlSequenceNode)LoadDocument("blueprint.yaml").Children[new YamlScalarNode("seedDataPaths")]).Children
        .OfType<YamlScalarNode>()
        .SelectMany(path => ((YamlSequenceNode)LoadDocument(path.Value!).Children[new YamlScalarNode("entities")])
            .Children.OfType<YamlMappingNode>());

    private static YamlMappingNode LoadDocument(string relativePath)
    {
        using var reader = new StreamReader(Path.Combine(BlueprintDirectory, relativePath));
        var stream = new YamlStream();
        stream.Load(reader);
        return (YamlMappingNode)stream.Documents[0].RootNode;
    }

    private static string? Scalar(YamlMappingNode node, string key) =>
        node.Children.TryGetValue(new YamlScalarNode(key), out var value) ? (value as YamlScalarNode)?.Value : null;

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Octo.Identity.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ??
               throw new DirectoryNotFoundException("Octo.Identity.sln not found above " + AppContext.BaseDirectory);
    }
}
