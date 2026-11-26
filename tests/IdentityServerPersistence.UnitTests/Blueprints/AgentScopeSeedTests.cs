using FluentAssertions;
using Xunit;
using YamlDotNet.RepresentationModel;

namespace IdentityServerPersistence.UnitTests.Blueprints;

/// <summary>
///     <c>System.Identity.Bootstrap</c> registers the agent scope <c>octo_agent</c> and attaches it to the MCP
///     resource indicator only, so a token of an agent's service-account client opens no platform API by itself (every
///     platform API requires <c>octo_api</c>, which the octoAPI resource carries). No client of the blueprint allows it.
///     Pinned against the seed files themselves, because the HTTP integration fixtures do not apply the blueprint.
/// </summary>
public class AgentScopeSeedTests
{
    private const string Scope = "octo_agent";
    private const string ScopeRtId = "660000000000000000000018";

    private static readonly string BlueprintDirectory = Path.Combine(FindRepositoryRoot(), "src",
        "Persistence.IdentityCkModel", "Blueprints", "System.Identity.Bootstrap");

    [Fact]
    public void ScopeSeed_IsEnabledUnderItsStableRtId_AndNotAdvertised()
    {
        var scope = Entities("seed-data/api-scopes.yaml").Single(e => Scalar(e, "rtId") == ScopeRtId);

        Scalar(scope, "ckTypeId").Should().Be("System.Identity/ApiScope");
        Scalar(scope, "rtWellKnownName").Should().Be(Scope);
        AttributeScalar(scope, "System/Name").Should().Be(Scope);
        AttributeScalar(scope, "System/Enabled").Should().Be("true");
        AttributeScalar(scope, "System.Identity/ShowInDiscoveryDocument").Should().Be("false");
    }

    [Fact]
    public void ScopeSeed_RtIdIsUsedByNoOtherSeedEntity()
    {
        AllSeedEntities().Count(e => Scalar(e, "rtId") == ScopeRtId).Should().Be(1);
    }

    [Fact]
    public void McpResourceIndicator_CarriesTheScope()
    {
        var mcpApi = Entities("seed-data/api-resources.yaml").Single(e => Scalar(e, "rtWellKnownName") == "mcpApi");

        AttributeList(mcpApi, "System.Identity/Scopes").Should().Contain(Scope,
            "a token for the agent scope is issued for the MCP audience");
    }

    [Fact]
    public void OctoApiResource_DoesNotCarryTheScope()
    {
        var octoApi = Entities("seed-data/api-resources.yaml").Single(e => Scalar(e, "rtWellKnownName") == "octoAPI");

        AttributeList(octoApi, "System.Identity/Scopes").Should().NotContain(Scope,
            "the platform APIs must never accept an agent token directly");
    }

    [Fact]
    public void NoClientOfTheBlueprint_AllowsTheScope()
    {
        var clients = SeedDataPaths()
            .Where(p => p.StartsWith("seed-data/clients/", StringComparison.Ordinal))
            .SelectMany(Entities)
            .Where(e => Scalar(e, "ckTypeId") == "System.Identity/Client")
            .ToList();
        clients.Should().NotBeEmpty();

        foreach (var client in clients)
        {
            AttributeList(client, "System.Identity/AllowedScopes").Should().NotContain(Scope,
                "only the agent clients MCP's create_agent registers get the agent scope ({0})",
                AttributeScalar(client, "System.Identity/ClientId"));
        }
    }

    [Fact]
    public void BlueprintVersion_IsBumpedSoExistingTenantsReimportTheSeed()
    {
        var blueprintId = Scalar(LoadDocument("blueprint.yaml"), "blueprintId");

        blueprintId.Should().NotBeNull();
        Version.Parse(blueprintId!["System.Identity.Bootstrap-".Length..]).Should()
            .BeGreaterThanOrEqualTo(new Version(1, 11, 0), "1.11.0 added octo_agent");
    }

    private static IEnumerable<YamlMappingNode> AllSeedEntities() => SeedDataPaths().SelectMany(Entities);

    private static List<string> SeedDataPaths() =>
        ((YamlSequenceNode)LoadDocument("blueprint.yaml").Children[new YamlScalarNode("seedDataPaths")]).Children
        .OfType<YamlScalarNode>()
        .Select(n => n.Value!)
        .ToList();

    private static IEnumerable<YamlMappingNode> Entities(string relativePath) =>
        ((YamlSequenceNode)LoadDocument(relativePath).Children[new YamlScalarNode("entities")]).Children
        .OfType<YamlMappingNode>();

    private static YamlNode? Attribute(YamlMappingNode entity, string attributeId)
    {
        var attributes = (YamlSequenceNode)entity.Children[new YamlScalarNode("attributes")];
        return attributes.Children.OfType<YamlMappingNode>()
            .Where(a => Scalar(a, "id") == attributeId)
            .Select(a => a.Children[new YamlScalarNode("value")])
            .SingleOrDefault();
    }

    private static string? AttributeScalar(YamlMappingNode entity, string attributeId) =>
        (Attribute(entity, attributeId) as YamlScalarNode)?.Value;

    private static List<string> AttributeList(YamlMappingNode entity, string attributeId) =>
        Attribute(entity, attributeId) is YamlSequenceNode sequence
            ? sequence.Children.OfType<YamlScalarNode>().Select(n => n.Value!).ToList()
            : [];

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
