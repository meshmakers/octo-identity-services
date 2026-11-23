using FluentAssertions;
using IdentityServerPersistence.SystemStores.OpenIddict;
using Shared.TestUtilities.Builders;
using Xunit;
using YamlDotNet.RepresentationModel;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServerPersistence.UnitTests.Blueprints;

/// <summary>
///     <c>System.Identity.Bootstrap</c> registers the API scope <c>ai.llm.invoke</c> that the AI service's
///     central-key LLM gateway requires, attaches it to the audience the AI service validates (<c>octoAPI</c>) and grants
///     it to NO client of the blueprint, so neither a user login nor an interactive client can obtain it. Pinned
///     against the seed files themselves, because the HTTP integration fixtures do not apply the blueprint.
/// </summary>
public class AiLlmInvokeScopeSeedTests
{
    private const string Scope = "ai.llm.invoke";
    private const string ScopeRtId = "660000000000000000000017";

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
        AttributeScalar(scope, "System.Identity/ShowInDiscoveryDocument").Should().Be("false",
            "a machine-only scope is not offered to interactive clients through the discovery document");
    }

    [Fact]
    public void ScopeSeed_RtIdIsUsedByNoOtherSeedEntity()
    {
        AllSeedEntities().Count(e => Scalar(e, "rtId") == ScopeRtId).Should().Be(1);
    }

    [Fact]
    public void OctoApiResource_CarriesTheScope_NextToThePlatformScopes()
    {
        var octoApi = Entities("seed-data/api-resources.yaml").Single(e => Scalar(e, "rtWellKnownName") == "octoAPI");

        AttributeList(octoApi, "System.Identity/Scopes").Should().BeEquivalentTo(
            ["octo_api", "octo_api.read_only", "octo_api.data_model_management", Scope],
            "the AI service validates the audience octoAPI, so a token for the scope must be issued for it");
    }

    [Fact]
    public void McpResourceIndicator_DoesNotCarryTheScope()
    {
        var mcpApi = Entities("seed-data/api-resources.yaml").Single(e => Scalar(e, "rtWellKnownName") == "mcpApi");

        AttributeList(mcpApi, "System.Identity/Scopes").Should().NotContain(Scope,
            "the MCP resource indicator serves interactive OAuth clients such as Claude Code");
    }

    [Fact]
    public void NoClientOfTheBlueprint_AllowsTheScope()
    {
        var clients = ClientEntities();
        clients.Should().NotBeEmpty();

        foreach (var client in clients)
        {
            var clientId = AttributeScalar(client, "System.Identity/ClientId");
            AttributeList(client, "System.Identity/AllowedScopes").Should().NotContain(Scope,
                "client {0} is a user-facing or default client (refinery-studio, octo-cli, swagger, MCP) and must not " +
                "obtain the LLM gateway scope", clientId);
        }
    }

    [Fact]
    public void NoClientOfTheBlueprint_GetsTheScopePermission()
    {
        foreach (var client in ClientEntities())
        {
            var rtClient = new RtClientBuilder()
                .WithClientId(AttributeScalar(client, "System.Identity/ClientId")!)
                .WithGrantTypes(AttributeList(client, "System.Identity/AllowedGrantTypes").ToArray())
                .WithScopes(AttributeList(client, "System.Identity/AllowedScopes").ToArray())
                .Build();

            ClientPermissionsMapper.MapPermissions(rtClient).Should().NotContain(Permissions.Prefixes.Scope + Scope);
        }
    }

    [Fact]
    public void ClientEntities_CoverEveryClientFileOfTheBlueprint()
    {
        var listed = SeedDataPaths().Where(p => p.StartsWith("seed-data/clients/", StringComparison.Ordinal)).ToList();
        var onDisk = Directory.GetFiles(Path.Combine(BlueprintDirectory, "seed-data", "clients"), "*.yaml")
            .Select(f => "seed-data/clients/" + Path.GetFileName(f))
            .ToList();

        listed.Should().BeEquivalentTo(onDisk, "the scan above must see every client the blueprint imports");
    }

    [Fact]
    public void BlueprintVersion_IsBumpedSoExistingTenantsReimportTheSeed()
    {
        var blueprintId = Scalar(LoadDocument("blueprint.yaml"), "blueprintId");

        blueprintId.Should().NotBeNull();
        var version = Version.Parse(blueprintId!["System.Identity.Bootstrap-".Length..]);
        version.Should().BeGreaterThanOrEqualTo(new Version(1, 10, 0),
            "1.10.0 added ai.llm.invoke; an unchanged version means existing tenants never re-import");
    }

    private static List<YamlMappingNode> ClientEntities() =>
        SeedDataPaths()
            .Where(p => p.StartsWith("seed-data/clients/", StringComparison.Ordinal))
            .SelectMany(Entities)
            .Where(e => Scalar(e, "ckTypeId") == "System.Identity/Client")
            .ToList();

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
