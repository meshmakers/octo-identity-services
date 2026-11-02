using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores.OpenIddict;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using NSubstitute;
using NSubstitute.Core;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;
using YamlDotNet.RepresentationModel;

namespace IdentityServerPersistence.UnitTests.Blueprints;

/// <summary>
///     AB#6839: the <c>octo-cli</c> client of the <c>System.Identity.Bootstrap</c> blueprint allows the RFC 8693
///     token-exchange grant next to the device-code grant (octo-cli exchanges the operator's home-tenant token for a
///     child-tenant token), the blueprint version was bumped so existing tenants re-import the seed, and a client
///     mirrored from it into a child tenant carries the same grants. Pinned against the seed files themselves,
///     because the integration fixtures do not apply the blueprint.
/// </summary>
public class OctoCliClientTokenExchangeSeedTests
{
    private const string DeviceCode = "urn:ietf:params:oauth:grant-type:device_code";
    private const string TokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";

    private static readonly string BlueprintDirectory = Path.Combine(FindRepositoryRoot(), "src",
        "Persistence.IdentityCkModel", "Blueprints", "System.Identity.Bootstrap");

    [Fact]
    public void OctoCliClientSeed_AllowsExactlyDeviceCodeAndTokenExchange()
    {
        SeededGrantTypes().Should().BeEquivalentTo([DeviceCode, TokenExchange]);
    }

    [Fact]
    public void OctoCliClientSeed_StaysAPublicClientWithoutSecretThatMirrorsToChildTenants()
    {
        var client = SeededClientEntity();

        AttributeScalar(client, "System.Identity/RequireClientSecret").Should().Be("false");
        AttributeScalar(client, "System.Identity/AutoProvisionInChildTenants").Should().Be("true");
    }

    [Fact]
    public void SeededGrantTypes_MapToDeviceCodeAndTokenExchangePermissions()
    {
        var client = new RtClientBuilder()
            .WithClientId("octo-cli")
            .WithGrantTypes(SeededGrantTypes().ToArray())
            .Build();

        ClientPermissionsMapper.GetUnsupportedGrantTypes(client).Should().BeEmpty(
            "every seeded grant must map to an OpenIddict permission or the client silently loses it");
        ClientPermissionsMapper.MapPermissions(client).Should().Contain(
            [OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.TokenExchange]);
    }

    [Theory]
    [InlineData(new string[0], true)]
    [InlineData(new[] { DeviceCode }, true)]
    [InlineData(new[] { DeviceCode, TokenExchange }, false)]
    [InlineData(new[] { TokenExchange }, false)]
    public void ExistingTenantStep_NeedsTheGrantOnlyWhenItIsMissing(string[] grants, bool expected)
    {
        IdentityServerPersistence.Services.ClientGrants.OctoCliTokenExchangeGrant.NeedsGrant(grants)
            .Should().Be(expected);
        IdentityServerPersistence.Services.ClientGrants.OctoCliTokenExchangeGrant.NeedsGrant(null)
            .Should().BeTrue();
    }

    [Fact]
    public void ExistingTenantStep_UsesTheSameGrantUrnAsTheSeed()
    {
        IdentityServerPersistence.Services.ClientGrants.OctoCliTokenExchangeGrant.TokenExchangeGrantType
            .Should().Be(TokenExchange);
        SeededGrantTypes().Should().Contain(IdentityServerPersistence.Services.ClientGrants.OctoCliTokenExchangeGrant
            .TokenExchangeGrantType);
    }

    [Fact]
    public void BlueprintVersion_IsBumpedSoExistingTenantsReimportTheSeed()
    {
        var blueprintId = Scalar(LoadDocument("blueprint.yaml"), "blueprintId");

        blueprintId.Should().NotBeNull();
        var version = Version.Parse(blueprintId!["System.Identity.Bootstrap-".Length..]);
        version.Should().BeGreaterThanOrEqualTo(new Version(1, 8, 0),
            "1.8.0 added the token-exchange grant to octo-cli; an unchanged version means existing tenants never re-import");
    }

    [Fact]
    public async Task ClientMirroredFromTheSeededOctoCli_CarriesTheSameGrants()
    {
        const string parentTenantId = "octosystem";
        const string childTenantId = "acme";
        var systemContext = Substitute.For<ISystemContext>();
        var parentRepo = Substitute.For<ITenantRepository>();
        var childRepo = Substitute.For<ITenantRepository>();
        var parentSession = Substitute.For<IOctoSession>();
        var childSession = Substitute.For<IOctoSession>();
        parentRepo.GetSessionAsync().Returns(parentSession);
        childRepo.GetSessionAsync().Returns(childSession);
        systemContext.TryFindTenantRepositoryAsync(parentTenantId).Returns(parentRepo);
        systemContext.TryFindTenantRepositoryAsync(childTenantId).Returns(childRepo);
        systemContext.TenantId.Returns(parentTenantId);

        var parent = new RtClientBuilder()
            .WithClientId("octo-cli")
            .WithGrantTypes(SeededGrantTypes().ToArray())
            .WithAutoProvisionInChildTenants()
            .Build();
        Returns(parentRepo, parentSession, new[] { parent });
        Returns(parentRepo, parentSession, Array.Empty<RtClientMirror>());
        Returns(childRepo, childSession, Array.Empty<RtClient>());

        var sut = new ClientMirrorProvisioningService(
            new Shared.TestUtilities.Fakes.CapturingLogger<ClientMirrorProvisioningService>(),
            systemContext, Substitute.For<ITenantDiscoveryService>());

        await sut.ProvisionForChildTenantAsync(parentTenantId, childTenantId);

        var mirrored = childRepo.ReceivedCalls()
            .Where(c => c.GetMethodInfo().Name == "InsertOneRtEntityAsync")
            .SelectMany(c => c.GetArguments().OfType<RtClient>())
            .Single();
        mirrored.ClientId.Should().Be("octo-cli");
        mirrored.AllowedGrantTypes.Should().BeEquivalentTo([DeviceCode, TokenExchange]);
    }

    private static void Returns(ITenantRepository repo, IOctoSession session, RtClient[] items)
    {
        var result = Substitute.For<IResultSet<RtClient>>();
        result.Items.Returns(items);
        repo.GetRtEntitiesByTypeAsync<RtClient>(session, Arg.Any<RtEntityQueryOptions>()).Returns(result);
    }

    private static void Returns(ITenantRepository repo, IOctoSession session, RtClientMirror[] items)
    {
        var result = Substitute.For<IResultSet<RtClientMirror>>();
        result.Items.Returns(items);
        repo.GetRtEntitiesByTypeAsync<RtClientMirror>(session, Arg.Any<RtEntityQueryOptions>()).Returns(result);
    }

    private static List<string> SeededGrantTypes()
    {
        var attributes = (YamlSequenceNode)SeededClientEntity().Children[new YamlScalarNode("attributes")];
        var grants = attributes.Children.OfType<YamlMappingNode>()
            .Single(a => Scalar(a, "id") == "System.Identity/AllowedGrantTypes");
        return ((YamlSequenceNode)grants.Children[new YamlScalarNode("value")]).Children
            .OfType<YamlScalarNode>()
            .Select(n => n.Value!)
            .ToList();
    }

    private static YamlMappingNode SeededClientEntity()
    {
        var root = LoadDocument("seed-data/clients/octo-tool.yaml");
        var entities = ((YamlSequenceNode)root.Children[new YamlScalarNode("entities")]).Children
            .OfType<YamlMappingNode>();
        return entities.Single(e => AttributeScalar(e, "System.Identity/ClientId") == "octo-cli");
    }

    private static string? AttributeScalar(YamlMappingNode entity, string attributeId)
    {
        var attributes = (YamlSequenceNode)entity.Children[new YamlScalarNode("attributes")];
        return attributes.Children.OfType<YamlMappingNode>()
            .Where(a => Scalar(a, "id") == attributeId)
            .Select(a => Scalar(a, "value"))
            .SingleOrDefault();
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
        return node.Children.TryGetValue(new YamlScalarNode(key), out var value)
            ? (value as YamlScalarNode)?.Value
            : null;
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
