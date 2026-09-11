using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServerPersistence.SystemStores.OpenIddict;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Stores;

/// <summary>
///     AB#5193: the resource-indicator (RFC 8707) lookup behind the OpenIddict server handlers.
///     Pins the two semantics the handlers rely on — disabled resources are invisible, and a
///     trailing slash is insignificant — plus the single-round-trip contract.
/// </summary>
public class OpenIddictResourceStoreTests
{
    private const string SeededWithSlash = "https://localhost:5017/";
    private const string SeededWithoutSlash = "https://localhost:5017";

    private readonly IOctoResourceStore _resourceStore = Substitute.For<IOctoResourceStore>();
    private readonly OpenIddictResourceStore _sut;

    public OpenIddictResourceStoreTests()
    {
        _sut = new OpenIddictResourceStore(_resourceStore);
    }

    [Fact]
    public async Task FindByNamesAsync_ExactName_ReturnsResource()
    {
        var ct = TestContext.Current.CancellationToken;
        StoredResources(ApiResource(SeededWithSlash));

        var found = await CollectAsync(_sut.FindByNamesAsync([SeededWithSlash], ct), ct);

        found.Should().ContainSingle().Which.Name.Should().Be(SeededWithSlash);
    }

    [Fact]
    public async Task FindByNamesAsync_RequestedWithoutTrailingSlash_MatchesSeededWithSlash()
    {
        var ct = TestContext.Current.CancellationToken;
        StoredResources(ApiResource(SeededWithSlash));

        var found = await CollectAsync(_sut.FindByNamesAsync([SeededWithoutSlash], ct), ct);

        found.Should().ContainSingle("the MCP metadata advertises the identifier without the slash " +
                                     "while the blueprint seeds it with one");
    }

    [Fact]
    public async Task FindByNamesAsync_RequestedWithTrailingSlash_MatchesSeededWithoutSlash()
    {
        var ct = TestContext.Current.CancellationToken;
        StoredResources(ApiResource(SeededWithoutSlash));

        var found = await CollectAsync(_sut.FindByNamesAsync([SeededWithSlash], ct), ct);

        found.Should().ContainSingle();
    }

    [Fact]
    public async Task FindByNamesAsync_DisabledResource_IsNotReturned()
    {
        var ct = TestContext.Current.CancellationToken;
        StoredResources(ApiResource(SeededWithSlash, enabled: false));

        var found = await CollectAsync(_sut.FindByNamesAsync([SeededWithSlash], ct), ct);

        found.Should().BeEmpty("a disabled API resource must not be requestable");
    }

    [Fact]
    public async Task FindByNamesAsync_QueriesBothSlashVariants_InOneRoundTrip()
    {
        var ct = TestContext.Current.CancellationToken;
        StoredResources();

        await CollectAsync(_sut.FindByNamesAsync([SeededWithoutSlash], ct), ct);

        var queried = _resourceStore.ReceivedCalls()
            .Single(call => call.GetMethodInfo().Name == nameof(IOctoResourceStore.FindRtApiResourcesByNameAsync));
        var names = ((IEnumerable<string>)queried.GetArguments()[0]!).ToList();
        names.Should().BeEquivalentTo(new[] { SeededWithoutSlash, SeededWithSlash });
    }

    [Fact]
    public async Task FindByNamesAsync_MultipleIndicators_QueriesOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        StoredResources(ApiResource(SeededWithSlash), ApiResource("https://other.example/api"));

        var found = await CollectAsync(
            _sut.FindByNamesAsync([SeededWithoutSlash, "https://other.example/api"], ct), ct);

        found.Should().HaveCount(2);
        await _resourceStore.Received(1).FindRtApiResourcesByNameAsync(Arg.Any<IEnumerable<string>>());
    }

    [Fact]
    public async Task FindByNamesAsync_NoUsableNames_DoesNotQuery()
    {
        var ct = TestContext.Current.CancellationToken;

        var found = await CollectAsync(_sut.FindByNamesAsync([string.Empty], ct), ct);

        found.Should().BeEmpty();
        await _resourceStore.DidNotReceive().FindRtApiResourcesByNameAsync(Arg.Any<IEnumerable<string>>());
    }

    [Fact]
    public async Task FindByNameAsync_UnknownResource_ReturnsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        StoredResources();

        var found = await _sut.FindByNameAsync("https://unknown.example/", ct);

        found.Should().BeNull();
    }

    [Fact]
    public async Task GetNameAsync_ReturnsStoredSpelling()
    {
        var ct = TestContext.Current.CancellationToken;

        var name = await _sut.GetNameAsync(ApiResource(SeededWithSlash), ct);

        name.Should().Be(SeededWithSlash, "the handler matches the requested value against what is stored");
    }

    private static async Task<List<RtApiResource>> CollectAsync(
        IAsyncEnumerable<RtApiResource> source, CancellationToken cancellationToken)
    {
        var items = new List<RtApiResource>();
        await foreach (var item in source.WithCancellation(cancellationToken))
        {
            items.Add(item);
        }

        return items;
    }

    private void StoredResources(params RtApiResource[] resources)
        => _resourceStore.FindRtApiResourcesByNameAsync(Arg.Any<IEnumerable<string>>())
            .Returns(call =>
            {
                var requested = ((IEnumerable<string>)call[0]).ToHashSet(StringComparer.Ordinal);
                return Task.FromResult<IEnumerable<RtApiResource>>(
                    resources.Where(resource => requested.Contains(resource.Name)).ToList());
            });

    private static RtApiResource ApiResource(string name, bool enabled = true) => new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        Name = name,
        DisplayName = name,
        Enabled = enabled,
        ShowInDiscoveryDocument = true,
        Claims = new AttributeStringValueList(),
        Scopes = new AttributeStringValueList { "octo_api" }
    };
}

/// <summary>AB#5193: trailing-slash tolerance used by the store and by the server handlers.</summary>
public class ResourceIdentifiersTests
{
    [Theory]
    [InlineData("https://host/mcp", "https://host/mcp")]
    [InlineData("https://host/mcp/", "https://host/mcp")]
    [InlineData("https://host/mcp//", "https://host/mcp")]
    // Only the PATH slash is insignificant: one inside a query or fragment is part of the value,
    // and a path slash sitting BEFORE a query still has to be stripped.
    [InlineData("https://host/mcp?tenant=prod/", "https://host/mcp?tenant=prod/")]
    [InlineData("https://host/mcp/?tenant=prod", "https://host/mcp?tenant=prod")]
    [InlineData("https://host/mcp/#frag/", "https://host/mcp#frag/")]
    public void Normalize_StripsTrailingPathSlashes_ButLeavesQueryAndFragmentAlone(
        string value, string expected)
        => ResourceIdentifiers.Normalize(value).Should().Be(expected);

    [Fact]
    public void Comparer_IgnoresTrailingSlash_ButNothingElse()
    {
        ResourceIdentifiers.Comparer.Equals("https://host/mcp", "https://host/mcp/").Should().BeTrue();
        ResourceIdentifiers.Comparer.Equals("https://host/mcp/?t=1", "https://host/mcp?t=1").Should().BeTrue();
        ResourceIdentifiers.Comparer.Equals("https://host/mcp", "https://host/MCP").Should().BeFalse();
        ResourceIdentifiers.Comparer.Equals("https://host/mcp", "https://host:443/mcp").Should().BeFalse();
        ResourceIdentifiers.Comparer.Equals("https://host/mcp?t=prod/", "https://host/mcp?t=prod")
            .Should().BeFalse("a slash inside the query distinguishes two resources");
    }

    [Fact]
    public void Variants_CoverBothSpellings_AndTheVerbatimValue()
    {
        ResourceIdentifiers.Variants("https://host/mcp")
            .Should().BeEquivalentTo(new[] { "https://host/mcp", "https://host/mcp/" });

        ResourceIdentifiers.Variants("https://host/mcp//")
            .Should().BeEquivalentTo(new[] { "https://host/mcp", "https://host/mcp/", "https://host/mcp//" });

        // The slash belongs at the end of the path, not of the string.
        ResourceIdentifiers.Variants("https://host/mcp?t=1")
            .Should().BeEquivalentTo(new[] { "https://host/mcp?t=1", "https://host/mcp/?t=1" });
    }
}
