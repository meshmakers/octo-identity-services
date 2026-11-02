using System.Collections.Immutable;
using FluentAssertions;
using IdentityServerPersistence.SystemStores.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using NSubstitute;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.OpenIddict;

/// <summary>
///     AB#5193: the decision behind the three resource-indicator handlers. Covers the statically
///     registered fast path without any tenant resource — the branch the HTTP integration tests
///     cannot reach, because <c>RegisterResources(...)</c> is a composition-time call.
/// </summary>
public class ResourceValidationHandlerTests
{
    private const string RootResource = "https://resource.example:5017";
    private const string RootResourceWithSlash = "https://resource.example:5017/";

    private readonly IOpenIddictResourceStore<RtApiResource> _store =
        Substitute.For<IOpenIddictResourceStore<RtApiResource>>();

    public ResourceValidationHandlerTests()
    {
        // No tenant resources at all — the static path has to carry these cases on its own.
        _store.FindByNamesAsync(Arg.Any<ImmutableArray<string>>(), Arg.Any<CancellationToken>())
            .Returns(Empty());
    }

    [Theory]
    [InlineData(RootResource)]
    [InlineData(RootResourceWithSlash)]
    public async Task StaticallyRegisteredResource_IsAccepted_InEitherSlashSpelling(string requested)
    {
        var ct = TestContext.Current.CancellationToken;

        // RegisterResources("https://resource.example:5017") stores a Uri, and Uri.AbsoluteUri
        // always renders a root identifier WITH a trailing slash — so an ordinal comparison here
        // would reject the very spelling the client was told to send.
        var options = OptionsWithResources(RootResource);

        var unknown = await OctoResourceValidationHandlers.FindUnknownResourcesAsync(
            _store, Request(requested), options, ct);

        unknown.Should().BeEmpty();
        _store.DidNotReceive().FindByNamesAsync(Arg.Any<ImmutableArray<string>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UnregisteredResource_FallsThroughToTheStore_AndIsRejected()
    {
        var ct = TestContext.Current.CancellationToken;

        var unknown = await OctoResourceValidationHandlers.FindUnknownResourcesAsync(
            _store, Request("https://other.example/api"), OptionsWithResources(RootResource), ct);

        unknown.Should().ContainSingle().Which.Should().Be("https://other.example/api");
        _store.Received(1).FindByNamesAsync(Arg.Any<ImmutableArray<string>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NoResourceParameter_PassesWithoutTouchingTheStore()
    {
        var ct = TestContext.Current.CancellationToken;

        var unknown = await OctoResourceValidationHandlers.FindUnknownResourcesAsync(
            _store, new OpenIddictRequest(), new OpenIddictServerOptions(), ct);

        unknown.Should().BeEmpty();
        _store.DidNotReceive().FindByNamesAsync(Arg.Any<ImmutableArray<string>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TenantResource_MustCarryOneOfTheRequestedScopes()
    {
        var ct = TestContext.Current.CancellationToken;
        const string resource = "https://tenant.example/api";

        _store.FindByNamesAsync(Arg.Any<ImmutableArray<string>>(), Arg.Any<CancellationToken>())
            .Returns(One(ApiResource(resource, "octo_api")));
        _store.GetNameAsync(Arg.Any<RtApiResource>(), Arg.Any<CancellationToken>())
            .Returns(call => new ValueTask<string?>(call.Arg<RtApiResource>().Name));

        var related = await OctoResourceValidationHandlers.FindUnknownResourcesAsync(
            _store, Request(resource, "openid octo_api"), new OpenIddictServerOptions(), ct);
        related.Should().BeEmpty();

        var unrelated = await OctoResourceValidationHandlers.FindUnknownResourcesAsync(
            _store, Request(resource, "openid"), new OpenIddictServerOptions(), ct);
        unrelated.Should().ContainSingle("the resource carries none of the requested scopes");

        var noScopeParameter = await OctoResourceValidationHandlers.FindUnknownResourcesAsync(
            _store, Request(resource), new OpenIddictServerOptions(), ct);
        noScopeParameter.Should().BeEmpty(
            "a refresh renewal sends no scope parameter — registration alone decides there");
    }

    /// <summary>
    ///     A resource created without scopes has no <c>Scopes</c> attribute at all — the property
    ///     is null. That must be a clean <c>invalid_target</c>, not a NullReferenceException and
    ///     an HTTP 500 on /connect/authorize.
    /// </summary>
    [Fact]
    public async Task ScopelessTenantResource_IsRejected_NotThrown()
    {
        var ct = TestContext.Current.CancellationToken;
        const string resource = "https://scopeless.example/api";

        var scopeless = ApiResource(resource);
        // The generated property is declared non-nullable, but the CK runtime leaves it null when
        // the entity carries no Scopes attribute — which is why the rest of the codebase writes
        // `apiResource.Scopes?.ToList() ?? []`. Reproduce that state deliberately.
        scopeless.Scopes = null!;

        _store.FindByNamesAsync(Arg.Any<ImmutableArray<string>>(), Arg.Any<CancellationToken>())
            .Returns(One(scopeless));
        _store.GetNameAsync(Arg.Any<RtApiResource>(), Arg.Any<CancellationToken>())
            .Returns(call => new ValueTask<string?>(call.Arg<RtApiResource>().Name));

        var unknown = await OctoResourceValidationHandlers.FindUnknownResourcesAsync(
            _store, Request(resource, "openid octo_api"), new OpenIddictServerOptions(), ct);

        unknown.Should().ContainSingle().Which.Should().Be(resource);
    }

    private static OpenIddictRequest Request(string resource, string? scope = null)
        => new() { Resources = ImmutableArray.Create<string?>(resource), Scope = scope };

    private static OpenIddictServerOptions OptionsWithResources(params string[] resources)
    {
        var options = new OpenIddictServerOptions();
        foreach (var resource in resources)
        {
            options.Resources.Add(new Uri(resource, UriKind.Absolute));
        }

        return options;
    }

    private static RtApiResource ApiResource(string name, params string[] scopes) => new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        Name = name,
        DisplayName = name,
        Enabled = true,
        ShowInDiscoveryDocument = true,
        Claims = new AttributeStringValueList(),
        Scopes = new AttributeStringValueList(scopes.ToList())
    };

#pragma warning disable CS1998 // async iterators without await are the shape IAsyncEnumerable needs here
    private static async IAsyncEnumerable<RtApiResource> Empty()
    {
        yield break;
    }

    private static async IAsyncEnumerable<RtApiResource> One(RtApiResource resource)
    {
        yield return resource;
    }
#pragma warning restore CS1998
}
