using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#5311: the discovery scope is the subtree strictly below one tenant, walked through the
///     tenants' own contexts (<see cref="ITenantContext.GetChildTenantsAsync" />) — direct and
///     indirect descendants, never the scope itself, never siblings or ancestors. Mirrors prod-1:
///     octosystem → {accounting → {meshmakers, salzburgdev, bernkopf → {tecob, gastroacker, bierok,
///     pureescape}}, energyiq}.
/// </summary>
public class TenantDiscoveryScopeTests
{
    private static readonly Dictionary<string, string[]> Hierarchy = new(StringComparer.OrdinalIgnoreCase)
    {
        ["octosystem"] = ["accounting", "energyiq"],
        ["accounting"] = ["meshmakers", "salzburgdev", "bernkopf"],
        ["bernkopf"] = ["tecob", "gastroacker", "bierok", "pureescape"],
        ["energyiq"] = [],
        ["meshmakers"] = [],
        ["salzburgdev"] = [],
        ["tecob"] = [],
        ["gastroacker"] = [],
        ["bierok"] = [],
        ["pureescape"] = []
    };

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly TenantDiscoveryService _sut;

    public TenantDiscoveryScopeTests()
    {
        _systemContext.TenantId.Returns("octosystem");
        foreach (var (tenantId, children) in Hierarchy)
        {
            // Build the substitute first: NSubstitute (NS4000) forbids configuring a substitute
            // inside a Returns() argument expression.
            var context = ContextWithChildren(tenantId, children);
            _systemContext.TryFindTenantContextAsync(tenantId).Returns(context);
        }

        _systemContext.TryFindTenantContextAsync(Arg.Is<string>(t => !Hierarchy.ContainsKey(t)))
            .Returns((ITenantContext?)null);

        _sut = new TenantDiscoveryService(_systemContext, Substitute.For<IAllowedTenantsResolver>(),
            NullLogger<TenantDiscoveryService>.Instance);
    }

    [Fact]
    public async Task ReturnsDirectAndIndirectDescendantsOnly()
    {
        var result = await _sut.GetScopeDescendantsAsync("accounting");

        result.Should().NotBeNull();
        result.Should().BeEquivalentTo("meshmakers", "salzburgdev", "bernkopf", "tecob", "gastroacker", "bierok",
            "pureescape");
        result.Should().NotContain("accounting", "the scope itself is never a destination");
        result.Should().NotContain("energyiq", "a sibling of the scope is outside the subtree");
        result.Should().NotContain("octosystem", "an ancestor of the scope is outside the subtree");
    }

    [Fact]
    public async Task ForAnIntermediateTenant_ReturnsItsSubtree()
    {
        var result = await _sut.GetScopeDescendantsAsync("bernkopf");

        result.Should().BeEquivalentTo("tecob", "gastroacker", "bierok", "pureescape");
    }

    [Fact]
    public async Task ForALeaf_ReturnsEmpty()
    {
        var result = await _sut.GetScopeDescendantsAsync("tecob");

        result.Should().NotBeNull();
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task ForTheSystemTenant_ReturnsEveryTenant()
    {
        var result = await _sut.GetScopeDescendantsAsync("octosystem");

        result.Should().HaveCount(Hierarchy.Count - 1);
        result.Should().NotContain("octosystem");
    }

    [Fact]
    public async Task ForUnknownScope_ReturnsNull()
    {
        (await _sut.GetScopeDescendantsAsync("nosuchtenant")).Should().BeNull();
        (await _sut.GetScopeDescendantsAsync("   ")).Should().BeNull();
    }

    [Fact]
    public async Task IsCaseInsensitiveOnMembership()
    {
        var result = await _sut.GetScopeDescendantsAsync("bernkopf");

        result!.Contains("TECOB").Should().BeTrue("the returned set compares case-insensitively");
    }

    [Fact]
    public async Task AChildWithoutContext_IsALeaf()
    {
        // A registry row whose tenant context cannot be resolved (half-created tenant) must not
        // abort the walk — it is offered as a leaf and not descended into.
        _systemContext.TryFindTenantContextAsync("tecob").Returns((ITenantContext?)null);

        var result = await _sut.GetScopeDescendantsAsync("bernkopf");

        result.Should().BeEquivalentTo("tecob", "gastroacker", "bierok", "pureescape");
    }

    [Fact]
    public async Task SurvivesACycleInTheRegistry()
    {
        var a = ContextWithChildren("a", ["b"]);
        var b = ContextWithChildren("b", ["a"]);
        _systemContext.TryFindTenantContextAsync("a").Returns(a);
        _systemContext.TryFindTenantContextAsync("b").Returns(b);

        var result = await _sut.GetScopeDescendantsAsync("a");

        result.Should().BeEquivalentTo("b");
    }

    [Fact]
    public async Task AFailingChildQuery_YieldsNull()
    {
        var broken = Substitute.For<ITenantContext>();
        broken.GetAdminSessionAsync().Returns(Task.FromException<IOctoAdminSession>(new InvalidOperationException("db down")));
        _systemContext.TryFindTenantContextAsync("accounting").Returns(broken);

        (await _sut.GetScopeDescendantsAsync("accounting")).Should().BeNull();
    }

    private static ITenantContext ContextWithChildren(string tenantId, string[] children)
    {
        var context = Substitute.For<ITenantContext>();
        context.TenantId.Returns(tenantId);
        var session = Substitute.For<IOctoAdminSession>();
        context.GetAdminSessionAsync().Returns(session);
        var result = Substitute.For<IResultSet<OctoTenant>>();
        result.Items.Returns(children.Select(c => new OctoTenant(c, "db-" + c, tenantId)).ToArray());
        context.GetChildTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>()).Returns(result);
        return context;
    }
}
