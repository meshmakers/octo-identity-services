using Shared.TestUtilities.Fakes;
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

    // The system registry (AB#6759): every child row a context lists is registered under that parent unless a test
    // says otherwise. Read lazily, so rows added inside a test count.
    private readonly List<OctoTenant> _registry = [];
    private readonly TenantDiscoveryService _sut;

    public TenantDiscoveryScopeTests()
    {
        _systemContext.TenantId.Returns("octosystem");
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>())
            .Returns(_ =>
            {
                var all = Substitute.For<IResultSet<OctoTenant>>();
                all.Items.Returns(_registry.ToArray());
                return all;
            });
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
            new PassThroughTenantProbeGuard(), NullLogger<TenantDiscoveryService>.Instance);
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
    public async Task AStaleChildRow_OfADeletedTenant_IsNotADescendant()
    {
        // AB#6759: 'ghost' was deleted from the system tenant; its row stayed in bernkopf's own registry.
        var bernkopf = ContextWithChildren("bernkopf", ["tecob", "ghost"]);
        _systemContext.TryFindTenantContextAsync("bernkopf").Returns(bernkopf);
        _registry.RemoveAll(t => t.TenantId == "ghost");

        var result = await _sut.GetScopeDescendantsAsync("accounting");

        result.Should().NotContain("ghost", "a tenant that no longer exists is nobody's descendant");
        result.Should().Contain("tecob");
    }

    [Fact]
    public async Task AStaleChildRow_WhoseNameWasReusedUnderAnotherParent_GrantsNothing()
    {
        // AB#6759: 'reused' was deleted below bernkopf (row stayed) and re-created by somebody else below energyiq,
        // with its own child. The scope 'accounting' must not reach the new tenant nor anything below it.
        var bernkopf = ContextWithChildren("bernkopf", ["tecob", "reused"]);
        _systemContext.TryFindTenantContextAsync("bernkopf").Returns(bernkopf);
        var energyiq = ContextWithChildren("energyiq", ["reused"]);
        _systemContext.TryFindTenantContextAsync("energyiq").Returns(energyiq);
        var reused = ContextWithChildren("reused", ["reused-child"]);
        _systemContext.TryFindTenantContextAsync("reused").Returns(reused);

        var accounting = await _sut.GetScopeDescendantsAsync("accounting");
        var owner = await _sut.GetScopeDescendantsAsync("energyiq");

        accounting.Should().NotContain(["reused", "reused-child"],
            "the registry names energyiq as the parent, the stale row below bernkopf grants nothing");
        owner.Should().BeEquivalentTo("reused", "reused-child");
    }

    [Fact]
    public async Task AChildRow_PointingToAnotherDatabase_IsNotADescendant()
    {
        // Same id and parent, but the registered tenant lives in a different database: the row is a leftover of an
        // earlier tenant of that name, not the registered one.
        Register("tecob", "bernkopf", "db-tecob-new");

        var result = await _sut.GetScopeDescendantsAsync("bernkopf");

        result.Should().BeEquivalentTo("gastroacker", "bierok", "pureescape");
    }

    [Fact]
    public async Task ALegacyRegistryRowWithoutParent_StillCounts()
    {
        // Rows written before ParentTenantId existed carry no parent; the database still has to match.
        Register("tecob", null);

        var result = await _sut.GetScopeDescendantsAsync("bernkopf");

        result.Should().Contain("tecob");
    }

    [Fact]
    public async Task AnUnreadableRegistry_YieldsNull()
    {
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>())
            .Returns(Task.FromException<IResultSet<OctoTenant>>(new InvalidOperationException("db down")));

        (await _sut.GetScopeDescendantsAsync("accounting")).Should().BeNull(
            "without the registry the walk cannot tell live children from stale rows");
    }

    [Fact]
    public async Task AFailingChildQuery_YieldsNull()
    {
        var broken = Substitute.For<ITenantContext>();
        broken.GetAdminSessionAsync().Returns(Task.FromException<IOctoAdminSession>(new InvalidOperationException("db down")));
        _systemContext.TryFindTenantContextAsync("accounting").Returns(broken);

        (await _sut.GetScopeDescendantsAsync("accounting")).Should().BeNull();
    }

    private ITenantContext ContextWithChildren(string tenantId, string[] children, bool register = true)
    {
        if (register)
        {
            foreach (var child in children)
            {
                Register(child, tenantId);
            }
        }

        var context = Substitute.For<ITenantContext>();
        context.TenantId.Returns(tenantId);
        var session = Substitute.For<IOctoAdminSession>();
        context.GetAdminSessionAsync().Returns(session);
        var result = Substitute.For<IResultSet<OctoTenant>>();
        result.Items.Returns(children.Select(c => new OctoTenant(c, "db-" + c, tenantId)).ToArray());
        context.GetChildTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>()).Returns(result);
        return context;
    }

    private void Register(string tenantId, string? parentTenantId, string? databaseName = null)
    {
        _registry.RemoveAll(t => string.Equals(t.TenantId, tenantId, StringComparison.OrdinalIgnoreCase));
        _registry.Add(new OctoTenant(tenantId, databaseName ?? "db-" + tenantId, parentTenantId));
    }
}
