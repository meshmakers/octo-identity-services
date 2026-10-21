using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#7044: the tenant-topology answer is (the caller's allowed tenants) ∩ (strict descendants of the
///     scope), each with depth and hasChildren, and nothing else. Hierarchy (a 3-level tree with a sibling
///     subtree, like prod-1):
///     octosystem → {accounting → {meshmakers, salzburgdev, bernkopf → {tecob, gastroacker}}, energyiq → {ec-a}}.
/// </summary>
public class TenantTopologyServiceTests
{
    private static readonly Dictionary<string, string[]> Hierarchy = new(StringComparer.OrdinalIgnoreCase)
    {
        ["octosystem"] = ["accounting", "energyiq"],
        ["accounting"] = ["meshmakers", "salzburgdev", "bernkopf"],
        ["bernkopf"] = ["tecob", "gastroacker"],
        ["energyiq"] = ["ec-a"],
        ["meshmakers"] = [],
        ["salzburgdev"] = [],
        ["tecob"] = [],
        ["gastroacker"] = [],
        ["ec-a"] = []
    };

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly Dictionary<string, ITenantContext> _contexts = new(StringComparer.OrdinalIgnoreCase);
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());
    private readonly TenantTopologyService _sut;

    public TenantTopologyServiceTests()
    {
        _systemContext.TenantId.Returns("octosystem");
        foreach (var (tenantId, children) in Hierarchy)
        {
            _contexts[tenantId] = ContextWithChildren(tenantId, children);
        }

        // Like the real system context, the lookup normalizes the id (case-insensitive).
        _systemContext.TryFindTenantContextAsync(Arg.Any<string>())
            .Returns(call => _contexts.TryGetValue(call.Arg<string>(), out var context) ? context : null);

        _sut = Create();
    }

    private TenantTopologyService Create(int maxNodes = 5000) => new(_systemContext, _cache,
        Options.Create(new OctoIdentityServicesOptions { TenantTopology = { MaxNodes = maxNodes } }),
        NullLogger<TenantTopologyService>.Instance);

    [Fact]
    public async Task ReturnsOnlyClaimedStrictDescendants_WithDepthAndHasChildren()
    {
        var result = await _sut.GetTopologyAsync("accounting",
            ["meshmakers", "bernkopf", "tecob", "accounting", "energyiq", "ec-a", "octosystem"]);

        result.Scope.Should().Be("accounting");
        result.Tenants.Should().BeEquivalentTo(new[]
        {
            new TenantTopologyEntry("meshmakers", 1, false),
            new TenantTopologyEntry("bernkopf", 1, true),
            new TenantTopologyEntry("tecob", 2, false)
        });
        result.Tenants.Select(t => t.TenantId).Should().NotContain(["accounting", "energyiq", "ec-a", "octosystem"],
            "the scope itself, a sibling subtree and ancestors are never listed");
    }

    [Fact]
    public async Task TenantInSubtreeButNotInClaim_IsNeverListed_AndItsChildrenAreNotRevealed()
    {
        var result = await _sut.GetTopologyAsync("accounting", ["meshmakers"]);

        result.Tenants.Should().BeEquivalentTo(new[] { new TenantTopologyEntry("meshmakers", 1, false) });
        result.Tenants.Select(t => t.TenantId).Should().NotContain(["bernkopf", "tecob", "gastroacker"]);
    }

    [Fact]
    public async Task ClaimedTenantOutsideTheSubtree_IsNeverListed()
    {
        var result = await _sut.GetTopologyAsync("accounting", ["energyiq", "ec-a"]);

        result.Tenants.Should().BeEmpty();
    }

    [Fact]
    public async Task ClaimMatchingIsCaseInsensitive_AndReturnsTheRegistryId()
    {
        var result = await _sut.GetTopologyAsync("ACCOUNTING", ["MeshMakers", "TECOB"]);

        result.Tenants.Select(t => t.TenantId).Should().BeEquivalentTo("meshmakers", "tecob");
    }

    [Fact]
    public async Task ScopeHasChildren_IsTrue_WhenTheEntitledListIsNotEmpty()
    {
        (await _sut.GetTopologyAsync("accounting", ["tecob"])).ScopeHasChildren.Should().BeTrue();
    }

    [Fact]
    public async Task ScopeHasChildren_IsTrue_WhenTheScopeItselfIsInTheClaim()
    {
        var result = await _sut.GetTopologyAsync("accounting", ["accounting"]);

        result.ScopeHasChildren.Should().BeTrue();
        result.Tenants.Should().BeEmpty();
    }

    [Fact]
    public async Task ScopeHasChildren_IsFalse_ForAScopeWithChildrenTheCallerHasNothingToDoWith()
    {
        // No oracle: a caller with no relation to the scope learns nothing about its children.
        var result = await _sut.GetTopologyAsync("accounting", ["energyiq"]);

        result.ScopeHasChildren.Should().BeFalse();
        result.Tenants.Should().BeEmpty();
    }

    [Fact]
    public async Task LegacySingleTenantDeployment_ScopeInClaimWithoutChildren_IsEmptyAndNoChildren()
    {
        var result = await _sut.GetTopologyAsync("meshmakers", ["meshmakers"]);

        result.ScopeHasChildren.Should().BeFalse();
        result.Tenants.Should().BeEmpty();
    }

    [Fact]
    public async Task UnknownScope_ScopeWithoutEntitledDescendants_AndForeignScope_AreIndistinguishable()
    {
        var unknown = await _sut.GetTopologyAsync("nosuchtenant", ["meshmakers"]);
        var noEntitled = await _sut.GetTopologyAsync("bernkopf", ["meshmakers"]);
        var foreign = await _sut.GetTopologyAsync("energyiq", ["meshmakers"]);

        foreach (var result in new[] { unknown, noEntitled, foreign })
        {
            result.ScopeHasChildren.Should().BeFalse();
            result.Tenants.Should().BeEmpty();
        }
    }

    [Fact]
    public async Task AFailingHierarchyRead_FailsClosed()
    {
        var broken = Substitute.For<ITenantContext>();
        broken.GetAdminSessionAsync().Returns(
            Task.FromException<IOctoAdminSession>(new InvalidOperationException("db down")));
        _systemContext.TryFindTenantContextAsync("bernkopf").Returns(broken);

        var act = () => _sut.GetTopologyAsync("accounting", ["meshmakers", "tecob"]);

        await act.Should().ThrowAsync<TenantHierarchyUnreadableException>(
            "a partial list would let an app decide on partial knowledge");
    }

    [Fact]
    public async Task ReachingTheNodeLimit_FailsClosed()
    {
        var sut = Create(maxNodes: 3);

        var act = () => sut.GetTopologyAsync("accounting", ["meshmakers"]);

        await act.Should().ThrowAsync<TenantHierarchyUnreadableException>();
    }

    [Fact]
    public async Task ACycleInTheRegistry_Terminates()
    {
        var a = ContextWithChildren("cyc-a", ["cyc-b"]);
        var b = ContextWithChildren("cyc-b", ["cyc-a"]);
        _systemContext.TryFindTenantContextAsync("cyc-a").Returns(a);
        _systemContext.TryFindTenantContextAsync("cyc-b").Returns(b);

        var result = await _sut.GetTopologyAsync("cyc-a", ["cyc-b"]);

        result.Tenants.Should().BeEquivalentTo(new[] { new TenantTopologyEntry("cyc-b", 1, true) });
    }

    [Fact]
    public async Task AChildWithoutContext_IsALeaf()
    {
        _systemContext.TryFindTenantContextAsync("tecob").Returns((ITenantContext?)null);

        var result = await _sut.GetTopologyAsync("bernkopf", ["tecob"]);

        result.Tenants.Should().BeEquivalentTo(new[] { new TenantTopologyEntry("tecob", 1, false) });
    }

    [Fact]
    public async Task HundredRequests_ReadTheRegistryOnce()
    {
        for (var i = 0; i < 100; i++)
        {
            await _sut.GetTopologyAsync("accounting", i % 2 == 0 ? ["tecob"] : ["meshmakers", "bernkopf"]);
        }

        await _systemContext.Received(1).TryFindTenantContextAsync("accounting");
        await _contexts["accounting"].Received(1).GetChildTenantsAsync(
            Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>());
    }

    [Fact]
    public async Task ConcurrentFirstRequests_ShareOneRead()
    {
        var gate = new TaskCompletionSource();
        var slow = ContextWithChildren("slow", ["slow-child"]);
        slow.GetAdminSessionAsync().Returns(async _ =>
        {
            await gate.Task;
            return Substitute.For<IOctoAdminSession>();
        });
        _systemContext.TryFindTenantContextAsync("slow").Returns(slow);

        var calls = Enumerable.Range(0, 20)
            .Select(_ => _sut.GetTopologyAsync("slow", ["slow-child"])).ToList();
        gate.SetResult();
        var results = await Task.WhenAll(calls);

        results.Should().OnlyContain(r => r.Tenants.Count == 1);
        await slow.Received(1).GetAdminSessionAsync();
    }

    [Fact]
    public async Task ASlowScope_DoesNotBlockOtherScopes_NorUnknownOnes()
    {
        var gate = new TaskCompletionSource();
        var slow = ContextWithChildren("slow", ["slow-child"]);
        slow.GetAdminSessionAsync().Returns(async _ =>
        {
            await gate.Task;
            return Substitute.For<IOctoAdminSession>();
        });
        _systemContext.TryFindTenantContextAsync("slow").Returns(slow);
        var stuck = _sut.GetTopologyAsync("slow", ["slow-child"]);

        // While "slow" hangs, a valid first request and unknown-scope spam complete.
        var other = _sut.GetTopologyAsync("accounting", ["tecob"]);
        var spam = Enumerable.Range(0, 20).Select(i => _sut.GetTopologyAsync($"unknown-{i}", ["tecob"])).ToList();
        var done = Task.WhenAll(spam.Append(other));
        (await Task.WhenAny(done, Task.Delay(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken))).Should().BeSameAs(done,
            "one hanging scope must not serialize first requests of other scopes");
        (await other).Tenants.Should().ContainSingle();
        stuck.IsCompleted.Should().BeFalse();

        gate.SetResult();
        (await stuck).Tenants.Should().ContainSingle();
    }

    [Fact]
    public async Task UnknownScopes_AreNeverCached_SoTheKeySpaceStaysBounded()
    {
        for (var i = 0; i < 50; i++)
        {
            await _sut.GetTopologyAsync($"unknown-{i}", ["meshmakers"]);
        }

        ((MemoryCache)_cache).Count.Should().Be(0);
    }

    [Fact]
    public async Task OnlyRegisteredScopesAreCached_OneEntryPerScope()
    {
        await _sut.GetTopologyAsync("accounting", ["tecob"]);
        await _sut.GetTopologyAsync("ACCOUNTING", ["tecob"]);
        await _sut.GetTopologyAsync("bernkopf", ["tecob"]);

        ((MemoryCache)_cache).Count.Should().Be(2);
    }

    [Fact]
    public async Task AFailedRead_IsNotCached_TheNextRequestRetries()
    {
        var failing = true;
        var flaky = Substitute.For<ITenantContext>();
        flaky.GetAdminSessionAsync().Returns(_ => failing
            ? Task.FromException<IOctoAdminSession>(new InvalidOperationException("db down"))
            : Task.FromResult(Substitute.For<IOctoAdminSession>()));
        var children = Substitute.For<IResultSet<OctoTenant>>();
        children.Items.Returns([new OctoTenant("flaky-child", "db", "flaky")]);
        flaky.GetChildTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>()).Returns(children);
        _systemContext.TryFindTenantContextAsync("flaky").Returns(flaky);

        var first = () => _sut.GetTopologyAsync("flaky", ["flaky-child"]);
        await first.Should().ThrowAsync<TenantHierarchyUnreadableException>();

        failing = false;
        var second = await _sut.GetTopologyAsync("flaky", ["flaky-child"]);
        second.Tenants.Should().HaveCount(1);
    }

    [Fact]
    public void TheCacheLivesAsLongAsTheTenantRegistry()
    {
        TenantTopologyService.CacheTtl.Should().Be(TenantRegistry.CacheTtl);
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
