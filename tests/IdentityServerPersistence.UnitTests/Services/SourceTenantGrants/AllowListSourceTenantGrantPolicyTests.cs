using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.SourceTenantGrants;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SourceTenantGrants;

/// <summary>AB#8345 — the production grant policy: S permits T exactly when T is on S's allow-list; fails closed.</summary>
public class AllowListSourceTenantGrantPolicyTests
{
    private readonly ITenantRegistry _registry = Substitute.For<ITenantRegistry>();
    private readonly ICrossTenantGrantPermissionStore _store = Substitute.For<ICrossTenantGrantPermissionStore>();
    private readonly ITenantRepository _sourceRepository = Substitute.For<ITenantRepository>();
    private readonly ITenantRepository _targetRepository = Substitute.For<ITenantRepository>();

    public AllowListSourceTenantGrantPolicyTests()
    {
        // Unknown tenants: no repository (NSubstitute would otherwise hand out an auto-substitute).
        _registry.TryGetRepositoryAsync(Arg.Any<string>()).Returns((ITenantRepository?)null);
        _registry.TryGetRepositoryAsync("s").Returns(_sourceRepository);
        _registry.TryGetRepositoryAsync("t").Returns(_targetRepository);
        _store.GetAsync(_targetRepository).Returns(new CrossTenantGrantPermissions { TargetTenantIds = ["s"] });
    }

    private AllowListSourceTenantGrantPolicy Policy()
        => new(_registry, _store, NullLogger<AllowListSourceTenantGrantPolicy>.Instance);

    private void SourcePermits(params string[] targets)
        => _store.GetAsync(_sourceRepository).Returns(new CrossTenantGrantPermissions { TargetTenantIds = [.. targets] });

    [Fact]
    public async Task ListedTarget_IsPermitted_CaseInsensitively()
    {
        SourcePermits("a", "t");

        (await Policy().IsPermittedAsync("s", "t", TestContext.Current.CancellationToken)).Should().BeTrue();
        (await Policy().IsPermittedAsync("s", " T ", TestContext.Current.CancellationToken)).Should().BeTrue();
    }

    [Fact]
    public async Task EmptyList_TheDefaultOfEveryTenant_PermitsNobody()
    {
        _store.GetAsync(_sourceRepository).Returns(new CrossTenantGrantPermissions());

        (await Policy().IsPermittedAsync("s", "t", TestContext.Current.CancellationToken)).Should().BeFalse();
    }

    [Fact]
    public async Task UnlistedTarget_IsNotPermitted()
    {
        SourcePermits("a", "b");

        (await Policy().IsPermittedAsync("s", "t", TestContext.Current.CancellationToken)).Should().BeFalse();
    }

    [Fact]
    public async Task ThePermissionIsDirectional_TargetsListDoesNotPermitTheSource()
    {
        // T lists S; that permits S to look up T's users, never T to look up S's.
        SourcePermits();

        (await Policy().IsPermittedAsync("s", "t", TestContext.Current.CancellationToken)).Should().BeFalse();
    }

    [Fact]
    public async Task UnknownSource_IsNotPermitted_AndCostsTheSameRead_AgainstTheTarget()
    {
        (await Policy().IsPermittedAsync("absent", "t", TestContext.Current.CancellationToken)).Should().BeFalse(
            "T's own list names 's', which must not leak into a decision about an unknown source");

        await _store.Received(1).GetAsync(_targetRepository);
    }

    [Fact]
    public async Task UnknownSourceAndTarget_IsNotPermitted()
    {
        (await Policy().IsPermittedAsync("absent", "nowhere", TestContext.Current.CancellationToken)).Should().BeFalse();
    }

    [Theory]
    [InlineData("", "t")]
    [InlineData("s", "")]
    [InlineData("  ", "t")]
    public async Task EmptyIds_AreNotPermitted(string source, string target)
    {
        SourcePermits("t");

        (await Policy().IsPermittedAsync(source, target, TestContext.Current.CancellationToken)).Should().BeFalse();
    }

    [Fact]
    public async Task UnreadableList_FailsClosed_WithoutThrowing()
    {
        _store.GetAsync(_sourceRepository).ThrowsAsync(new InvalidOperationException("broken row"));

        (await Policy().IsPermittedAsync("s", "t", TestContext.Current.CancellationToken)).Should().BeFalse();
    }

    [Fact]
    public async Task UnreadableRegistry_FailsClosed_WithoutThrowing()
    {
        _registry.TryGetRepositoryAsync("s").ThrowsAsync(new InvalidOperationException("registry down"));

        (await Policy().IsPermittedAsync("s", "t", TestContext.Current.CancellationToken)).Should().BeFalse();
    }

    [Fact]
    public async Task SourceListingItself_DoesNotCount()
    {
        SourcePermits("s");

        (await Policy().IsPermittedAsync("s", "s", TestContext.Current.CancellationToken)).Should().BeFalse();
    }
}

/// <summary>AB#8345 — normalization and validation of a submitted allow-list.</summary>
public class CrossTenantGrantPermissionListTests
{
    [Fact]
    public void Normalize_TrimsLowerCasesDeduplicatesAndSorts()
        => CrossTenantGrantPermissionList.Normalize([" Customer-B", "customer-a", "CUSTOMER-B", "", null])
            .Should().Equal("customer-a", "customer-b");

    [Fact]
    public void Validate_EmptyList_IsValid()
        => CrossTenantGrantPermissionList.Validate("s", []).Should().BeEmpty();

    [Fact]
    public void Validate_Null_IsRefused()
        => CrossTenantGrantPermissionList.Validate("s", null).Should().ContainSingle()
            .Which.Should().Contain("required");

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Validate_EmptyEntry_IsRefused(string? entry)
        => CrossTenantGrantPermissionList.Validate("s", ["a", entry]).Should().NotBeEmpty();

    [Theory]
    [InlineData("a b")]
    [InlineData("a/b")]
    [InlineData("a.b")]
    [InlineData("{\"$ne\":null}")]
    [InlineData("ä")]
    public void Validate_InvalidTenantId_IsRefused_AndNamed(string entry)
        => CrossTenantGrantPermissionList.Validate("s", [entry]).Should().ContainSingle()
            .Which.Should().Contain(entry.ToLowerInvariant());

    [Fact]
    public void Validate_TooLongTenantId_IsRefused()
        => CrossTenantGrantPermissionList.Validate("s", [new string('a', 65)]).Should().NotBeEmpty();

    [Fact]
    public void Validate_LongestTenantId_IsValid()
        => CrossTenantGrantPermissionList.Validate("s", [new string('a', 64), "x_y-1"]).Should().BeEmpty();

    [Fact]
    public void Validate_OwnTenant_IsRefused_CaseInsensitively()
        => CrossTenantGrantPermissionList.Validate("Source", ["SOURCE"]).Should().ContainSingle()
            .Which.Should().Contain("itself");

    [Fact]
    public void Validate_MoreThanTheMaximum_IsRefused()
    {
        var entries = Enumerable.Range(0, CrossTenantGrantPermissionList.MaxEntries + 1).Select(i => $"t{i}").ToList();

        CrossTenantGrantPermissionList.Validate("s", entries).Should().ContainSingle()
            .Which.Should().Contain("at most");
        CrossTenantGrantPermissionList.Validate("s", entries.Take(CrossTenantGrantPermissionList.MaxEntries).ToList())
            .Should().BeEmpty();
    }
}
