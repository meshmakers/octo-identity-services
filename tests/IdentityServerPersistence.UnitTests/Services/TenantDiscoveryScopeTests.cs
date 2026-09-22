using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#5311: the discovery scope is the registry subtree strictly below one tenant — direct and
///     indirect descendants, never the scope itself, never siblings or ancestors. Mirrors the
///     prod-1 accounting hierarchy: octosystem → accounting → {meshmakers, salzburgdev, bernkopf →
///     {tecob, gastroacker, bierok, pureescape}}, with energyiq as an unrelated sibling of accounting.
/// </summary>
public class TenantDiscoveryScopeTests
{
    private const string SystemTenant = "octosystem";

    private static readonly OctoTenant[] Registry =
    [
        new("accounting", "db-accounting", SystemTenant),
        new("energyiq", "db-energyiq", SystemTenant),
        new("meshmakers", "db-meshmakers", "accounting"),
        new("salzburgdev", "db-salzburgdev", "accounting"),
        new("bernkopf", "db-bernkopf", "accounting"),
        new("tecob", "db-tecob", "bernkopf"),
        new("gastroacker", "db-gastroacker", "bernkopf"),
        new("bierok", "db-bierok", "bernkopf"),
        new("pureescape", "db-pureescape", "bernkopf")
    ];

    [Fact]
    public void CollectDescendants_ReturnsDirectAndIndirectDescendantsOnly()
    {
        var result = TenantDiscoveryService.CollectDescendants(Registry, SystemTenant, "accounting");

        result.Should().NotBeNull();
        result.Should().BeEquivalentTo("meshmakers", "salzburgdev", "bernkopf", "tecob", "gastroacker", "bierok",
            "pureescape");
        result.Should().NotContain("accounting", "the scope itself is never a destination");
        result.Should().NotContain("energyiq", "a sibling of the scope is outside the subtree");
        result.Should().NotContain(SystemTenant, "an ancestor of the scope is outside the subtree");
    }

    [Fact]
    public void CollectDescendants_ForAnIntermediateTenant_ReturnsItsSubtree()
    {
        var result = TenantDiscoveryService.CollectDescendants(Registry, SystemTenant, "bernkopf");

        result.Should().BeEquivalentTo("tecob", "gastroacker", "bierok", "pureescape");
    }

    [Fact]
    public void CollectDescendants_ForALeaf_ReturnsEmpty()
    {
        var result = TenantDiscoveryService.CollectDescendants(Registry, SystemTenant, "tecob");

        result.Should().NotBeNull();
        result.Should().BeEmpty();
    }

    [Fact]
    public void CollectDescendants_ForUnknownScope_ReturnsNull()
    {
        TenantDiscoveryService.CollectDescendants(Registry, SystemTenant, "nosuchtenant").Should().BeNull();
    }

    [Fact]
    public void CollectDescendants_ForTheSystemTenant_ReturnsEveryTenant()
    {
        var result = TenantDiscoveryService.CollectDescendants(Registry, SystemTenant, SystemTenant);

        result.Should().HaveCount(Registry.Length);
        result.Should().NotContain(SystemTenant);
    }

    [Fact]
    public void CollectDescendants_TreatsMissingParentAsChildOfTheSystemTenant()
    {
        // Registry records written before the parent id existed (AB#5151) carry no parent.
        OctoTenant[] legacy = [new("legacy", "db-legacy"), new("child", "db-child", "legacy")];

        TenantDiscoveryService.CollectDescendants(legacy, SystemTenant, SystemTenant)
            .Should().BeEquivalentTo("legacy", "child");
        TenantDiscoveryService.CollectDescendants(legacy, SystemTenant, "legacy")
            .Should().BeEquivalentTo("child");
    }

    [Fact]
    public void CollectDescendants_IsCaseInsensitiveAndKeepsRegistrySpelling()
    {
        var result = TenantDiscoveryService.CollectDescendants(Registry, SystemTenant, "Bernkopf");

        result.Should().BeEquivalentTo("tecob", "gastroacker", "bierok", "pureescape");
        result!.Contains("TECOB").Should().BeTrue("the returned set compares case-insensitively");
    }

    [Fact]
    public void CollectDescendants_SurvivesACycleInTheRegistry()
    {
        OctoTenant[] cyclic = [new("a", "db-a", "b"), new("b", "db-b", "a")];

        var result = TenantDiscoveryService.CollectDescendants(cyclic, SystemTenant, "a");

        result.Should().BeEquivalentTo("b");
    }
}
