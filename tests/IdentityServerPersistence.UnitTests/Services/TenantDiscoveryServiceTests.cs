using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#5311 (review finding): the public discovery path, not only the subtree walk. A user whose
///     home is the grouping tenant <c>bernkopf</c> and whose allowed tenants reach outside the
///     accounting subtree (an unrelated <c>energyiq</c> mapping, the system tenant) must be offered
///     only the tenants below the scope; an unknown scope must yield nothing, not the unscoped list.
/// </summary>
public class TenantDiscoveryServiceTests
{
    private const string SystemTenant = "octosystem";

    private static readonly OctoTenant[] Registry =
    [
        new("accounting", "db-accounting", SystemTenant),
        new("energyiq", "db-energyiq", SystemTenant),
        new("bernkopf", "db-bernkopf", "accounting"),
        new("tecob", "db-tecob", "bernkopf"),
        new("bierok", "db-bierok", "bernkopf")
    ];

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly IAllowedTenantsResolver _resolver = Substitute.For<IAllowedTenantsResolver>();
    private readonly RtUser _klaus = new RtUserBuilder().WithUserName("kbernkopf").WithEmail("kbernkopf@tecob.at").Build();
    private readonly TenantDiscoveryService _sut;

    public TenantDiscoveryServiceTests()
    {
        _systemContext.TenantId.Returns(SystemTenant);
        _systemContext.GetAdminSessionAsync().Returns(Substitute.For<IOctoAdminSession>());
        var registry = Substitute.For<IResultSet<OctoTenant>>();
        registry.Items.Returns(Registry);
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>())
            .Returns(registry);

        SetupTenant(SystemTenant, null);
        foreach (var tenant in Registry)
        {
            SetupTenant(tenant.TenantId, tenant.TenantId == "bernkopf" ? _klaus : null);
        }

        _resolver.ResolveAsync("bernkopf", _klaus)
            .Returns(new List<string> { "bernkopf", "tecob", "bierok", "energyiq", SystemTenant });

        _sut = new TenantDiscoveryService(_systemContext, _resolver, NullLogger<TenantDiscoveryService>.Instance);
    }

    [Fact]
    public async Task WithoutScope_ReturnsEveryAllowedTenant()
    {
        var result = await _sut.FindTenantsForUserAsync("kbernkopf@tecob.at");

        result.Should().BeEquivalentTo("bernkopf", "tecob", "bierok", "energyiq", SystemTenant);
    }

    [Fact]
    public async Task WithScope_ReturnsOnlyTheTenantsBelowIt()
    {
        var result = await _sut.FindTenantsForUserAsync("kbernkopf@tecob.at", "accounting");

        result.Should().BeEquivalentTo("bernkopf", "tecob", "bierok");
        result.Should().NotContain("energyiq", "an allowed tenant outside the subtree is not offered");
        result.Should().NotContain(SystemTenant, "an ancestor of the scope is not offered");
        result.Should().NotContain("accounting", "the scope itself is never offered");
    }

    [Fact]
    public async Task WithScope_TheHomeSearchStaysGlobal()
    {
        // The user lives above/beside the subtree in the registry order — the scope must not
        // restrict WHERE the user is looked for, only what is returned.
        await _sut.FindTenantsForUserAsync("kbernkopf@tecob.at", "bernkopf");

        await _systemContext.Received().FindTenantRepositoryAsync("energyiq");
        await _systemContext.Received().FindTenantRepositoryAsync("bernkopf");
    }

    [Fact]
    public async Task WithUnknownScope_ReturnsNothing()
    {
        var result = await _sut.FindTenantsForUserAsync("kbernkopf@tecob.at", "nosuchtenant");

        result.Should().BeEmpty();
        await _resolver.DidNotReceiveWithAnyArgs().ResolveAsync(default!, default!);
    }

    private void SetupTenant(string tenantId, RtUser? user)
    {
        var repository = Substitute.For<ITenantRepository>();
        var session = Substitute.For<IOctoSession>();
        repository.TenantId.Returns(tenantId);
        repository.GetSessionAsync().Returns(session);
        var users = Substitute.For<IResultSet<RtUser>>();
        users.Items.Returns(user == null ? Array.Empty<RtUser>() : new[] { user });
        repository.GetRtEntitiesByTypeAsync<RtUser>(session, Arg.Any<RtEntityQueryOptions>()).Returns(users);
        _systemContext.FindTenantRepositoryAsync(tenantId).Returns(repository);
    }
}
