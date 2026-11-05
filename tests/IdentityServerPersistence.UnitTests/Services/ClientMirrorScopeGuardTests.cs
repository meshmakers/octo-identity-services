using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#6758: the service itself refuses to create, rotate or remove a mirror in a tenant outside the parent's
///     subtree — independent of the controller filter, so no other caller can bypass the check. The system tenant as
///     parent reaches every tenant (tenant creation, dynamic client registration).
/// </summary>
public class ClientMirrorScopeGuardTests
{
    private const string SystemTenant = "octosystem";
    private const string Parent = "a";

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly ITenantDiscoveryService _discovery = Substitute.For<ITenantDiscoveryService>();
    private readonly ClientMirrorProvisioningService _sut;

    public ClientMirrorScopeGuardTests()
    {
        _systemContext.TenantId.Returns(SystemTenant);
        _systemContext.TryFindTenantRepositoryAsync(Arg.Any<string>())
            .Returns(Task.FromResult<ITenantRepository?>(null));
        _discovery.GetScopeDescendantsAsync(Parent)
            .Returns(new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "a-child", "a-grandchild" });
        _sut = new ClientMirrorProvisioningService(NullLogger<ClientMirrorProvisioningService>.Instance,
            _systemContext, _discovery);
    }

    private static readonly string[] Outside = ["s", "s-child", "u", SystemTenant, "does-not-exist"];

    public static TheoryData<string> OutsideTenants => new(Outside);

    [Theory]
    [MemberData(nameof(OutsideTenants))]
    public async Task OutsideTheSubtree_EveryEntryPoint_IsRefused_BeforeAnyTenantIsTouched(string child)
    {
        var calls = new Func<Task>[]
        {
            () => _sut.ProvisionForChildTenantAsync(Parent, child),
            () => _sut.ProvisionInTenantAsync(Parent, "ci", child),
            () => _sut.RotateMirrorSecretAsync(Parent, "ci", child),
            () => _sut.RemoveMirrorAsync(Parent, "ci", child)
        };

        foreach (var call in calls)
        {
            await call.Should().ThrowAsync<ClientMirrorScopeException>();
        }

        _ = _systemContext.DidNotReceive().TryFindTenantRepositoryAsync(Arg.Any<string>());
    }

    [Theory]
    [InlineData("a-child")]
    [InlineData("A-GrandChild")]
    public async Task InsideTheSubtree_IsNotRefused(string child)
    {
        // The unknown tenant repository yields the normal "nothing to do" answers, not a scope error.
        (await _sut.ProvisionInTenantAsync(Parent, "ci", child)).NewlyProvisioned.Should().Be(0);
        (await _sut.RotateMirrorSecretAsync(Parent, "ci", child)).Should().BeNull();
        (await _sut.RemoveMirrorAsync(Parent, "ci", child)).Should().BeFalse();
    }

    [Theory]
    [InlineData("s")]
    [InlineData("does-not-exist")]
    public async Task SystemParent_ReachesEveryTenant(string child)
    {
        (await _sut.ProvisionInTenantAsync(SystemTenant, "ci", child)).NewlyProvisioned.Should().Be(0);
        (await _sut.RotateMirrorSecretAsync(SystemTenant, "ci", child)).Should().BeNull();
        (await _sut.RemoveMirrorAsync(SystemTenant, "ci", child)).Should().BeFalse();
    }

    [Fact]
    public async Task UnregisteredParent_ReachesNothing()
    {
        _discovery.GetScopeDescendantsAsync("ghost").Returns((IReadOnlySet<string>?)null);

        await _sut.Invoking(s => s.ProvisionForChildTenantAsync("ghost", "a-child"))
            .Should().ThrowAsync<ClientMirrorScopeException>();
    }
}
