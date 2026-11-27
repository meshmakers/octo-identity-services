using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.ServiceAccountExchange;
using IdentityServerPersistence.Services.SourceTenantGrants;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     A gate that cannot read its state (the tenant registry or a tenant database throws) answers
///     <see cref="ServiceAccountExchangeRefusal.StateUnreadable" />, which the token endpoint answers as an outage (HTTP
///     503), never as a refusal of the target.
/// </summary>
public class ServiceAccountExchangeGateStateUnreadableTests
{
    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly ITenantRegistry _tenantRegistry = Substitute.For<ITenantRegistry>();

    public ServiceAccountExchangeGateStateUnreadableTests()
    {
        _systemContext.TenantId.Returns("octosystem");
    }

    private ServiceAccountExchangeGate CreateGate() => new(_systemContext, _tenantRegistry,
        Substitute.For<ISourceTenantGrantPolicy>(), Substitute.For<IClientMirrorProvisioningService>(),
        Substitute.For<ICrossTenantShadowUserChainResolver>(), NullLogger<ServiceAccountExchangeGate>.Instance);

    [Fact]
    public async Task RegistryThatThrows_IsStateUnreadable_NotARefusalOfTheTarget()
    {
        _tenantRegistry.TryGetTenantAsync(Arg.Any<string>())
            .ThrowsAsync(new TimeoutException("registry database down"));

        var decision = await CreateGate().EvaluateAsync("a", "sa-client", "b");

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.StateUnreadable);
        decision.ShadowClient.Should().BeNull();
    }

    [Fact]
    public async Task SourceDatabaseThatThrows_IsStateUnreadable_NotARefusalOfTheTarget()
    {
        _tenantRegistry.TryGetTenantAsync("a").Returns(new OctoTenant("a", "db_a", "g"));
        _tenantRegistry.TryGetTenantAsync("b").Returns(new OctoTenant("b", "db_b", "g"));
        _tenantRegistry.TryGetRepositoryAsync(Arg.Any<string>())
            .ThrowsAsync(new TimeoutException("tenant database down"));

        var decision = await CreateGate().EvaluateAsync("a", "sa-client", "b");

        decision.Refusal.Should().Be(ServiceAccountExchangeRefusal.StateUnreadable);
        decision.ShadowClient.Should().BeNull();
    }
}
