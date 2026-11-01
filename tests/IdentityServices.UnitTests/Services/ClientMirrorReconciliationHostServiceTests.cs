using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>AB#8019: interval of the client mirror reconciliation.</summary>
public class ClientMirrorReconciliationHostServiceTests
{
    [Fact]
    public void Default_IsFiveMinutes()
    {
        ClientMirrorReconciliationHostService.GetInterval(new OctoIdentityServicesOptions())
            .Should().Be(TimeSpan.FromMinutes(5));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ZeroOrLess_SwitchesTheJobOff(int seconds)
    {
        ClientMirrorReconciliationHostService.GetInterval(
                new OctoIdentityServicesOptions { ClientMirrorReconciliationInterval = seconds })
            .Should().BeNull();
    }

    [Fact]
    public void AConfiguredValue_IsSeconds()
    {
        ClientMirrorReconciliationHostService.GetInterval(
                new OctoIdentityServicesOptions { ClientMirrorReconciliationInterval = 30 })
            .Should().Be(TimeSpan.FromSeconds(30));
    }
}
