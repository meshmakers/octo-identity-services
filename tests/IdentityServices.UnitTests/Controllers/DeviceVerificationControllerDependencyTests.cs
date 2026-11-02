using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Protocol;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     AB#7884 — the device approval cannot provision cross-tenant users: the controller has no dependency that could.
///     Cross-tenant provisioning lives in exactly two places, the interactive login and the token exchange.
/// </summary>
public class DeviceVerificationControllerDependencyTests
{
    [Theory]
    [InlineData(typeof(ICrossTenantUserProvisioningService))]
    [InlineData(typeof(ICrossTenantAuthenticationService))]
    [InlineData(typeof(IOctoIdentityProviderStore))]
    [InlineData(typeof(SignInManager<RtUser>))]
    public void Constructor_TakesNoCrossTenantProvisioningDependency(Type forbidden)
    {
        var parameters = typeof(DeviceVerificationController).GetConstructors()
            .SelectMany(c => c.GetParameters()).Select(p => p.ParameterType);

        parameters.Should().NotContain(forbidden);
    }
}
