using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.Blueprints;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     Unit tests for <see cref="IdentityBlueprintVariableProvider"/>. Pins both the
///     standard <c>octo.*</c> keys (the engine default's contract that this provider
///     replicates) and the Identity-specific keys exposed for
///     <c>System.Identity.Bootstrap-1.0.0</c> seed entities.
/// </summary>
public class IdentityBlueprintVariableProviderTests
{
    private static IdentityBlueprintVariableProvider CreateSut(
        OctoBlueprintVariablesOptions? baseOptions = null,
        OctoIdentityServicesOptions? identityOptions = null)
    {
        var baseMonitor = Substitute.For<IOptionsMonitor<OctoBlueprintVariablesOptions>>();
        baseMonitor.CurrentValue.Returns(baseOptions ?? new OctoBlueprintVariablesOptions());

        var identityMonitor = Substitute.For<IOptionsMonitor<OctoIdentityServicesOptions>>();
        identityMonitor.CurrentValue.Returns(identityOptions ?? new OctoIdentityServicesOptions
        {
            IdentityServerLicenseKey = "test-license",
            AutoMapperLicenseKey = "test-license",
        });

        return new IdentityBlueprintVariableProvider(
            baseMonitor,
            identityMonitor,
            NullLogger<IdentityBlueprintVariableProvider>.Instance);
    }

    [Fact]
    public async Task GetVariables_ExposesAllStandardOctoKeys()
    {
        var sut = CreateSut(
            new OctoBlueprintVariablesOptions
            {
                OctoVersion = "3.4.5",
                Environment = "test",
                SystemTenantId = "octosystem",
            });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables.Keys.Should().Contain(new[]
        {
            "octo.version",
            "octo.environment",
            "octo.environmentMode",
            "octo.tenantId",
            "octo.systemTenantId",
            "octo.isSystemTenant",
        });
        variables["octo.version"].Should().Be("3.4.5");
        variables["octo.environment"].Should().Be("test");
        variables["octo.environmentMode"].Should().Be("Testing");
        variables["octo.tenantId"].Should().Be("acme");
        variables["octo.systemTenantId"].Should().Be("octosystem");
        variables["octo.isSystemTenant"].Should().Be("false");
    }

    [Fact]
    public async Task GetVariables_SystemTenantMatch_IsCaseInsensitive()
    {
        var sut = CreateSut(new OctoBlueprintVariablesOptions { SystemTenantId = "OctoSystem" });

        var variables = await sut.GetVariablesAsync("octosystem", TestContext.Current.CancellationToken);

        variables["octo.isSystemTenant"].Should().Be("true");
    }

    [Fact]
    public async Task GetVariables_NormalisesFourSegmentOctoVersionToThreeSegment()
    {
        var sut = CreateSut(new OctoBlueprintVariablesOptions { OctoVersion = "3.3.109.0" });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.version"].Should().Be("3.3.109");
    }

    [Fact]
    public async Task GetVariables_PreservesPreReleaseSuffixOnNormalisedVersion()
    {
        var sut = CreateSut(new OctoBlueprintVariablesOptions { OctoVersion = "3.3.109.0-test1" });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.version"].Should().Be("3.3.109-test1");
    }

    [Fact]
    public async Task GetVariables_UnknownEnvironment_FallsBackToDevelopmentMode()
    {
        var sut = CreateSut(new OctoBlueprintVariablesOptions { Environment = "nonsense" });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.environment"].Should().Be("nonsense");
        variables["octo.environmentMode"].Should().Be("Development");
    }

    [Fact]
    public async Task GetVariables_ExposesIdentityAuthorityUrlWithTrailingSlashTrimmed()
    {
        var sut = CreateSut(identityOptions: new OctoIdentityServicesOptions
        {
            IdentityServerLicenseKey = "test",
            AutoMapperLicenseKey = "test",
            AuthorityUrl = "https://identity.test.octo-mesh.com/",
        });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.identity.authorityUrl"].Should().Be("https://identity.test.octo-mesh.com");
    }

    [Fact]
    public async Task GetVariables_ExposesIdentityRefineryStudioUrlWithTrailingSlashTrimmed()
    {
        var sut = CreateSut(identityOptions: new OctoIdentityServicesOptions
        {
            IdentityServerLicenseKey = "test",
            AutoMapperLicenseKey = "test",
            RefineryStudioUrl = "https://studio.test.octo-mesh.com/",
        });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.identity.refineryStudioUrl"].Should().Be("https://studio.test.octo-mesh.com");
    }

    [Fact]
    public async Task GetVariables_NullRefineryStudioUrl_ResolvesToEmptyString()
    {
        // Operator forgot to set RefineryStudioUrl — blueprint apply must NOT crash; the
        // Refinery Studio client entity gets empty redirect URIs and the misconfiguration
        // surfaces on first user login instead of being silently swallowed.
        var sut = CreateSut(identityOptions: new OctoIdentityServicesOptions
        {
            IdentityServerLicenseKey = "test",
            AutoMapperLicenseKey = "test",
            RefineryStudioUrl = null,
        });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.identity.refineryStudioUrl"].Should().Be("");
    }
}
