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

    // -------------- AB#4208: scheme / domain / per-service public URL ----------------

    [Fact]
    public async Task GetVariables_OctoScheme_DefaultsToHttpsWhenUnset()
    {
        // Engine-level default — the Identity provider re-emits scheme/domain so the
        // replacement provider stays a superset of DefaultBlueprintVariableProvider's
        // contract.
        var sut = CreateSut();

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.scheme"].Should().Be("https");
    }

    [Fact]
    public async Task GetVariables_OctoDomain_StripsTrailingSlashes()
    {
        var sut = CreateSut(new OctoBlueprintVariablesOptions
        {
            Domain = "test-2.octo-mesh.com/",
        });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.domain"].Should().Be("test-2.octo-mesh.com");
    }

    [Fact]
    public async Task GetVariables_McpPublicUrl_ComposedFromSchemeAndDomain()
    {
        // Cluster path: no per-service override → URL composed from the per-cluster base.
        var sut = CreateSut(new OctoBlueprintVariablesOptions
        {
            Scheme = "https",
            Domain = "test-2.octo-mesh.com",
        });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.mcp.publicUrl"].Should().Be("https://mcp.test-2.octo-mesh.com");
    }

    [Fact]
    public async Task GetVariables_McpPublicUrl_ExplicitOverrideWinsOverComposition()
    {
        // Dev path: Start-Octo runs MCP natively on localhost:5017 which does not fit the
        // mcp.<domain> pattern. The explicit override wins so the blueprint substitution
        // still lands a usable URL on the seed entity.
        var sut = CreateSut(
            new OctoBlueprintVariablesOptions
            {
                Scheme = "https",
                Domain = "test-2.octo-mesh.com", // would compose if no override
            },
            new OctoIdentityServicesOptions
            {
                IdentityServerLicenseKey = "test",
                AutoMapperLicenseKey = "test",
                ServicePublicUrlOverrides = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["mcp"] = "https://localhost:5017/",
                },
            });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.mcp.publicUrl"].Should().Be("https://localhost:5017");
    }

    [Fact]
    public async Task GetVariables_McpPublicUrl_EmptyWhenNeitherSourceSet()
    {
        // Dev with no override AND no cluster domain → empty. The blueprint apply still
        // succeeds; OIDC fails loudly on first MCP login, matching the RefineryStudioUrl
        // contract.
        var sut = CreateSut();

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.mcp.publicUrl"].Should().Be("");
    }

    [Fact]
    public void ResolvePublicUrl_OverrideTakesPrecedenceOverComposition()
    {
        var overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["mcp"] = "https://localhost:5017",
        };

        var result = IdentityBlueprintVariableProvider.ResolvePublicUrl(
            "mcp", "https", "test-2.octo-mesh.com", overrides);

        result.Should().Be("https://localhost:5017");
    }

    [Fact]
    public void ResolvePublicUrl_NoDomainNoOverride_ReturnsEmpty()
    {
        var result = IdentityBlueprintVariableProvider.ResolvePublicUrl(
            "mcp", "https", string.Empty, overrides: null);

        result.Should().Be(string.Empty);
    }

    [Fact]
    public void ResolvePublicUrl_HonoursCustomScheme()
    {
        var result = IdentityBlueprintVariableProvider.ResolvePublicUrl(
            "mcp", "http", "test-2.octo-mesh.com", overrides: null);

        result.Should().Be("http://mcp.test-2.octo-mesh.com");
    }

    [Fact]
    public void ResolvePublicUrl_WhitespaceOverride_FallsBackToComposition()
    {
        // Defensive: an operator who sets OCTO_IDENTITY__SERVICEPUBLICURLOVERRIDES__MCP=""
        // by mistake should still get the composed URL, not an empty string in the entity.
        var overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["mcp"] = "   ",
        };

        var result = IdentityBlueprintVariableProvider.ResolvePublicUrl(
            "mcp", "https", "test-2.octo-mesh.com", overrides);

        result.Should().Be("https://mcp.test-2.octo-mesh.com");
    }

    [Fact]
    public void ResolvePublicUrl_OverrideWithSurroundingWhitespace_IsTrimmed()
    {
        // Operator copy-pasted an URL with stray whitespace into the env var or
        // appsettings — strip it before the slash-strip so the URL lands clean.
        var overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["mcp"] = "  https://localhost:5017/  ",
        };

        var result = IdentityBlueprintVariableProvider.ResolvePublicUrl(
            "mcp", "https", string.Empty, overrides);

        result.Should().Be("https://localhost:5017");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void ResolvePublicUrl_WhitespaceOnlyDomainNoOverride_ReturnsEmpty(string rawDomain)
    {
        // Whitespace-only OCTO_BLUEPRINTS__DOMAIN must not compose
        // "https://mcp.   " into the entity — treat it as unset.
        var result = IdentityBlueprintVariableProvider.ResolvePublicUrl(
            "mcp", "https", rawDomain, overrides: null);

        result.Should().Be(string.Empty);
    }

    [Fact]
    public async Task GetVariables_OctoScheme_WhitespaceOnlyFallsBackToDefault()
    {
        // Mirrors the engine's DefaultBlueprintVariableProvider behaviour: a
        // whitespace-only Scheme is treated as unset and the default "https" wins.
        var sut = CreateSut(new OctoBlueprintVariablesOptions { Scheme = "   " });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.scheme"].Should().Be("https");
    }

    [Fact]
    public async Task GetVariables_OctoDomain_WhitespaceOnlyResolvesToEmptyString()
    {
        var sut = CreateSut(new OctoBlueprintVariablesOptions { Domain = "   " });

        var variables = await sut.GetVariablesAsync("acme", TestContext.Current.CancellationToken);

        variables["octo.domain"].Should().Be(string.Empty);
    }
}
